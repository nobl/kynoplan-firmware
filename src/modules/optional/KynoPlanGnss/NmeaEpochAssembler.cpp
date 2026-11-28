#include "NmeaEpochAssembler.h"

#if defined(KYNOPLAN_GNSS_STREAM) || defined(PIO_UNIT_TESTING)

namespace
{
constexpr uint32_t MS_PER_DAY = 86400000;
constexpr size_t MAX_FIELDS = 24;

bool isDigit(char c)
{
    return c >= '0' && c <= '9';
}

int hexValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

bool parseDigits(const char *p, size_t n, uint32_t &out)
{
    if (n == 0 || n > 9)
        return false;
    uint32_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (!isDigit(p[i]))
            return false;
        v = v * 10 + (uint32_t)(p[i] - '0');
    }
    out = v;
    return true;
}

// Signed decimal to fixed point with `decimals` places, rounding half away from zero on the first dropped digit.
bool parseFixed(const char *p, size_t n, unsigned decimals, int64_t &out)
{
    size_t i = 0;
    bool neg = false;
    if (i < n && (p[i] == '-' || p[i] == '+')) {
        neg = p[i] == '-';
        i++;
    }
    int64_t v = 0;
    unsigned intDigits = 0, used = 0;
    bool any = false, dropped = false, roundUp = false;
    for (; i < n && isDigit(p[i]); i++) {
        if (++intDigits > 12)
            return false;
        v = v * 10 + (p[i] - '0');
        any = true;
    }
    if (i < n && p[i] == '.') {
        i++;
        for (; i < n && isDigit(p[i]); i++) {
            any = true;
            if (used < decimals) {
                v = v * 10 + (p[i] - '0');
                used++;
            } else if (!dropped) {
                roundUp = p[i] >= '5';
                dropped = true;
            }
        }
    }
    if (i != n || !any)
        return false;
    for (; used < decimals; used++)
        v *= 10;
    if (roundUp)
        v++;
    out = neg ? -v : v;
    return true;
}

// hhmmss[.f...] to ms of day; digits past milliseconds are truncated so the second never rounds up.
bool parseTime(const char *p, size_t n, uint32_t &tod)
{
    uint32_t hh, mm, ss;
    if (n < 6 || !parseDigits(p, 2, hh) || !parseDigits(p + 2, 2, mm) || !parseDigits(p + 4, 2, ss))
        return false;
    if (hh > 23 || mm > 59 || ss > 60)
        return false;
    uint32_t ms = 0;
    if (n > 6) {
        if (p[6] != '.' || n == 7)
            return false;
        uint32_t scale = 100;
        for (size_t i = 7; i < n; i++) {
            if (!isDigit(p[i]))
                return false;
            ms += (uint32_t)(p[i] - '0') * scale;
            scale /= 10;
        }
    }
    tod = ((hh * 60 + mm) * 60 + ss) * 1000 + ms;
    return true;
}

int32_t daysFromCivil(int32_t y, int32_t m, int32_t d)
{
    y -= m <= 2;
    const int32_t era = (y >= 0 ? y : y - 399) / 400;
    const int32_t yoe = y - era * 400;
    const int32_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const int32_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

// ddmmyy: false for a malformed or impossible date; inWindow false outside MIN/MAX_DATE_YEAR (receiver default dates).
bool parseDate(const char *p, size_t n, int32_t &days, bool &inWindow)
{
    static constexpr uint8_t DAYS_IN_MONTH[12] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    uint32_t dd, mo, yy;
    if (n != 6 || !parseDigits(p, 2, dd) || !parseDigits(p + 2, 2, mo) || !parseDigits(p + 4, 2, yy))
        return false;
    if (mo < 1 || mo > 12 || dd < 1 || dd > DAYS_IN_MONTH[mo - 1])
        return false;
    const int32_t year = 2000 + (int32_t)yy;
    if (mo == 2 && dd == 29 && (year % 4 != 0)) // 2000..2099: every fourth year is a leap year
        return false;
    inWindow = year >= NmeaEpochAssembler::MIN_DATE_YEAR && year <= NmeaEpochAssembler::MAX_DATE_YEAR;
    days = daysFromCivil(year, (int32_t)mo, (int32_t)dd);
    return true;
}

// NMEA [d]ddmm.mmmm to degrees * 1e7 with integer math, rounded half up on the magnitude.
bool parseCoord(const char *p, size_t n, char hemi, bool isLat, int32_t &out)
{
    size_t dot = 0;
    while (dot < n && p[dot] != '.')
        dot++;
    if (dot < 3 || dot > 5)
        return false;
    uint32_t deg, minInt;
    if (!parseDigits(p, dot - 2, deg) || !parseDigits(p + dot - 2, 2, minInt) || minInt > 59)
        return false;
    int64_t minScaled = minInt, pow10 = 1;
    if (dot < n) {
        const size_t fracLen = n - dot - 1;
        if (fracLen == 0 || fracLen > 9)
            return false;
        for (size_t i = dot + 1; i < n; i++) {
            if (!isDigit(p[i]))
                return false;
            minScaled = minScaled * 10 + (p[i] - '0');
            pow10 *= 10;
        }
    }
    const int64_t e7 = (int64_t)deg * 10000000 + (minScaled * 10000000 + 30 * pow10) / (60 * pow10);
    if (e7 > (isLat ? 900000000LL : 1800000000LL))
        return false;
    const char pos = isLat ? 'N' : 'E', neg = isLat ? 'S' : 'W';
    if (hemi != pos && hemi != neg)
        return false;
    out = (int32_t)(hemi == neg ? -e7 : e7);
    return true;
}

bool parsePosition(const char *const *fp, const size_t *fn, int32_t &lat, int32_t &lon, bool &has)
{
    // fp/fn: lat, N/S, lon, E/W
    const bool anyEmpty = fn[0] == 0 || fn[1] == 0 || fn[2] == 0 || fn[3] == 0;
    const bool allEmpty = fn[0] == 0 && fn[1] == 0 && fn[2] == 0 && fn[3] == 0;
    if (allEmpty) {
        has = false;
        return true;
    }
    if (anyEmpty || fn[1] != 1 || fn[3] != 1)
        return false;
    if (!parseCoord(fp[0], fn[0], fp[1][0], true, lat) || !parseCoord(fp[2], fn[2], fp[3][0], false, lon))
        return false;
    has = true;
    return true;
}

// Estimated (E), manual (M), simulated (S) and no-fix (N) modes are not measured fixes.
bool isMeasuredMode(char mode)
{
    return mode != 'E' && mode != 'M' && mode != 'S' && mode != 'N';
}
} // namespace

bool selectForPeriod(const GnssEpoch &epoch, uint32_t periodMs)
{
    uint32_t periodS = (periodMs + 500) / 1000;
    if (periodS == 0)
        periodS = 1;
    const int64_t secs = epoch.hasDate ? epoch.fixUtcMs / 1000 : (int64_t)(epoch.utcTodMs / 1000);
    return secs % periodS == 0;
}

NmeaEpochAssembler::NmeaEpochAssembler(uint32_t epochTimeoutMs) : timeoutMs(epochTimeoutMs) {}

void NmeaEpochAssembler::reset()
{
    const uint32_t keepTimeout = timeoutMs;
    *this = NmeaEpochAssembler(keepTimeout);
}

void NmeaEpochAssembler::feed(const char *data, size_t len, uint32_t monotonicMs)
{
    for (size_t i = 0; i < len; i++)
        feed(data[i], monotonicMs);
}

void NmeaEpochAssembler::feed(char c, uint32_t monotonicMs)
{
    if (c == '$') {
        if (inLine && !lineOverflow)
            badLine();
        inLine = true;
        lineLen = 0;
        lineOverflow = false;
        lineStartMs = monotonicMs;
        return;
    }
    if (!inLine)
        return;
    if (c == '\r' || c == '\n') {
        if (!lineOverflow)
            endLine(monotonicMs);
        inLine = false;
        return;
    }
    if (lineOverflow)
        return;
    if (c < 0x20 || c > 0x7e) {
        badLine();
        inLine = false;
        return;
    }
    if (lineLen >= MAX_LINE) {
        lineOverflow = true;
        badLine();
        return;
    }
    line[lineLen++] = c;
}

void NmeaEpochAssembler::poll(uint32_t nowMs)
{
    checkTimeout(nowMs);
}

bool NmeaEpochAssembler::pop(GnssEpoch &out)
{
    if (queueCount == 0)
        return false;
    out = queue[queueHead];
    queueHead = (queueHead + 1) % QUEUE_CAPACITY;
    queueCount--;
    return true;
}

void NmeaEpochAssembler::badLine()
{
    counters.badSentences++;
}

void NmeaEpochAssembler::checkTimeout(uint32_t nowMs)
{
    // Unsigned subtraction keeps this correct across the 32-bit ms wrap.
    if (hasPending && (uint32_t)(nowMs - pending.deviceMsFirstByte) >= timeoutMs)
        emitPending(GnssEpochClose::TIMEOUT, nowMs);
}

void NmeaEpochAssembler::endLine(uint32_t nowMs)
{
    if (lineLen == 0) {
        badLine();
        return;
    }
    size_t star = 0;
    while (star < lineLen && line[star] != '*')
        star++;
    if (star + 3 != lineLen) {
        badLine();
        return;
    }
    const int hi = hexValue(line[star + 1]), lo = hexValue(line[star + 2]);
    uint8_t sum = 0;
    for (size_t i = 0; i < star; i++)
        sum ^= (uint8_t)line[i];
    if (hi < 0 || lo < 0 || sum != (uint8_t)(hi * 16 + lo)) {
        counters.checksumErrors++;
        badLine();
        return;
    }
    lineLen = star;
    processSentence(nowMs);
}

void NmeaEpochAssembler::processSentence(uint32_t nowMs)
{
    Field f[MAX_FIELDS];
    size_t nf = 0;
    size_t start = 0;
    for (size_t i = 0; i <= lineLen; i++) {
        if (i == lineLen || line[i] == ',') {
            if (nf < MAX_FIELDS)
                f[nf++] = {line + start, i - start};
            start = i + 1;
        }
    }
    if (f[0].n != 5 || f[0].p[0] < 'A' || f[0].p[0] > 'Z' || f[0].p[1] < 'A' || f[0].p[1] > 'Z')
        return; // proprietary or non-standard sentence: not ours to judge
    const char *t = f[0].p + 2;
    const bool isGga = t[0] == 'G' && t[1] == 'G' && t[2] == 'A';
    const bool isRmc = t[0] == 'R' && t[1] == 'M' && t[2] == 'C';
    if (!isGga && !isRmc)
        return;

    GnssEpoch s = {};
    uint32_t tod = 0;
    bool hasTime = false, hasDays = false;
    int32_t days = 0;
    const bool ok = isGga ? parseGga(f, nf, s, tod, hasTime) : parseRmc(f, nf, s, tod, hasTime, days, hasDays);
    if (!ok) {
        badLine();
        return;
    }
    if (!hasTime) {
        counters.untimedSentences++;
        return;
    }
    mergeSentence(isGga, s, tod, hasDays, days, nowMs);
}

bool NmeaEpochAssembler::parseGga(const Field *f, size_t nf, GnssEpoch &s, uint32_t &tod, bool &hasTime)
{
    if (nf < 12)
        return false;
    hasTime = f[1].n != 0;
    if (hasTime && !parseTime(f[1].p, f[1].n, tod))
        return false;
    const char *pp[4] = {f[2].p, f[3].p, f[4].p, f[5].p};
    const size_t pn[4] = {f[2].n, f[3].n, f[4].n, f[5].n};
    if (!parsePosition(pp, pn, s.latE7, s.lonE7, s.hasPosition))
        return false;
    uint32_t u;
    if (f[6].n != 0) {
        if (f[6].n != 1 || !parseDigits(f[6].p, 1, u))
            return false;
        s.ggaQuality = u <= MAX_GGA_QUALITY ? (uint8_t)u : 0; // 9 is outside NMEA 0..8: treated as absent
    }
    if (f[7].n != 0) {
        if (f[7].n > 3 || !parseDigits(f[7].p, f[7].n, u) || u > 255)
            return false;
        s.satsUsed = (uint8_t)u;
        s.hasSats = true;
    }
    int64_t v;
    if (f[8].n != 0) {
        if (!parseFixed(f[8].p, f[8].n, 2, v) || v < 0)
            return false;
        s.hdopX100 = (uint16_t)(v > 65535 ? 65535 : v);
        s.hasHdop = true;
    }
    if (f[9].n != 0) {
        if (!parseFixed(f[9].p, f[9].n, 2, v) || v > INT32_MAX || v < INT32_MIN)
            return false;
        s.altMslCm = (int32_t)v;
        s.hasAltitude = true;
    }
    if (f[11].n != 0) {
        if (!parseFixed(f[11].p, f[11].n, 2, v) || v > INT32_MAX || v < INT32_MIN)
            return false;
        s.geoidSepCm = (int32_t)v;
        s.hasGeoidSep = true;
    }
    return true;
}

bool NmeaEpochAssembler::parseRmc(const Field *f, size_t nf, GnssEpoch &s, uint32_t &tod, bool &hasTime, int32_t &days,
                                  bool &hasDays)
{
    if (nf < 10)
        return false;
    hasTime = f[1].n != 0;
    if (hasTime && !parseTime(f[1].p, f[1].n, tod))
        return false;
    if (f[2].n != 1 || (f[2].p[0] != 'A' && f[2].p[0] != 'V'))
        return false;
    s.rmcStatus = f[2].p[0];
    const char *pp[4] = {f[3].p, f[4].p, f[5].p, f[6].p};
    const size_t pn[4] = {f[3].n, f[4].n, f[5].n, f[6].n};
    if (!parsePosition(pp, pn, s.latE7, s.lonE7, s.hasPosition))
        return false;
    int64_t v;
    if (f[7].n != 0) {
        // Above 999999 kn is garbage, and the bound keeps v * 1852 inside int64.
        if (!parseFixed(f[7].p, f[7].n, 6, v) || v < 0 || v > 999999999999LL)
            return false;
        // knots * 1e6 -> mm/s: 1 kn = 1852 m / 3600 s.
        const int64_t mms = (v * 1852 + 1800000) / 3600000;
        s.speedMmS = (uint32_t)(mms > UINT32_MAX ? UINT32_MAX : mms);
        s.hasSpeed = true;
    }
    if (f[8].n != 0) {
        if (!parseFixed(f[8].p, f[8].n, 2, v) || v < 0 || v > 36000)
            return false;
        s.courseCdeg = (uint16_t)(v % 36000);
        s.hasCourse = true;
    }
    bool inWindow = false;
    if (f[9].n != 0 && !parseDate(f[9].p, f[9].n, days, inWindow))
        return false;
    hasDays = inWindow; // an out-of-window year is a receiver default, not a date: the sentence stays, the date goes
    if (nf > 12 && f[12].n == 1)
        s.rmcMode = f[12].p[0];
    return true;
}

void NmeaEpochAssembler::mergeSentence(bool isGga, const GnssEpoch &s, uint32_t tod, bool hasDays, int32_t days, uint32_t nowMs)
{
    if (hasLastEmitted && tod == lastEmittedTod) {
        counters.staleSentences++; // one record per key: a late half never reopens an emitted epoch
        return;
    }
    if (hasPending && pending.utcTodMs != tod)
        emitPending(GnssEpochClose::SUPERSEDED, nowMs);
    if (!hasPending) {
        pending = GnssEpoch{};
        pending.utcTodMs = tod;
        pending.deviceMsFirstByte = lineStartMs;
        pendingHasRmcDate = false;
        hasPending = true;
    }
    if (isGga ? pending.hasGga : pending.hasRmc) {
        counters.staleSentences++;
        return;
    }
    if (isGga) {
        pending.hasGga = true;
        pending.ggaQuality = s.ggaQuality;
        pending.satsUsed = s.satsUsed;
        pending.hasSats = s.hasSats;
        pending.hdopX100 = s.hdopX100;
        pending.hasHdop = s.hasHdop;
        pending.altMslCm = s.altMslCm;
        pending.hasAltitude = s.hasAltitude;
        pending.geoidSepCm = s.geoidSepCm;
        pending.hasGeoidSep = s.hasGeoidSep;
        if (s.hasPosition) {
            pending.latE7 = s.latE7;
            pending.lonE7 = s.lonE7;
            pending.hasPosition = true;
        }
    } else {
        pending.hasRmc = true;
        pending.rmcStatus = s.rmcStatus;
        pending.rmcMode = s.rmcMode;
        pending.speedMmS = s.speedMmS;
        pending.hasSpeed = s.hasSpeed;
        pending.courseCdeg = s.courseCdeg;
        pending.hasCourse = s.hasCourse;
        if (s.hasPosition && !pending.hasPosition) {
            pending.latE7 = s.latE7;
            pending.lonE7 = s.lonE7;
            pending.hasPosition = true;
        }
        pendingHasRmcDate = hasDays;
        pendingDays = days;
    }
    if (pending.hasGga && pending.hasRmc)
        emitPending(GnssEpochClose::COMPLETE, nowMs);
}

void NmeaEpochAssembler::emitPending(GnssEpochClose reason, uint32_t nowMs)
{
    GnssEpoch &e = pending;
    const uint32_t tod = e.utcTodMs;
    bool hasDate = false;
    int32_t days = 0;
    if (pendingHasRmcDate) {
        hasDate = true;
        days = pendingDays;
    } else if (hasDateAnchor) {
        // GGA carries no date: reuse the last one, a step back of more than 12 h being a midnight rollover.
        if (tod >= anchorTod) {
            hasDate = true;
            days = anchorDays;
        } else if (anchorTod - tod > MS_PER_DAY / 2) {
            hasDate = true;
            days = anchorDays + 1;
        }
        e.dateCarried = hasDate;
    }
    e.hasDate = hasDate;
    if (hasDate)
        e.fixUtcMs = (int64_t)days * MS_PER_DAY + tod;
    // Only a status-A RMC date is trusted to date later GGA-only epochs; a void RMC may carry the receiver's default
    if (hasDate && (e.dateCarried || e.rmcStatus == 'A')) {
        hasDateAnchor = true;
        anchorDays = days;
        anchorTod = tod;
    }
    e.valid = e.hasGga && e.hasRmc && e.rmcStatus == 'A' && e.ggaQuality >= 1 && e.ggaQuality <= 5 &&
              (e.rmcMode == 0 || isMeasuredMode(e.rmcMode)) && e.hasPosition;
    e.epochCounter = ++emittedCount;
    e.deviceMsComplete = nowMs;
    e.closeReason = reason;

    if (queueCount == QUEUE_CAPACITY) {
        queueHead = (queueHead + 1) % QUEUE_CAPACITY;
        queueCount--;
        counters.queueOverflows++;
    }
    queue[(queueHead + queueCount) % QUEUE_CAPACITY] = e;
    queueCount++;

    hasLastEmitted = true;
    lastEmittedTod = tod;
    hasPending = false;
}

#endif
