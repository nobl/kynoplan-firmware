// Unit tests for NmeaEpochAssembler and selectForPeriod() in
// src/modules/optional/KynoPlanGnss/NmeaEpochAssembler.cpp - the byte-fed GGA/RMC parser that turns a GNSS receiver's
// NMEA stream into one GnssEpoch record per receiver fix time for the KynoPlan GNSS stream.
//
// Contract pinned here:
//  - identity is the receiver's UTC fix time, never the coordinates: a stationary receiver repeating the same position
//    must still produce one record per second, and a GGA/RMC pair for one time must produce exactly one record, even
//    when one half arrives after the epoch was closed by the timeout. The timeout is judged only by poll(), which the
//    caller runs after each drain: bytes are stamped once per drain, so a GGA/RMC pair split across two drains carries
//    the later drain's stamp, and judging the timeout on that stamp would report a valid fix as two broken halves;
//  - `valid` means a measured fix as KynoPlan SPEC 9.3 defines NEW_FIX: RMC status 'A', GGA quality 1..5 and, when the
//    RMC mode indicator is present, a mode other than E/M/S/N. Dead reckoning (quality 6 / mode E), manual input
//    (7 / M), simulation (8 / S) and no-fix mode N are positions the receiver did not measure, and a client that
//    records them as fixes stores invented tracks;
//  - GGA carries no date, so its date is carried from the last RMC, including across midnight and a year end, where the
//    GGA of 00:00:00 can arrive before (or without) the RMC that carries the new date. Only a status-A RMC sets the
//    carried date (a void RMC may carry the receiver's default date), and an RMC date must exist in the calendar and
//    fall inside MIN_DATE_YEAR..MAX_DATE_YEAR, else it is no date at all;
//  - GGA quality outside NMEA's 0..8 reads as 0 (absent), never as a quality the client must interpret;
//  - coordinates, speed and course are converted with integer math, so the record carries exactly the precision the
//    NMEA digits do - no float rounding of 1e-7 degree positions;
//  - corrupt input (bad checksum, malformed fields, overlong or truncated lines) is dropped and counted, and the parser
//    resynchronises on the next '$', whatever byte boundaries the UART reads fall on;
//  - selectForPeriod() decimates on the UTC second grid regardless of the fix time's fractional part.
//
// Regressions guarded: two records for one fix time (late half reopening an epoch); a fixed stationary position
// collapsing into one record; estimated, manual or simulated positions reported as valid fixes (the old
// "quality > 0" rule); GGA-only epochs dated on the previous day after midnight, or undated; float-rounded lat/lon;
// dropped checksum verification; parser state lost between feed() calls; the timeout firing one ms late or early, or
// firing inside feed() on a split drain; a void RMC's default date dating later epochs; Feb 30 or a 1980 receiver
// default accepted as a date; GGA quality 9 passed through;
// a stuck parser after an overlong line; decimation choosing the wrong seconds.
#include "Arduino.h" // declares setup()/loop() with the linkage the framework's main() calls
#include "TestUtil.h"
#include "modules/optional/KynoPlanGnss/NmeaEpochAssembler.h"
#include <cstdio>
#include <cstdlib>
#include <stdint.h>
#include <string>
#include <unity.h>
#include <vector>

namespace
{
constexpr int64_t MS_PER_DAY = 86400000;
constexpr int64_t DAY_2026_11_27 = 20784; // days since 1970-01-01
constexpr int64_t DAY_2026_12_31 = 20818;
constexpr int64_t DAY_2027_01_01 = 20819;
constexpr const char *LATLON = "4807.038247,N,01131.000000,E";

std::string nmea(const std::string &body)
{
    uint8_t sum = 0;
    for (char c : body)
        sum ^= (uint8_t)c;
    char tail[8];
    snprintf(tail, sizeof(tail), "*%02X\r\n", sum);
    return "$" + body + tail;
}

std::string gga(const char *time, const char *latlon = LATLON, int quality = 1)
{
    char b[128];
    snprintf(b, sizeof(b), "GNGGA,%s,%s,%d,12,0.90,545.40,M,46.90,M,,", time, latlon, quality);
    return nmea(b);
}

std::string rmc(const char *time, const char *date = "271126", const char *latlon = LATLON, const char *speed = "22.40",
                const char *course = "84.40", char status = 'A', char mode = 'A')
{
    char b[128];
    snprintf(b, sizeof(b), "GNRMC,%s,%c,%s,%s,%s,%s,,,%c,V", time, status, latlon, speed, course, date, mode);
    return nmea(b);
}

void feedStr(NmeaEpochAssembler &a, const std::string &s, uint32_t ms)
{
    a.feed(s.data(), s.size(), ms);
}

std::vector<GnssEpoch> drain(NmeaEpochAssembler &a)
{
    std::vector<GnssEpoch> out;
    GnssEpoch e;
    while (a.pop(e))
        out.push_back(e);
    return out;
}

// Feeds one sentence alone and closes its epoch by timeout, returning the single record.
GnssEpoch single(const std::string &sentence)
{
    NmeaEpochAssembler a;
    feedStr(a, sentence, 0);
    a.poll(NmeaEpochAssembler::DEFAULT_TIMEOUT_MS);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    return v[0];
}

// A complete GGA+RMC epoch with good position, status 'A', and the given GGA quality and RMC mode.
GnssEpoch pairWith(int quality, char mode)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00", LATLON, quality), 0);
    feedStr(a, rmc("123519.00", "271126", LATLON, "22.40", "84.40", 'A', mode), 20);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_TRUE(v[0].hasGga && v[0].hasRmc && v[0].hasPosition);
    TEST_ASSERT_EQUAL_INT('A', v[0].rmcStatus);
    return v[0];
}

uint32_t tod(int h, int m, int s, int ms = 0)
{
    return (uint32_t)(((h * 60 + m) * 60 + s) * 1000 + ms);
}

void assertSameEpoch(const GnssEpoch &a, const GnssEpoch &b)
{
    TEST_ASSERT_EQUAL_UINT32(a.epochCounter, b.epochCounter);
    TEST_ASSERT_EQUAL_UINT32(a.utcTodMs, b.utcTodMs);
    TEST_ASSERT_EQUAL_INT64(a.fixUtcMs, b.fixUtcMs);
    TEST_ASSERT_EQUAL_UINT32(a.deviceMsFirstByte, b.deviceMsFirstByte);
    TEST_ASSERT_EQUAL_UINT32(a.deviceMsComplete, b.deviceMsComplete);
    TEST_ASSERT_EQUAL_INT32(a.latE7, b.latE7);
    TEST_ASSERT_EQUAL_INT32(a.lonE7, b.lonE7);
    TEST_ASSERT_EQUAL_INT32(a.altMslCm, b.altMslCm);
    TEST_ASSERT_EQUAL_INT32(a.geoidSepCm, b.geoidSepCm);
    TEST_ASSERT_EQUAL_UINT32(a.speedMmS, b.speedMmS);
    TEST_ASSERT_EQUAL_UINT16(a.courseCdeg, b.courseCdeg);
    TEST_ASSERT_EQUAL_UINT16(a.hdopX100, b.hdopX100);
    TEST_ASSERT_EQUAL_UINT8(a.ggaQuality, b.ggaQuality);
    TEST_ASSERT_EQUAL_UINT8(a.satsUsed, b.satsUsed);
    TEST_ASSERT_EQUAL_INT(a.rmcStatus, b.rmcStatus);
    TEST_ASSERT_EQUAL_INT(a.rmcMode, b.rmcMode);
    TEST_ASSERT_EQUAL(a.valid, b.valid);
    TEST_ASSERT_EQUAL(a.hasGga, b.hasGga);
    TEST_ASSERT_EQUAL(a.hasRmc, b.hasRmc);
    TEST_ASSERT_EQUAL(a.hasDate, b.hasDate);
    TEST_ASSERT_EQUAL(a.dateCarried, b.dateCarried);
    TEST_ASSERT_EQUAL(a.hasPosition, b.hasPosition);
    TEST_ASSERT_EQUAL(a.hasSpeed, b.hasSpeed);
    TEST_ASSERT_EQUAL(a.hasCourse, b.hasCourse);
    TEST_ASSERT_EQUAL((int)a.closeReason, (int)b.closeReason);
}
} // namespace

void setUp(void) {}
void tearDown(void) {}

// --- assembly ---

static void test_gga_then_rmc_emits_one_complete_epoch(void)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 1000);
    TEST_ASSERT_EQUAL_UINT32(0, a.available());
    feedStr(a, rmc("123519.00"), 1020);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    const GnssEpoch &e = v[0];
    TEST_ASSERT_EQUAL_UINT32(1, e.epochCounter);
    TEST_ASSERT_EQUAL_INT((int)GnssEpochClose::COMPLETE, (int)e.closeReason);
    TEST_ASSERT_TRUE(e.hasGga && e.hasRmc && e.hasDate && e.hasPosition && e.valid);
    TEST_ASSERT_FALSE(e.dateCarried);
    TEST_ASSERT_EQUAL_UINT32(tod(12, 35, 19), e.utcTodMs);
    // 2026-11-27 12:35:19 UTC, cross-checked against the literal Unix ms.
    TEST_ASSERT_EQUAL_INT64(DAY_2026_11_27 * MS_PER_DAY + tod(12, 35, 19), e.fixUtcMs);
    TEST_ASSERT_EQUAL_INT64(1795782919000LL, e.fixUtcMs);
    TEST_ASSERT_EQUAL_UINT32(1000, e.deviceMsFirstByte);
    TEST_ASSERT_EQUAL_UINT32(1020, e.deviceMsComplete);
    TEST_ASSERT_EQUAL_INT32(481173041, e.latE7);
    TEST_ASSERT_EQUAL_INT32(115166667, e.lonE7);
    TEST_ASSERT_EQUAL_UINT8(1, e.ggaQuality);
    TEST_ASSERT_EQUAL_UINT8(12, e.satsUsed);
    TEST_ASSERT_EQUAL_UINT16(90, e.hdopX100);
    TEST_ASSERT_EQUAL_INT32(54540, e.altMslCm);
    TEST_ASSERT_EQUAL_INT32(4690, e.geoidSepCm);
    TEST_ASSERT_EQUAL_UINT32(11524, e.speedMmS);
    TEST_ASSERT_EQUAL_UINT16(8440, e.courseCdeg);
    TEST_ASSERT_EQUAL_INT('A', e.rmcStatus);
    TEST_ASSERT_EQUAL_INT('A', e.rmcMode);
    TEST_ASSERT_EQUAL_UINT32(0, a.stats().badSentences);
}

// GSA/GSV/VTG/TXT between the pair belong to the same burst and must neither close the epoch nor count as bad.
static void test_other_sentences_do_not_close_epoch(void)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    feedStr(a, nmea("GNGSA,A,3,05,13,15,18,,,,,,,,,1.50,0.90,1.20,1"), 5);
    feedStr(a, nmea("GPGSV,3,1,11,05,45,123,40,13,30,045,38,15,60,270,42,18,12,310,30,1"), 10);
    feedStr(a, nmea("GNTXT,01,01,02,ANTSTATUS=OK"), 12);
    feedStr(a, rmc("123519.00"), 20);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_EQUAL_INT((int)GnssEpochClose::COMPLETE, (int)v[0].closeReason);
    TEST_ASSERT_EQUAL_UINT32(0, a.stats().badSentences);
}

static void test_any_talker_id_accepted(void)
{
    const std::string g = gga("123519.00"), r = rmc("123519.00");
    const char *talkers[] = {"GP", "GL", "GA", "GB", "BD", "GN"};
    uint32_t t = 0;
    for (const char *talker : talkers) {
        const std::string gb = std::string(talker) + g.substr(3, g.find('*') - 3);
        const std::string rb = std::string(talker) + r.substr(3, r.find('*') - 3);
        NmeaEpochAssembler b;
        feedStr(b, nmea(gb), t);
        feedStr(b, nmea(rb), t + 10);
        std::vector<GnssEpoch> v = drain(b);
        TEST_ASSERT_EQUAL_UINT32(1, v.size());
        TEST_ASSERT_TRUE(v[0].valid);
        t += 1000;
    }
}

// Every possible split point of a multi-sentence stream, across two feed() calls and byte at a time, must produce
// exactly the records a single feed() does.
static void test_split_at_every_byte_boundary_yields_identical_records(void)
{
    const std::string stream = gga("123519.00") + nmea("GNGSA,A,3,05,13,15,18,,,,,,,,,1.50,0.90,1.20,1") + rmc("123519.00") +
                               rmc("123520.00") + gga("123520.00") + gga("123521.00") + rmc("123521.00");
    NmeaEpochAssembler ref;
    feedStr(ref, stream, 500);
    const std::vector<GnssEpoch> want = drain(ref);
    TEST_ASSERT_EQUAL_UINT32(3, want.size());

    for (size_t k = 0; k <= stream.size(); k++) {
        NmeaEpochAssembler a;
        a.feed(stream.data(), k, 500);
        a.feed(stream.data() + k, stream.size() - k, 500);
        const std::vector<GnssEpoch> got = drain(a);
        TEST_ASSERT_EQUAL_UINT32(want.size(), got.size());
        for (size_t i = 0; i < want.size(); i++)
            assertSameEpoch(want[i], got[i]);
    }

    NmeaEpochAssembler bytes;
    for (char c : stream)
        bytes.feed(c, 500);
    const std::vector<GnssEpoch> got = drain(bytes);
    TEST_ASSERT_EQUAL_UINT32(want.size(), got.size());
    for (size_t i = 0; i < want.size(); i++)
        assertSameEpoch(want[i], got[i]);
}

// A stationary receiver repeats the same coordinates; each second is still its own epoch.
static void test_identical_coordinates_every_second_yield_distinct_epochs(void)
{
    NmeaEpochAssembler a;
    const int n = 6;
    for (int i = 0; i < n; i++) {
        char t[16];
        snprintf(t, sizeof(t), "1235%02d.00", 10 + i);
        feedStr(a, gga(t), (uint32_t)i * 1000);
        feedStr(a, rmc(t), (uint32_t)i * 1000 + 20);
    }
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(n, v.size());
    for (int i = 0; i < n; i++) {
        TEST_ASSERT_EQUAL_UINT32(i + 1, v[i].epochCounter);
        TEST_ASSERT_EQUAL_UINT32(tod(12, 35, 10 + i), v[i].utcTodMs);
        TEST_ASSERT_EQUAL_INT32(481173041, v[i].latE7);
        TEST_ASSERT_TRUE(v[i].valid);
    }
}

// --- validity ---

static void test_rmc_void_is_not_valid(void)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    feedStr(a, rmc("123519.00", "271126", LATLON, "0.00", "0.00", 'V'), 20);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_EQUAL_INT('V', v[0].rmcStatus);
    TEST_ASSERT_TRUE(v[0].hasPosition);
    TEST_ASSERT_FALSE(v[0].valid);
}

static void test_gga_quality_zero_is_not_valid(void)
{
    const GnssEpoch e = pairWith(0, 'A');
    TEST_ASSERT_EQUAL_UINT8(0, e.ggaQuality);
    TEST_ASSERT_FALSE(e.valid);
}

// Each case below is otherwise a good fix, so the old "quality > 0" rule would report it valid.
static void test_dead_reckoning_quality6_mode_E_is_not_valid(void)
{
    const GnssEpoch e = pairWith(6, 'E');
    TEST_ASSERT_EQUAL_UINT8(6, e.ggaQuality);
    TEST_ASSERT_EQUAL_INT('E', e.rmcMode);
    TEST_ASSERT_FALSE(e.valid);
}

static void test_manual_quality7_is_not_valid(void)
{
    TEST_ASSERT_FALSE(pairWith(7, 'A').valid);
}

static void test_simulator_quality8_is_not_valid(void)
{
    TEST_ASSERT_FALSE(pairWith(8, 'A').valid);
}

// NMEA defines GGA quality 0..8. A 9 is read as absent (0), so a client never receives a quality it cannot classify.
static void test_gga_quality_above_8_reads_as_absent(void)
{
    const GnssEpoch e = pairWith(9, 'A');
    TEST_ASSERT_EQUAL_UINT8(0, e.ggaQuality);
    TEST_ASSERT_FALSE(e.valid);
    TEST_ASSERT_EQUAL_UINT8(8, pairWith(8, 'A').ggaQuality);
}

static void test_mode_N_with_good_data_is_not_valid(void)
{
    const GnssEpoch e = pairWith(1, 'N');
    TEST_ASSERT_EQUAL_INT('N', e.rmcMode);
    TEST_ASSERT_FALSE(e.valid);
}

// Each rule on its own: quality 6 with a measured mode, and E/M/S with quality 1, are still not fixes; quality 1..5
// with measured modes, and an RMC without a mode field (NMEA 2.1), are.
static void test_validity_quality_and_mode_boundaries(void)
{
    TEST_ASSERT_FALSE(pairWith(6, 'A').valid);
    TEST_ASSERT_FALSE(pairWith(1, 'E').valid);
    TEST_ASSERT_FALSE(pairWith(1, 'M').valid);
    TEST_ASSERT_FALSE(pairWith(1, 'S').valid);
    TEST_ASSERT_TRUE(pairWith(1, 'A').valid);
    TEST_ASSERT_TRUE(pairWith(2, 'D').valid);
    TEST_ASSERT_TRUE(pairWith(4, 'R').valid);
    TEST_ASSERT_TRUE(pairWith(5, 'F').valid);

    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    feedStr(a, nmea("GNRMC,123519.00,A,4807.038247,N,01131.000000,E,22.40,84.40,271126,,"), 20);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_EQUAL_INT(0, v[0].rmcMode);
    TEST_ASSERT_TRUE(v[0].valid);
}

// What an AG3335 sends before its first fix: time and date, empty position fields. Well-formed, so not bad.
static void test_time_without_fix_is_emitted_invalid(void)
{
    NmeaEpochAssembler a;
    feedStr(a, nmea("GNGGA,000012.00,,,,,0,00,99.99,,,,,,"), 0);
    feedStr(a, nmea("GNRMC,000012.00,V,,,,,,,271126,,,N,V"), 20);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_FALSE(v[0].valid);
    TEST_ASSERT_FALSE(v[0].hasPosition);
    TEST_ASSERT_FALSE(v[0].hasSpeed);
    TEST_ASSERT_FALSE(v[0].hasCourse);
    TEST_ASSERT_TRUE(v[0].hasDate);
    TEST_ASSERT_EQUAL_UINT16(9999, v[0].hdopX100);
    TEST_ASSERT_EQUAL_INT('N', v[0].rmcMode);
    TEST_ASSERT_EQUAL_UINT32(0, a.stats().badSentences);
}

// A GGA only epoch carries a valid position but cannot be valid: validity requires both sentences.
static void test_gga_only_is_not_valid(void)
{
    const GnssEpoch e = single(gga("123519.00"));
    TEST_ASSERT_TRUE(e.hasPosition);
    TEST_ASSERT_FALSE(e.hasRmc);
    TEST_ASSERT_FALSE(e.valid);
}

// --- corrupt input ---

static void test_bad_checksum_dropped_and_counted(void)
{
    NmeaEpochAssembler a;
    std::string bad = gga("123519.00");
    bad[bad.size() - 3] = bad[bad.size() - 3] == '0' ? '1' : '0'; // corrupt the checksum's low digit
    feedStr(a, bad, 0);
    feedStr(a, nmea("GNGGA,123519.00,4807.038247,N,01131.000000,E,1,12,0.90,545.40,M,46.90,M,,"), 5);
    a.poll(1);
    TEST_ASSERT_EQUAL_UINT32(1, a.stats().badSentences);
    TEST_ASSERT_EQUAL_UINT32(1, a.stats().checksumErrors);
    // The good copy is the one accepted: its '$' time is the epoch's first byte.
    feedStr(a, rmc("123519.00"), 20);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_EQUAL_UINT32(5, v[0].deviceMsFirstByte);

    // A sentence without a checksum, and one with a corrupted payload, are dropped as well.
    NmeaEpochAssembler b;
    feedStr(b, "$GNGGA,123519.00,4807.038247,N,01131.000000,E,1,12,0.90,545.40,M,46.90,M,,\r\n", 0);
    std::string flipped = gga("123519.00");
    flipped[10] = '9';
    feedStr(b, flipped, 0);
    b.poll(1000);
    TEST_ASSERT_EQUAL_UINT32(0, b.available());
    TEST_ASSERT_EQUAL_UINT32(2, b.stats().badSentences);
}

static void test_malformed_fields_dropped_and_counted(void)
{
    NmeaEpochAssembler a;
    feedStr(a, nmea("GNGGA,123519.00,4807.038247,X,01131.000000,E,1,12,0.90,545.40,M,46.90,M,,"), 0); // hemisphere
    feedStr(a, nmea("GNGGA,126019.00,4807.038247,N,01131.000000,E,1,12,0.90,545.40,M,46.90,M,,"), 0); // minute 60
    feedStr(a, nmea("GNRMC,123519.00,A,4807.038247,N,01131.000000,E,22.40,360.01,271126,,,A,V"), 0);  // course
    feedStr(a, nmea("GNRMC,123519.00,A,4807.038247,N,01131.000000,E,22.40,84.40,321126,,,A,V"), 0);   // day 32
    feedStr(a, nmea("GNGGA,123519.00,4807.038247,N"), 0);                                             // truncated
    a.poll(1000);
    TEST_ASSERT_EQUAL_UINT32(0, a.available());
    TEST_ASSERT_EQUAL_UINT32(5, a.stats().badSentences);
    TEST_ASSERT_EQUAL_UINT32(0, a.stats().checksumErrors);
}

// A checksum-valid but absurd speed must be rejected before the knots-to-mm/s product can overflow int64.
static void test_absurd_speed_rejected(void)
{
    NmeaEpochAssembler a;
    feedStr(a, rmc("123519.00", "271126", LATLON, "999999999999.999999"), 0);
    a.poll(1000);
    TEST_ASSERT_EQUAL_UINT32(0, a.available());
    TEST_ASSERT_EQUAL_UINT32(1, a.stats().badSentences);
}

// An overlong line (no terminator in sight) is rejected once, and the next '$' restarts parsing cleanly.
static void test_overlong_line_rejected_and_parser_resyncs(void)
{
    NmeaEpochAssembler a;
    feedStr(a, "$GNGGA," + std::string(200, '1'), 0);
    feedStr(a, gga("123519.00"), 0);
    feedStr(a, rmc("123519.00"), 10);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, a.stats().badSentences);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_TRUE(v[0].valid);

    // A sentence cut off by a new '$', and one hit by a non-printable byte, are each one bad sentence.
    NmeaEpochAssembler b;
    feedStr(b, "$GNGGA,123519.00,48", 0);
    std::string noisy = gga("123520.00");
    noisy[20] = '\x01';
    feedStr(b, noisy, 0);
    feedStr(b, gga("123521.00"), 0);
    feedStr(b, rmc("123521.00"), 10);
    TEST_ASSERT_EQUAL_UINT32(2, b.stats().badSentences);
    TEST_ASSERT_EQUAL_UINT32(1, drain(b).size());
}

// --- timeout and closing ---

// The window runs from the '$' of the epoch's first sentence; it is still open 1 ms before the timeout and closed at it.
static void test_missing_rmc_emitted_after_timeout_with_carried_date(void)
{
    constexpr uint32_t T = NmeaEpochAssembler::DEFAULT_TIMEOUT_MS;
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    feedStr(a, rmc("123519.00"), 20);
    drain(a);
    feedStr(a, gga("123520.00"), 1000);
    a.poll(1000 + T - 1);
    TEST_ASSERT_EQUAL_UINT32(0, a.available());
    a.poll(1000 + T);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    const GnssEpoch &e = v[0];
    TEST_ASSERT_EQUAL_INT((int)GnssEpochClose::TIMEOUT, (int)e.closeReason);
    TEST_ASSERT_EQUAL_UINT32(2, e.epochCounter);
    TEST_ASSERT_TRUE(e.hasGga);
    TEST_ASSERT_FALSE(e.hasRmc);
    TEST_ASSERT_TRUE(e.hasDate);
    TEST_ASSERT_TRUE(e.dateCarried);
    TEST_ASSERT_EQUAL_INT64(DAY_2026_11_27 * MS_PER_DAY + tod(12, 35, 20), e.fixUtcMs);
    TEST_ASSERT_EQUAL_UINT32(1000, e.deviceMsFirstByte);
    TEST_ASSERT_EQUAL_UINT32(1000 + T, e.deviceMsComplete);
}

// The GPS thread drains GGA at t and, after a stall, the RMC that had been waiting in the UART at t+310. Both halves of
// one fix time must still be one valid epoch: with the old 300 ms timeout checked in feed(), the RMC's first byte closed
// the GGA alone as TIMEOUT and the receiver's valid fix was reported as NO_FIX.
static void test_split_drain_310ms_apart_is_one_valid_epoch(void)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 5000);
    a.poll(5000);
    feedStr(a, rmc("123519.00"), 5310);
    a.poll(5310);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_EQUAL_INT((int)GnssEpochClose::COMPLETE, (int)v[0].closeReason);
    TEST_ASSERT_TRUE(v[0].valid);
    TEST_ASSERT_EQUAL_UINT32(5000, v[0].deviceMsFirstByte);
    TEST_ASSERT_EQUAL_UINT32(5310, v[0].deviceMsComplete);
}

// feed() never judges the timeout, however late the drain stamp: only poll() after the drain does.
static void test_feed_never_closes_an_epoch_by_timeout(void)
{
    constexpr uint32_t T = NmeaEpochAssembler::DEFAULT_TIMEOUT_MS;
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    a.feed('\n', T + 10);
    TEST_ASSERT_EQUAL_UINT32(0, a.available());
    feedStr(a, rmc("123519.00"), T + 10);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_EQUAL_INT((int)GnssEpochClose::COMPLETE, (int)v[0].closeReason);
    TEST_ASSERT_TRUE(v[0].valid);
}

// A sentence with the next fix time closes the epoch before the timeout would.
static void test_missing_rmc_emitted_when_next_time_arrives(void)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    feedStr(a, gga("123519.10"), 100);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_EQUAL_INT((int)GnssEpochClose::SUPERSEDED, (int)v[0].closeReason);
    TEST_ASSERT_EQUAL_UINT32(tod(12, 35, 19), v[0].utcTodMs);
    TEST_ASSERT_FALSE(v[0].hasDate); // no RMC seen yet, nothing to carry
    TEST_ASSERT_EQUAL_UINT32(100, v[0].deviceMsComplete);
}

// The RMC for a time whose epoch already closed by timeout must not create a second record for that time.
static void test_late_rmc_after_timeout_is_stale(void)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    a.poll(NmeaEpochAssembler::DEFAULT_TIMEOUT_MS);
    feedStr(a, rmc("123519.00"), NmeaEpochAssembler::DEFAULT_TIMEOUT_MS + 50);
    a.poll(2000);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_FALSE(v[0].hasRmc);
    TEST_ASSERT_EQUAL_UINT32(1, a.stats().staleSentences);
}

// A second GGA for the same time (two talkers) is ignored, not a new epoch.
static void test_duplicate_sentence_in_epoch_is_stale(void)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    feedStr(a, gga("123519.00", "4807.000000,N,01131.000000,E"), 5);
    feedStr(a, rmc("123519.00"), 10);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_EQUAL_INT32(481173041, v[0].latE7);
    TEST_ASSERT_EQUAL_UINT32(1, a.stats().staleSentences);
}

// --- dates ---

// The GGA of 00:00:00 arrives before the RMC carrying the new date (and year): the pair is one epoch on the new date.
static void test_midnight_gga_before_rmc_takes_new_date(void)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("235959.00"), 0);
    feedStr(a, rmc("235959.00", "311226"), 20);
    feedStr(a, gga("000000.00"), 1000);
    feedStr(a, rmc("000000.00", "010127"), 1020);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(2, v.size());
    TEST_ASSERT_EQUAL_INT64(DAY_2026_12_31 * MS_PER_DAY + tod(23, 59, 59), v[0].fixUtcMs);
    TEST_ASSERT_EQUAL_INT64(DAY_2027_01_01 * MS_PER_DAY, v[1].fixUtcMs);
    TEST_ASSERT_FALSE(v[1].dateCarried);
}

// With no RMC after midnight, the carried date must roll to the next day (and here the next year).
static void test_midnight_gga_only_carries_rolled_date(void)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("235959.00"), 0);
    feedStr(a, rmc("235959.00", "311226"), 20);
    feedStr(a, gga("000000.00"), 1000);
    a.poll(1000 + NmeaEpochAssembler::DEFAULT_TIMEOUT_MS);
    feedStr(a, gga("000001.00"), 2000);
    a.poll(2000 + NmeaEpochAssembler::DEFAULT_TIMEOUT_MS);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(3, v.size());
    TEST_ASSERT_TRUE(v[1].hasDate && v[1].dateCarried);
    TEST_ASSERT_EQUAL_INT64(DAY_2027_01_01 * MS_PER_DAY, v[1].fixUtcMs);
    TEST_ASSERT_EQUAL_INT64(DAY_2027_01_01 * MS_PER_DAY + 1000, v[2].fixUtcMs);
}

// A small step back in time (receiver re-acquisition) is not a midnight; the date is unknown rather than guessed.
static void test_small_backward_step_leaves_date_unknown(void)
{
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    feedStr(a, rmc("123519.00"), 20);
    feedStr(a, gga("123510.00"), 1000);
    a.poll(1000 + NmeaEpochAssembler::DEFAULT_TIMEOUT_MS);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(2, v.size());
    TEST_ASSERT_FALSE(v[1].hasDate);
}

// A void RMC before the first fix carries whatever date the receiver defaults to. It dates its own NO_FIX epoch, but
// must not become the date later GGA-only epochs inherit; an earlier status-A date stays the carried one.
static void test_void_rmc_date_does_not_date_later_epochs(void)
{
    constexpr uint32_t T = NmeaEpochAssembler::DEFAULT_TIMEOUT_MS;
    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    feedStr(a, rmc("123519.00", "010125", LATLON, "0.00", "0.00", 'V'), 20);
    feedStr(a, gga("123520.00"), 1000);
    a.poll(1000 + T);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(2, v.size());
    TEST_ASSERT_TRUE(v[0].hasDate); // its own date, as SPEC 9.3 lets a NO_FIX carry fix_utc_ms
    TEST_ASSERT_FALSE(v[1].hasDate);

    NmeaEpochAssembler b;
    feedStr(b, gga("123519.00"), 0);
    feedStr(b, rmc("123519.00"), 20); // status A, 27 Nov 2026
    feedStr(b, gga("123520.00"), 1000);
    feedStr(b, rmc("123520.00", "010125", LATLON, "0.00", "0.00", 'V'), 1020);
    feedStr(b, gga("123521.00"), 2000);
    b.poll(2000 + T);
    v = drain(b);
    TEST_ASSERT_EQUAL_UINT32(3, v.size());
    TEST_ASSERT_TRUE(v[2].hasDate && v[2].dateCarried);
    TEST_ASSERT_EQUAL_INT64(DAY_2026_11_27 * MS_PER_DAY + tod(12, 35, 21), v[2].fixUtcMs);
}

// Day 31 of a 30-day month and 29 Feb of a common year are malformed sentences; 29 Feb of a leap year is a date.
static void test_rmc_date_validated_per_month(void)
{
    const char *bad[] = {"311126", "310426", "300226", "290226", "000126"};
    for (const char *d : bad) {
        NmeaEpochAssembler a;
        feedStr(a, rmc("123519.00", d), 0);
        a.poll(NmeaEpochAssembler::DEFAULT_TIMEOUT_MS);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, a.available(), d);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, a.stats().badSentences, d);
    }
    const GnssEpoch leap = single(rmc("123519.00", "290228"));
    TEST_ASSERT_TRUE(leap.hasDate);
    TEST_ASSERT_EQUAL_INT64((int64_t)21243 * MS_PER_DAY + tod(12, 35, 19), leap.fixUtcMs); // 2028-02-29
    TEST_ASSERT_TRUE(single(rmc("123519.00", "311226")).hasDate);
    TEST_ASSERT_TRUE(single(rmc("123519.00", "300426")).hasDate);
}

// A year outside the window is a receiver default (e.g. 06 Jan 1980, read as 2080): the RMC keeps its fix data but has
// no date, and dates nothing after it. The window's own edges are dates.
static void test_rmc_year_outside_window_is_no_date(void)
{
    const char *outside[] = {"060180", "311223", "010180"};
    for (const char *d : outside) {
        const GnssEpoch e = single(rmc("123519.00", d));
        TEST_ASSERT_TRUE_MESSAGE(e.hasRmc, d);
        TEST_ASSERT_FALSE_MESSAGE(e.hasDate, d);
    }
    TEST_ASSERT_TRUE(single(rmc("123519.00", "010124")).hasDate);
    TEST_ASSERT_TRUE(single(rmc("123519.00", "311279")).hasDate);

    NmeaEpochAssembler a;
    feedStr(a, gga("123519.00"), 0);
    feedStr(a, rmc("123519.00", "060180"), 20);
    std::vector<GnssEpoch> v = drain(a);
    TEST_ASSERT_EQUAL_UINT32(1, v.size());
    TEST_ASSERT_TRUE(v[0].valid);
    TEST_ASSERT_FALSE(v[0].hasDate);
    TEST_ASSERT_EQUAL_UINT32(0, a.stats().badSentences);
}

// --- conversions ---

static void test_latlon_integer_conversion_exact(void)
{
    // 48 + 7.038247/60 = 48.1173041166..., 11 + 31/60 = 11.5166666...
    GnssEpoch e = single(gga("123519.00", "4807.038247,S,01131.000000,W"));
    TEST_ASSERT_EQUAL_INT32(-481173041, e.latE7);
    TEST_ASSERT_EQUAL_INT32(-115166667, e.lonE7);
    // 37 + 45.123456/60 = 37.7520576 exactly; 122 + 25.654321/60 = 122.4275720166...
    e = single(gga("123519.00", "3745.123456,S,12225.654321,W"));
    TEST_ASSERT_EQUAL_INT32(-377520576, e.latE7);
    TEST_ASSERT_EQUAL_INT32(-1224275720, e.lonE7);
    // 0.000003' = 0.5e-7 degrees exactly: rounds half up (a truncating conversion gives 0).
    e = single(gga("123519.00", "0000.000003,N,00000.000000,E"));
    TEST_ASSERT_EQUAL_INT32(1, e.latE7);
    TEST_ASSERT_EQUAL_INT32(0, e.lonE7);
    // 7-digit minutes at the edges of the range: 89 59.9999999' N, 179 59.9999999' E.
    e = single(gga("123519.00", "8959.9999999,N,17959.9999999,E"));
    TEST_ASSERT_EQUAL_INT32(900000000, e.latE7);
    TEST_ASSERT_EQUAL_INT32(1800000000, e.lonE7);
    // 2 fractional digits, as some receivers send: 52 + 31.12/60 = 52.518666...
    e = single(gga("123519.00", "5231.12,N,01324.56,E"));
    TEST_ASSERT_EQUAL_INT32(525186667, e.latE7);
    TEST_ASSERT_EQUAL_INT32(134093333, e.lonE7);
}

static void test_speed_and_course_conversion(void)
{
    struct Case {
        const char *speed, *course;
        uint32_t mms;
        uint16_t cdeg;
    } cases[] = {
        {"0.000", "0.00", 0, 0},         {"1.000", "359.99", 514, 35999}, // 1852/3600 = 0.514444 m/s
        {"22.40", "84.40", 11524, 8440}, {"100.5", "359.996", 51702, 0},  // 359.996 rounds to 360.00, which is 0
        {"0.001", "0.004", 1, 0},                                         // 0.514 mm/s rounds to 1
    };
    for (const Case &c : cases) {
        const GnssEpoch e = single(rmc("123519.00", "271126", LATLON, c.speed, c.course));
        TEST_ASSERT_TRUE(e.hasSpeed && e.hasCourse);
        TEST_ASSERT_EQUAL_UINT32(c.mms, e.speedMmS);
        TEST_ASSERT_EQUAL_UINT16(c.cdeg, e.courseCdeg);
    }
    const GnssEpoch none = single(rmc("123519.00", "271126", LATLON, "", ""));
    TEST_ASSERT_FALSE(none.hasSpeed);
    TEST_ASSERT_FALSE(none.hasCourse);
}

// --- output queue ---

// The queue is fixed size: an unread backlog drops the oldest epochs and counts them.
static void test_queue_full_drops_oldest(void)
{
    NmeaEpochAssembler a;
    const int n = (int)NmeaEpochAssembler::QUEUE_CAPACITY + 2;
    for (int i = 0; i < n; i++) {
        char t[16];
        snprintf(t, sizeof(t), "1235%02d.00", 10 + i);
        feedStr(a, gga(t), (uint32_t)i * 1000);
        feedStr(a, rmc(t), (uint32_t)i * 1000 + 20);
    }
    TEST_ASSERT_EQUAL_UINT32(NmeaEpochAssembler::QUEUE_CAPACITY, a.available());
    TEST_ASSERT_EQUAL_UINT32(2, a.stats().queueOverflows);
    GnssEpoch e;
    TEST_ASSERT_TRUE(a.pop(e));
    TEST_ASSERT_EQUAL_UINT32(3, e.epochCounter);
}

// --- decimation ---

static GnssEpoch epochAt(int64_t fixUtcMs)
{
    GnssEpoch e = {};
    e.hasDate = true;
    e.fixUtcMs = fixUtcMs;
    e.utcTodMs = (uint32_t)(fixUtcMs % MS_PER_DAY);
    return e;
}

static void test_selectForPeriod_1000_selects_every_epoch(void)
{
    const int64_t base = DAY_2026_11_27 * MS_PER_DAY + tod(12, 35, 18);
    for (int s = 0; s < 10; s++) {
        TEST_ASSERT_TRUE(selectForPeriod(epochAt(base + s * 1000), 1000));
        TEST_ASSERT_TRUE(selectForPeriod(epochAt(base + s * 1000 + 100), 1000));
    }
}

static void test_selectForPeriod_2000_selects_even_seconds(void)
{
    const int64_t base = DAY_2026_11_27 * MS_PER_DAY + tod(12, 35, 18);
    TEST_ASSERT_TRUE(selectForPeriod(epochAt(base), 2000));
    TEST_ASSERT_TRUE(selectForPeriod(epochAt(base + 100), 2000)); // .10 still second 18
    TEST_ASSERT_FALSE(selectForPeriod(epochAt(base + 1000), 2000));
    TEST_ASSERT_FALSE(selectForPeriod(epochAt(base + 1900), 2000)); // .90 still second 19
    TEST_ASSERT_TRUE(selectForPeriod(epochAt(base + 2000), 2000));
}

static void test_selectForPeriod_5000_selects_every_fifth_second(void)
{
    const int64_t base = DAY_2026_11_27 * MS_PER_DAY + tod(12, 35, 20);
    int selected = 0;
    for (int s = 0; s < 10; s++) {
        const bool sel = selectForPeriod(epochAt(base + s * 1000 + 100), 5000);
        TEST_ASSERT_EQUAL(s % 5 == 0, sel);
        selected += sel;
    }
    TEST_ASSERT_EQUAL_INT(2, selected);
}

// Without a date the UTC time of day gives the same grid, since 86400 is a multiple of 2 and 5.
static void test_selectForPeriod_without_date_uses_time_of_day(void)
{
    GnssEpoch e = {};
    e.utcTodMs = tod(12, 35, 20, 100);
    TEST_ASSERT_TRUE(selectForPeriod(e, 5000));
    e.utcTodMs = tod(12, 35, 21, 0);
    TEST_ASSERT_FALSE(selectForPeriod(e, 2000));
    TEST_ASSERT_FALSE(selectForPeriod(e, 5000));
}

void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_gga_then_rmc_emits_one_complete_epoch);
    RUN_TEST(test_other_sentences_do_not_close_epoch);
    RUN_TEST(test_any_talker_id_accepted);
    RUN_TEST(test_split_at_every_byte_boundary_yields_identical_records);
    RUN_TEST(test_identical_coordinates_every_second_yield_distinct_epochs);
    RUN_TEST(test_rmc_void_is_not_valid);
    RUN_TEST(test_gga_quality_zero_is_not_valid);
    RUN_TEST(test_dead_reckoning_quality6_mode_E_is_not_valid);
    RUN_TEST(test_manual_quality7_is_not_valid);
    RUN_TEST(test_simulator_quality8_is_not_valid);
    RUN_TEST(test_gga_quality_above_8_reads_as_absent);
    RUN_TEST(test_mode_N_with_good_data_is_not_valid);
    RUN_TEST(test_validity_quality_and_mode_boundaries);
    RUN_TEST(test_time_without_fix_is_emitted_invalid);
    RUN_TEST(test_gga_only_is_not_valid);
    RUN_TEST(test_bad_checksum_dropped_and_counted);
    RUN_TEST(test_malformed_fields_dropped_and_counted);
    RUN_TEST(test_absurd_speed_rejected);
    RUN_TEST(test_overlong_line_rejected_and_parser_resyncs);
    RUN_TEST(test_missing_rmc_emitted_after_timeout_with_carried_date);
    RUN_TEST(test_split_drain_310ms_apart_is_one_valid_epoch);
    RUN_TEST(test_feed_never_closes_an_epoch_by_timeout);
    RUN_TEST(test_missing_rmc_emitted_when_next_time_arrives);
    RUN_TEST(test_late_rmc_after_timeout_is_stale);
    RUN_TEST(test_duplicate_sentence_in_epoch_is_stale);
    RUN_TEST(test_midnight_gga_before_rmc_takes_new_date);
    RUN_TEST(test_midnight_gga_only_carries_rolled_date);
    RUN_TEST(test_small_backward_step_leaves_date_unknown);
    RUN_TEST(test_void_rmc_date_does_not_date_later_epochs);
    RUN_TEST(test_rmc_date_validated_per_month);
    RUN_TEST(test_rmc_year_outside_window_is_no_date);
    RUN_TEST(test_latlon_integer_conversion_exact);
    RUN_TEST(test_speed_and_course_conversion);
    RUN_TEST(test_queue_full_drops_oldest);
    RUN_TEST(test_selectForPeriod_1000_selects_every_epoch);
    RUN_TEST(test_selectForPeriod_2000_selects_even_seconds);
    RUN_TEST(test_selectForPeriod_5000_selects_every_fifth_second);
    RUN_TEST(test_selectForPeriod_without_date_uses_time_of_day);
    exit(UNITY_END());
}

void loop() {}
