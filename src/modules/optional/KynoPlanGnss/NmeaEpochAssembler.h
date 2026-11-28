#pragma once

#if defined(KYNOPLAN_GNSS_STREAM) || defined(PIO_UNIT_TESTING)

#include <stddef.h>
#include <stdint.h>

// Why an epoch was closed and emitted.
enum class GnssEpochClose : uint8_t { COMPLETE = 0, SUPERSEDED = 1, TIMEOUT = 2 };

// One receiver fix time, assembled from the GGA and RMC sentences that carry it. Fields mirror NMEA content only.
struct GnssEpoch {
    uint32_t epochCounter;      // 1 for the first emitted epoch, +1 per emitted epoch
    uint32_t utcTodMs;          // UTC time of day from the sentences (ms since 00:00:00)
    int64_t fixUtcMs;           // ms since the Unix epoch, meaningful only when hasDate; 23:59:60 is not distinguished
    uint32_t deviceMsFirstByte; // monotonic ms of the '$' of the epoch's first accepted sentence
    uint32_t deviceMsComplete;  // monotonic ms at which the epoch was emitted
    int32_t latE7;              // degrees * 1e7, valid when hasPosition
    int32_t lonE7;
    int32_t altMslCm;    // GGA altitude above mean sea level
    int32_t geoidSepCm;  // GGA geoid separation
    uint32_t speedMmS;   // RMC speed over ground
    uint16_t courseCdeg; // RMC course over ground, 0..35999
    uint16_t hdopX100;   // GGA HDOP * 100, saturated at 65535
    uint8_t ggaQuality;  // GGA fix quality 0..8 (an empty field, or a value above 8, reads as 0)
    uint8_t satsUsed;    // GGA satellites used
    char rmcStatus;      // 'A' / 'V', 0 without RMC
    char rmcMode;        // NMEA 2.3+ mode indicator (A/D/E/N/...), 0 when absent
    // A measured fix (KynoPlan SPEC 9.3): GGA and RMC present, status 'A', quality 1..5, mode (if sent) not E/M/S/N.
    bool valid;
    bool hasGga;
    bool hasRmc;
    bool hasDate;     // fixUtcMs is set (date from this epoch's RMC, or carried forward from a status-A RMC)
    bool dateCarried; // hasDate, but the date came from an earlier epoch, not this epoch's RMC
    bool hasPosition;
    bool hasAltitude;
    bool hasGeoidSep;
    bool hasHdop;
    bool hasSats;
    bool hasSpeed;
    bool hasCourse;
    GnssEpochClose closeReason;
};

struct NmeaEpochStats {
    uint32_t badSentences;     // checksum, malformed, overlong or truncated lines (all dropped)
    uint32_t checksumErrors;   // subset of badSentences
    uint32_t staleSentences;   // GGA/RMC for an epoch already emitted, or a duplicate within one epoch
    uint32_t untimedSentences; // well-formed GGA/RMC with an empty time field
    uint32_t queueOverflows;   // epochs dropped (oldest first) because the output queue was full
};

// Choose epochs on a UTC-second grid: 1000 = every, 2000 = even seconds, 5000 = seconds % 5 == 0.
// periodMs is rounded to whole seconds (minimum 1); the fractional part of the fix time is ignored.
// Receivers above 1 Hz are out of scope: every epoch within a selected second passes.
bool selectForPeriod(const GnssEpoch &epoch, uint32_t periodMs);

// Byte-fed NMEA parser for GGA/RMC (any talker) that emits one GnssEpoch per receiver fix time.
class NmeaEpochAssembler
{
  public:
    static constexpr size_t MAX_LINE = 96; // NMEA's 82 incl. "$" and CRLF, plus margin
    static constexpr size_t QUEUE_CAPACITY = 8;
    // Leaves room for GSA/GSV between GGA and RMC at 9600 baud and a late drain; well inside SPEC 9.3's 1500 ms expiry
    static constexpr uint32_t DEFAULT_TIMEOUT_MS = 700;
    static constexpr uint8_t MAX_GGA_QUALITY = 8;
    static constexpr int32_t MIN_DATE_YEAR = 2024; // RMC dates outside this window are receiver defaults, not dates
    static constexpr int32_t MAX_DATE_YEAR = 2079;

    explicit NmeaEpochAssembler(uint32_t epochTimeoutMs = DEFAULT_TIMEOUT_MS);

    // Never closes an epoch by timeout: bytes are stamped once per drain, so a late stamp is not a late sentence.
    void feed(char c, uint32_t monotonicMs);
    void feed(const char *data, size_t len, uint32_t monotonicMs);
    // Emits the pending epoch if its timeout has passed. Call it after each drain, once the UART has been emptied.
    void poll(uint32_t nowMs);

    size_t available() const { return queueCount; }
    bool pop(GnssEpoch &out);
    const NmeaEpochStats &stats() const { return counters; }
    void reset();

  private:
    struct Field {
        const char *p;
        size_t n;
    };

    void endLine(uint32_t nowMs);
    void processSentence(uint32_t nowMs);
    bool parseGga(const Field *f, size_t nf, GnssEpoch &s, uint32_t &tod, bool &hasTime);
    bool parseRmc(const Field *f, size_t nf, GnssEpoch &s, uint32_t &tod, bool &hasTime, int32_t &days, bool &hasDays);
    void mergeSentence(bool isGga, const GnssEpoch &s, uint32_t tod, bool hasDays, int32_t days, uint32_t nowMs);
    void emitPending(GnssEpochClose reason, uint32_t nowMs);
    void checkTimeout(uint32_t nowMs);
    void badLine();

    uint32_t timeoutMs;

    char line[MAX_LINE];
    size_t lineLen = 0;
    bool inLine = false;
    bool lineOverflow = false;
    uint32_t lineStartMs = 0;

    bool hasPending = false;
    GnssEpoch pending = {};
    bool pendingHasRmcDate = false;
    int32_t pendingDays = 0;

    bool hasLastEmitted = false;
    uint32_t lastEmittedTod = 0;
    uint32_t emittedCount = 0;

    bool hasDateAnchor = false;
    int32_t anchorDays = 0;
    uint32_t anchorTod = 0;

    GnssEpoch queue[QUEUE_CAPACITY];
    size_t queueHead = 0;
    size_t queueCount = 0;

    NmeaEpochStats counters = {};
};

#endif
