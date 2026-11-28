// KynoPlan GNSS stream tap in src/gps/GPS.cpp: kynoplanGnssOnNmeaByte() fed from GPS::whileActive(),
// kynoplanGnssOnDrainEnd() after every drain, kynoplanGnssWantsReceiverAwake() sampled once per GPS::runOnce()
// (sink registered through kynoplanGnssSetTap() in src/modules/optional/KynoPlanGnss/KynoPlanGnssHooks.cpp), and
// kynoplanGnssKick(), with which the module wakes the GPS thread on stream start.
//
// Why: the stream needs every NMEA byte the receiver produces, including between position fixes, but
// every GPS::publishUpdate() reaches PositionModule::handleNewPosition() -> trySmartBroadcast(), which
// can put a position on LoRa. So the tap must be invisible to the position logic: while a stream wants
// the receiver awake, GPS::down() parks it in GPS_IDLE instead of sleeping, and the IDLE drain hands the
// bytes to the tap only - never to the TinyGPS reader, never to publishUpdate(). The thread runs every
// <= GPS_THREAD_INTERVAL ms to drain, but its wake checks stay on the 5 s ticks the scheduler has
// without the tap, so up()/down() happen at the same instants.
//
// Each case drives GPS::runOnce() the way the OSThread scheduler does - advancing a virtual clock by
// each returned interval - against a scripted receiver that emits a GGA+RMC burst every second while
// its EN pin is high. The tap-active run is compared, event for event, with a run that has no tap.
//
// Regressions guarded:
//   - the tap misses bytes the drain consumed, or the reader stops getting them;
//   - with no stream, anything at all differs from a build without the tap;
//   - a stream does not stop the hard sleep, or the IDLE bytes are discarded instead of tapped;
//   - the IDLE bytes reach the TinyGPS reader, or the faster drain ticks move the wake checks: either
//     adds or moves publishUpdate() calls, i.e. extra LoRa position broadcasts;
//   - the receiver stays powered after the stream ends, or a stream starting mid-sleep starts a search;
//   - the warm lock times learned while the stream keeps the receiver powered outlive the stream: the prediction
//     stays short and every cold search after the stream starts late, moving post-stream publishes;
//   - the stream-mode drain interval loses upstream's 16 ms spread, so drains phase-lock to the 1 s bursts;
//   - a drain ends without kynoplanGnssOnDrainEnd(), so the epoch timeout is judged on a half-read UART;
//   - kynoplanGnssKick() does not reschedule the thread (stream start waits up to 5 s), or the kicked run moves
//     the 5 s wake-check phase and with it the next search.
//
// KYNOPLAN_GNSS_STREAM reaches GPS.cpp only in [env:coverage-kynoplan]; a #define here could not, as the
// src objects are compiled once per env. Under plain coverage only the baseline-harness cases run.
#include "MeshTypes.h" // before TestUtil.h
#include "TestUtil.h"
#include <unity.h>

#if defined(ARCH_PORTDUINO)

#include "GPSStatus.h"
#include "GpioLogic.h"
#include "Observer.h"
#include "PowerMon.h"
#include "UptimeClock.h"
#include "gps/GPS.h"
#include "gps/RTC.h"
#include "mesh/NodeDB.h"
#include <HardwareSerial.h>
#include <cstdio>
#include <string>
#include <vector>
#if defined(KYNOPLAN_GNSS_STREAM)
#include "modules/optional/KynoPlanGnss/KynoPlanGnssHooks.h"
#endif

class GpsTestShim : public GPS
{
  public:
    static void setSerial(HardwareSerial *serial) { _serial_gps = serial; }
    void prime()
    {
        gnssModel = GNSS_MODEL_MTK; // neither u-blox nor Airoha, and native has no standby pin: hard sleep, as the X1
        GPSInitFinished = true;
    }
    int32_t tick() { return runOnce(); }
    unsigned long scheduledInterval() const { return interval; }
    void scheduleIn(unsigned long ms) { setInterval(ms); }
    GPSPowerState state() const { return powerState; }
    uint32_t readerChars() const
    {
#ifndef TINYGPS_OPTION_NO_STATISTICS
        return reader.charsProcessed();
#else
        return 0;
#endif
    }
};

namespace
{

class ScriptedSerial : public HardwareSerial
{
  public:
    void begin(unsigned long) override {}
    void begin(unsigned long, uint16_t) override {}
    void end() override {}
    int available() override { return (int)(pending.size() - pos); }
    int peek() override { return available() ? (uint8_t)pending[pos] : -1; }
    int read() override
    {
        if (!available())
            return -1;
        consumed += pending[pos];
        return (uint8_t)pending[pos++];
    }
    void flush() override {}
    size_t write(uint8_t) override { return 1; }
    operator bool() override { return true; }

    void append(const std::string &s) { pending += s; }
    void reset()
    {
        pending.clear();
        consumed.clear();
        pos = 0;
    }
    std::string consumed; // every byte anything read from the port, in order

  private:
    std::string pending;
    size_t pos = 0;
};

std::string nmea(const std::string &body)
{
    uint8_t cs = 0;
    for (char c : body)
        cs ^= (uint8_t)c;
    char tail[8];
    snprintf(tail, sizeof(tail), "*%02X\r\n", cs);
    return "$" + body + tail;
}

// One second of receiver output: a fixed 3D fix, UTC 12:00:00 + second, 1 Jan 2030 (past any BUILD_EPOCH).
std::string burst(uint32_t second)
{
    char hms[16];
    snprintf(hms, sizeof(hms), "%02u%02u%02u.00", 12 + second / 3600 % 12, second / 60 % 60, second % 60);
    const std::string t = hms;
    return nmea("GPGGA," + t + ",4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,") +
           nmea("GPRMC," + t + ",A,4807.038,N,01131.000,E,000.0,000.0,010130,,,A");
}

// The same second before the first fix after power-on: time only, no position.
std::string noFixBurst(uint32_t second)
{
    char hms[16];
    snprintf(hms, sizeof(hms), "%02u%02u%02u.00", 12 + second / 3600 % 12, second / 60 % 60, second % 60);
    const std::string t = hms;
    return nmea("GPGGA," + t + ",,,,,0,00,99.9,,,,,,") + nmea("GPRMC," + t + ",V,,,,,,,010130,,,N");
}

enum : char { EV_PUBLISH = 'P', EV_UP = 'U', EV_DOWN = 'D' };
struct Event {
    uint32_t atMs;
    char kind;
    bool operator==(const Event &o) const { return atMs == o.atMs && kind == o.kind; }
};

struct Trace {
    std::vector<Event> events; // publishUpdate() notifications and scheduler wake/sleep decisions
    std::vector<GPSPowerState> states;
    uint32_t readerChars = 0;
    uint32_t idleBytesTapped = 0;
    bool consumedAllTapped = false;
    bool pinAlwaysOn = true;
    int32_t lastLatitude = 0;
    std::vector<uint32_t> stateAtMs;      // elapsed ms at which each entry of `states` began
    std::vector<int32_t> streamIntervals; // runOnce() intervals returned while held in GPS_IDLE for the stream
    bool drainEndAfterEveryByte = true;
};

constexpr uint32_t START_MS = 100000;
constexpr uint32_t UPDATE_INTERVAL_S = 30; // > GPS_UPDATE_ALWAYS_ON_THRESHOLD_MS, so the hold-then-sleep path runs

ScriptedSerial serial;
GpioVirtPin enablePin;
Trace *recording = nullptr;
std::string tapped;
bool streamWanted = false;
uint32_t coldStartMs = 0;       // receiver outputs no fix for this long after power-on
uint32_t kickAtMs = UINT32_MAX; // elapsed ms at which the scenario calls kynoplanGnssKick()
size_t bytesSinceDrainEnd = 0;  // bytes tapped since the last kynoplanGnssOnDrainEnd()

struct StatusRecorder {
    int onStatus(const meshtastic::GPSStatus *s)
    {
        recording->events.push_back({Time::getMillis(), EV_PUBLISH});
        recording->lastLatitude = s->getLatitude();
        return 0;
    }
} statusRecorder;

#if defined(KYNOPLAN_GNSS_STREAM)
void tapOnByte(char c, uint32_t)
{
    tapped += c;
    bytesSinceDrainEnd++;
}
void tapOnDrainEnd(uint32_t)
{
    bytesSinceDrainEnd = 0;
}
bool tapWantsAwake()
{
    return streamWanted;
}
#endif

using StreamScript = bool (*)(uint32_t elapsedMs); // what kynoplanGnssWantsReceiverAwake() answers, over time

// Runs the GPS thread for durationMs as the OSThread scheduler would. `script` null: no stream.
Trace runScenario(uint32_t durationMs, StreamScript script)
{
    Trace trace;
    recording = &trace;
    tapped.clear();
    serial.reset();
    streamWanted = false;
    bytesSinceDrainEnd = 0;
    randomSeed(1234);
    resetRTCStateForTests();
    Time::resetMonotonicForTests();
    Time::setTestMillis(START_MS);

    GpsTestShim *shim = new GpsTestShim();
    GpsTestShim::setSerial(&serial);
    shim->enablePin = &enablePin;
    shim->prime();
    CallbackObserver<StatusRecorder, const meshtastic::GPSStatus *> observer(&statusRecorder, &StatusRecorder::onStatus);
    observer.observe(&shim->newStatus);
    shim->enable();
    gps.reset(shim); // kynoplanGnssKick() reschedules the global GPS thread

    uint32_t nextBurstS = 0;
    bool wasPowered = false;
    uint32_t poweredSinceMs = 0;
    for (uint32_t now = START_MS; now - START_MS < durationMs;) {
        const uint32_t elapsed = now - START_MS;
        if (script)
            streamWanted = script(elapsed);
        const bool powered = enablePin.get() == GpioVirtPin::On;
        if (powered && !wasPowered)
            poweredSinceMs = elapsed;
        wasPowered = powered;
        for (; nextBurstS * 1000 <= elapsed; nextBurstS++) {
            if (powered)
                serial.append(elapsed - poweredSinceMs < coldStartMs ? noFixBurst(nextBurstS) : burst(nextBurstS));
        }
        const GPSPowerState before = shim->state();
        const size_t tappedBefore = tapped.size();
        const int32_t interval = shim->tick();
        const GPSPowerState after = shim->state();
        if (before == GPS_IDLE && after != GPS_ACTIVE)
            trace.idleBytesTapped += tapped.size() - tappedBefore;
        if (before != GPS_ACTIVE && after == GPS_ACTIVE)
            trace.events.push_back({now, EV_UP});
        if (before == GPS_ACTIVE && after != GPS_ACTIVE)
            trace.events.push_back({now, EV_DOWN});
        if (trace.states.empty() || trace.states.back() != after) {
            trace.states.push_back(after);
            trace.stateAtMs.push_back(elapsed);
        }
        if (enablePin.get() != GpioVirtPin::On)
            trace.pinAlwaysOn = false;
        if (bytesSinceDrainEnd != 0)
            trace.drainEndAfterEveryByte = false;
        if (before == GPS_IDLE && after == GPS_IDLE && streamWanted)
            trace.streamIntervals.push_back(interval);
        TEST_ASSERT_TRUE_MESSAGE(interval >= 0 && interval <= 5000, "GPS thread interval out of range");
        if (kickAtMs > elapsed && kickAtMs - elapsed <= (uint32_t)interval) {
            // The module starts the stream and kicks; the scheduler runs the thread at once if the kick rescheduled it
            now = START_MS + kickAtMs;
            Time::setTestMillis(now);
            if (script)
                streamWanted = script(kickAtMs);
#if defined(KYNOPLAN_GNSS_STREAM)
            shim->scheduleIn(GPS_THREAD_INTERVAL);
            kynoplanGnssKick();
#endif
            if (shim->scheduledInterval() == 0)
                continue;
            now = START_MS + elapsed + (uint32_t)interval;
        } else {
            now += (uint32_t)interval;
        }
        Time::setTestMillis(now);
    }

    trace.readerChars = shim->readerChars();
    trace.consumedAllTapped = !tapped.empty() && tapped == serial.consumed;
    observer.unobserve(&shim->newStatus);
    gps.release();
    shim->disable();
    delete shim;
    recording = nullptr;
    return trace;
}

bool contains(const std::vector<GPSPowerState> &states, GPSPowerState s)
{
    for (auto x : states)
        if (x == s)
            return true;
    return false;
}

size_t countKind(const Trace &t, char kind)
{
    size_t n = 0;
    for (const auto &e : t.events)
        n += e.kind == kind;
    return n;
}

void assertSameEvents(const Trace &expected, const Trace &actual)
{
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(expected.events.size(), actual.events.size(), "event count differs");
    for (size_t i = 0; i < expected.events.size(); i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "event %u (%c at %u ms)", (unsigned)i, expected.events[i].kind, expected.events[i].atMs);
        TEST_ASSERT_EQUAL_INT_MESSAGE(expected.events[i].kind, actual.events[i].kind, msg);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(expected.events[i].atMs, actual.events[i].atMs, msg);
    }
}

constexpr uint32_t SCENARIO_MS = 150 * 1000; // several lock -> hold -> publish -> sleep cycles

} // namespace

void setUp(void)
{
    config.position.gps_update_interval = UPDATE_INTERVAL_S;
    config.position.fixed_position = false;
    // DISABLED keeps publishUpdate() off positionModule (null here); newStatus still fires on every publish
    config.position.gps_mode = meshtastic_Config_PositionConfig_GpsMode_DISABLED;
    coldStartMs = 0;
    kickAtMs = UINT32_MAX;
#if defined(KYNOPLAN_GNSS_STREAM)
    kynoplanGnssSetTap(nullptr, nullptr);
#endif
}

void tearDown(void)
{
#if defined(KYNOPLAN_GNSS_STREAM)
    kynoplanGnssSetTap(nullptr, nullptr);
#endif
    Time::useRealClock();
}

// The harness premise every comparison below rests on: without a stream the receiver locks, publishes
// and hard-sleeps on a cycle, several times per scenario.
void test_baseline_harness_cycles_through_hard_sleep(void)
{
    const Trace t = runScenario(SCENARIO_MS, nullptr);
    TEST_ASSERT_TRUE_MESSAGE(contains(t.states, GPS_HARDSLEEP), "baseline must hard-sleep");
    TEST_ASSERT_TRUE_MESSAGE(countKind(t, EV_DOWN) >= 3, "expected several search cycles");
    TEST_ASSERT_TRUE_MESSAGE(countKind(t, EV_PUBLISH) >= 3, "expected publishes");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, t.lastLatitude, "the reader never produced a fix");
}

#if defined(KYNOPLAN_GNSS_STREAM)

bool neverWanted(uint32_t)
{
    return false;
}
bool alwaysWanted(uint32_t)
{
    return true;
}
// Wanted from the start, dropped 5 s into the first sleep (first down() is ~21 s in).
bool wantedUntil26s(uint32_t elapsedMs)
{
    return elapsedMs < 26000;
}
// Starts 3 s into the first hard sleep.
bool wantedFrom24s(uint32_t elapsedMs)
{
    return elapsedMs >= 24000;
}

void test_tap_receives_every_byte_the_drain_consumes(void)
{
    kynoplanGnssSetTap(tapOnByte, tapWantsAwake);
    const Trace t = runScenario(SCENARIO_MS, neverWanted);
    TEST_ASSERT_TRUE_MESSAGE(t.consumedAllTapped, "tap must see exactly the bytes read from the UART");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(serial.consumed.size(), t.readerChars, "TinyGPS must still get every byte");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, t.lastLatitude, "the reader never produced a fix");
}

void test_no_stream_behaves_exactly_as_without_the_tap(void)
{
    const Trace without = runScenario(SCENARIO_MS, nullptr);
    kynoplanGnssSetTap(tapOnByte, tapWantsAwake);
    const Trace with = runScenario(SCENARIO_MS, neverWanted);
    assertSameEvents(without, with);
    TEST_ASSERT_TRUE_MESSAGE(without.states == with.states, "power state sequence differs");
    TEST_ASSERT_EQUAL_UINT32(without.readerChars, with.readerChars);
}

void test_stream_keeps_the_receiver_powered_and_tapped(void)
{
    kynoplanGnssSetTap(tapOnByte, tapWantsAwake);
    const Trace t = runScenario(SCENARIO_MS, alwaysWanted);
    TEST_ASSERT_FALSE_MESSAGE(contains(t.states, GPS_HARDSLEEP), "a stream must not hard-sleep the receiver");
    TEST_ASSERT_FALSE(contains(t.states, GPS_SOFTSLEEP));
    TEST_ASSERT_TRUE_MESSAGE(contains(t.states, GPS_IDLE), "between fixes the receiver idles");
    TEST_ASSERT_TRUE_MESSAGE(t.pinAlwaysOn, "receiver EN must stay high");
    TEST_ASSERT_TRUE_MESSAGE(t.idleBytesTapped > 0, "NMEA between fixes must reach the tap");
    TEST_ASSERT_TRUE_MESSAGE(t.consumedAllTapped, "no byte may be read without reaching the tap");
    TEST_ASSERT_LESS_THAN_UINT32_MESSAGE(serial.consumed.size(), t.readerChars, "IDLE bytes must not reach TinyGPS");
}

// The "no extra LoRa broadcasts" regression: same publishes, same wake and sleep decisions, same instants.
void test_stream_leaves_publishes_and_scheduler_decisions_identical(void)
{
    const Trace without = runScenario(SCENARIO_MS, nullptr);
    kynoplanGnssSetTap(tapOnByte, tapWantsAwake);
    const Trace with = runScenario(SCENARIO_MS, alwaysWanted);
    TEST_ASSERT_TRUE_MESSAGE(contains(without.states, GPS_HARDSLEEP), "test premise: the baseline sleeps");
    assertSameEvents(without, with);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(without.readerChars, with.readerChars, "TinyGPS input differs");
    TEST_ASSERT_EQUAL_INT32(without.lastLatitude, with.lastLatitude);
}

void test_stream_end_puts_the_receiver_back_to_sleep(void)
{
    const Trace without = runScenario(SCENARIO_MS, nullptr);
    kynoplanGnssSetTap(tapOnByte, tapWantsAwake);
    const Trace with = runScenario(SCENARIO_MS, wantedUntil26s);
    assertSameEvents(without, with);
    // IDLE (held) -> HARDSLEEP once the stream ends, without waiting for the next search
    TEST_ASSERT_TRUE_MESSAGE(with.states.size() >= 3, "expected ACTIVE, IDLE, HARDSLEEP");
    TEST_ASSERT_EQUAL(GPS_ACTIVE, with.states[0]);
    TEST_ASSERT_EQUAL(GPS_IDLE, with.states[1]);
    TEST_ASSERT_EQUAL(GPS_HARDSLEEP, with.states[2]);
}

void test_stream_start_during_sleep_wakes_without_a_search(void)
{
    const Trace without = runScenario(SCENARIO_MS, nullptr);
    kynoplanGnssSetTap(tapOnByte, tapWantsAwake);
    const Trace with = runScenario(SCENARIO_MS, wantedFrom24s);
    assertSameEvents(without, with);
    TEST_ASSERT_TRUE_MESSAGE(with.states.size() >= 3, "expected ACTIVE, HARDSLEEP, IDLE");
    TEST_ASSERT_EQUAL(GPS_HARDSLEEP, with.states[1]);
    TEST_ASSERT_EQUAL(GPS_IDLE, with.states[2]);
    TEST_ASSERT_TRUE_MESSAGE(with.idleBytesTapped > 0, "the woken receiver's NMEA must reach the tap");
}

// Upstream spreads ACTIVE drains over GPS_THREAD_INTERVAL + random(16) so they do not lock to the receiver's 1 s
// bursts and split GGA/RMC pairs the same way every second. Stream drains in GPS_IDLE keep that spread (from their
// own generator, so random() draws, and with them ACTIVE timing, stay as without the tap).
void test_stream_drain_interval_keeps_the_upstream_spread(void)
{
    kynoplanGnssSetTap(tapOnByte, tapWantsAwake);
    const Trace t = runScenario(SCENARIO_MS, alwaysWanted);
    bool seen[16] = {};
    size_t distinct = 0;
    for (int32_t i : t.streamIntervals) {
        TEST_ASSERT_TRUE_MESSAGE(i <= GPS_THREAD_INTERVAL + 15, "stream drain interval above the spread");
        if (i >= GPS_THREAD_INTERVAL && !seen[i - GPS_THREAD_INTERVAL]) {
            seen[i - GPS_THREAD_INTERVAL] = true;
            distinct++;
        }
    }
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32_MESSAGE(8, distinct, "stream drains must spread over the 16 ms window");
}

// NmeaEpochAssembler::poll() runs from kynoplanGnssOnDrainEnd(); every tapped byte must be followed by one before the
// thread sleeps, or the epoch timeout is judged while part of the epoch is still unread.
void test_every_drain_is_followed_by_the_drain_end_hook(void)
{
    kynoplanGnssSetTap(tapOnByte, tapWantsAwake, tapOnDrainEnd);
    const Trace t = runScenario(SCENARIO_MS, alwaysWanted);
    TEST_ASSERT_TRUE(t.idleBytesTapped > 0);
    TEST_ASSERT_TRUE_MESSAGE(t.drainEndAfterEveryByte, "a drain ended without kynoplanGnssOnDrainEnd()");
}

// The module kicks the GPS thread when a stream starts 3 s into a hard sleep: the receiver must power up at that
// instant, not at the next 5 s tick, and the kicked run must neither start a search nor move the wake-check phase.
void test_kick_wakes_the_receiver_at_stream_start_and_keeps_the_schedule(void)
{
    const Trace without = runScenario(SCENARIO_MS, nullptr);
    kynoplanGnssSetTap(tapOnByte, tapWantsAwake);
    const Trace unkicked = runScenario(SCENARIO_MS, wantedFrom24s);
    TEST_ASSERT_TRUE(unkicked.states.size() >= 3);
    TEST_ASSERT_TRUE_MESSAGE(unkicked.stateAtMs[2] > 24000, "test premise: without a kick the wake waits for a tick");
    kickAtMs = 24000;
    const Trace with = runScenario(SCENARIO_MS, wantedFrom24s);
    TEST_ASSERT_TRUE(with.states.size() >= 3);
    TEST_ASSERT_EQUAL(GPS_HARDSLEEP, with.states[1]);
    TEST_ASSERT_EQUAL(GPS_IDLE, with.states[2]);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(24000, with.stateAtMs[2], "the kick must wake the receiver at once");
    assertSameEvents(without, with);
}

// Stream from the 2nd to the 5th search end, with a receiver that needs 20 s from power-on to its first fix. Searches
// 3-5 begin on a receiver the stream kept powered and lock at once. Learning them keeps the cadence during the stream,
// but the model they leave is a warm one: carried past the stream, it starts the cold post-stream searches late and
// moves every publish. GPS::down() restores the model saved when the stream first held the receiver, so after the
// stream the time from each search end to the next search start (60 s minus the prediction, on the 5 s tick grid)
// must be what it is without a stream.
bool wantedFromDown2ToDown5(uint32_t)
{
    const size_t downs = countKind(*recording, EV_DOWN);
    return downs >= 2 && downs < 5;
}

std::vector<uint32_t> gapsAfterDowns(const Trace &t)
{
    std::vector<uint32_t> gaps;
    for (size_t i = 0; i < t.events.size(); i++) {
        if (t.events[i].kind != EV_DOWN)
            continue;
        for (size_t j = i + 1; j < t.events.size(); j++) {
            if (t.events[j].kind == EV_UP) {
                gaps.push_back(t.events[j].atMs - t.events[i].atMs);
                break;
            }
        }
    }
    return gaps;
}

std::vector<uint32_t> searchDurations(const Trace &t)
{
    std::vector<uint32_t> d;
    uint32_t upAt = START_MS;
    for (const Event &e : t.events) {
        if (e.kind == EV_UP)
            upAt = e.atMs;
        else if (e.kind == EV_DOWN)
            d.push_back(e.atMs - upAt);
    }
    return d;
}

void test_searches_on_a_receiver_kept_warm_do_not_shorten_the_lock_prediction(void)
{
    config.position.gps_update_interval = 60;
    coldStartMs = 20000;
    constexpr uint32_t LONG_SCENARIO_MS = 600 * 1000;
    const Trace without = runScenario(LONG_SCENARIO_MS, nullptr);
    kynoplanGnssSetTap(tapOnByte, tapWantsAwake);
    const Trace with = runScenario(LONG_SCENARIO_MS, wantedFromDown2ToDown5);

    const std::vector<uint32_t> coldSearch = searchDurations(without), mixedSearch = searchDurations(with);
    const std::vector<uint32_t> coldGaps = gapsAfterDowns(without), mixedGaps = gapsAfterDowns(with);
    TEST_ASSERT_TRUE_MESSAGE(coldGaps.size() >= 7 && mixedGaps.size() >= 7, "expected 8 search cycles");
    TEST_ASSERT_TRUE(coldSearch.size() >= 5 && mixedSearch.size() >= 5);
    for (size_t i = 2; i < 5; i++) // test premise: the stream made searches 3-5 warm
        TEST_ASSERT_TRUE_MESSAGE(mixedSearch[i] + 10000 < coldSearch[i], "held search was not warm");
    for (size_t i = 5; i < 7; i++) {
        char msg[48];
        snprintf(msg, sizeof(msg), "sleep after search %u", (unsigned)i + 1);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(coldGaps[i], mixedGaps[i], msg);
    }
}

#endif // KYNOPLAN_GNSS_STREAM

void setup()
{
    initializeTestEnvironment();
    if (!powerMon)
        powerMonInit();
    UNITY_BEGIN();
    RUN_TEST(test_baseline_harness_cycles_through_hard_sleep);
#if defined(KYNOPLAN_GNSS_STREAM)
    RUN_TEST(test_tap_receives_every_byte_the_drain_consumes);
    RUN_TEST(test_no_stream_behaves_exactly_as_without_the_tap);
    RUN_TEST(test_stream_keeps_the_receiver_powered_and_tapped);
    RUN_TEST(test_stream_leaves_publishes_and_scheduler_decisions_identical);
    RUN_TEST(test_stream_end_puts_the_receiver_back_to_sleep);
    RUN_TEST(test_stream_start_during_sleep_wakes_without_a_search);
    RUN_TEST(test_stream_drain_interval_keeps_the_upstream_spread);
    RUN_TEST(test_every_drain_is_followed_by_the_drain_end_hook);
    RUN_TEST(test_kick_wakes_the_receiver_at_stream_start_and_keeps_the_schedule);
    RUN_TEST(test_searches_on_a_receiver_kept_warm_do_not_shorten_the_lock_prediction);
#endif
    exit(UNITY_END());
}

void loop() {}

#else

void setUp(void) {}
void tearDown(void) {}
void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    exit(UNITY_END());
}
void loop() {}

#endif
