#pragma once

#if defined(KYNOPLAN_GNSS_STREAM)

#include <stdint.h>

// The GPS thread's side of the KynoPlan GNSS stream: GPS.cpp calls the sink, a module registers it.
// Thread context: every sink callback runs on the GPS OSThread, i.e. the cooperative main loop, never from an ISR or
// the BLE task. onByte runs once per received byte and onDrainEnd once per GPS runOnce(); both must stay short.
// wantsAwake is sampled once per runOnce() and must be a cheap, lock-free read of state the module already holds.
using KynoPlanGnssByteFn = void (*)(char c, uint32_t monotonicMs);
using KynoPlanGnssAwakeFn = bool (*)();
using KynoPlanGnssDrainEndFn = void (*)(uint32_t monotonicMs);

// Register the sink once, before the GPS thread runs; nullptr restores the default (no-op / false).
void kynoplanGnssSetTap(KynoPlanGnssByteFn onByte, KynoPlanGnssAwakeFn wantsAwake, KynoPlanGnssDrainEndFn onDrainEnd = nullptr);

// Every byte the GPS drain reads from the receiver UART, stamped with Time::getMillisMonotonic() at drain start.
void kynoplanGnssOnNmeaByte(char c, uint32_t monotonicMs);

// After every GPS runOnce() drain, with the UART emptied: where NmeaEpochAssembler::poll() belongs.
void kynoplanGnssOnDrainEnd(uint32_t monotonicMs);

// True while a stream client needs NMEA, so the receiver must stay powered between position fixes.
bool kynoplanGnssWantsReceiverAwake();

// Module -> GPS: run the GPS thread now (once wantsAwake turns true) instead of at its next <= 5 s wake check.
// Main-loop context only. Implemented in GPS.cpp; does nothing while the receiver is already searching.
void kynoplanGnssKick();

#endif
