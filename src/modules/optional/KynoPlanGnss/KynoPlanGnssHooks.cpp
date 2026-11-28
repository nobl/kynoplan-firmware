#include "KynoPlanGnssHooks.h"

#if defined(KYNOPLAN_GNSS_STREAM)

#include "configuration.h"

namespace
{
KynoPlanGnssByteFn tapOnByte = nullptr;
KynoPlanGnssAwakeFn tapWantsAwake = nullptr;
KynoPlanGnssDrainEndFn tapOnDrainEnd = nullptr;
} // namespace

void kynoplanGnssSetTap(KynoPlanGnssByteFn onByte, KynoPlanGnssAwakeFn wantsAwake, KynoPlanGnssDrainEndFn onDrainEnd)
{
    tapOnByte = onByte;
    tapWantsAwake = wantsAwake;
    tapOnDrainEnd = onDrainEnd;
}

void kynoplanGnssOnNmeaByte(char c, uint32_t monotonicMs)
{
    if (tapOnByte)
        tapOnByte(c, monotonicMs);
}

void kynoplanGnssOnDrainEnd(uint32_t monotonicMs)
{
    if (tapOnDrainEnd)
        tapOnDrainEnd(monotonicMs);
}

bool kynoplanGnssWantsReceiverAwake()
{
    return tapWantsAwake && tapWantsAwake();
}

#if MESHTASTIC_EXCLUDE_GPS
void kynoplanGnssKick() {} // no GPS thread to wake
#endif

#endif
