#pragma once

#include "mesh/MeshTypes.h"
#include "mesh/generated/meshtastic/mesh.pb.h"
#include <cstdint>

// Private-application portnum (256-511 range in portnums.proto) for KynoPlan enhanced-GNSS traffic.
// This traffic is phone <-> this node only: it must never reach LoRa, MQTT or UDP.
constexpr uint32_t KYNOPLAN_GNSS_PORTNUM = 300;

// The PhoneAPI transport a client packet arrived on, passed by PhoneAPI into MeshService::handleToRadio.
// UNKNOWN is the default for every other caller and is refused like OTHER (USB serial, TCP, HTTP, ...).
enum class KynoplanToRadioTransport : uint8_t { UNKNOWN = 0, BLE, OTHER };

// True if p is decoded on the KynoPlan GNSS port. The variant is checked first because decoded.portnum
// aliases encrypted.size in the payload union; an undecoded packet's port cannot be known.
inline bool kynoplanGnssPortPacket(const meshtastic_MeshPacket &p)
{
    return p.which_payload_variant == meshtastic_MeshPacket_decoded_tag && (uint32_t)p.decoded.portnum == KYNOPLAN_GNSS_PORTNUM;
}

// True only for a decoded KynoPlan GNSS packet addressed to this node (never broadcast, never unknown ourNode).
// hop_limit and want_ack are deliberately ignored: a packet to us is delivered locally and never routed.
inline bool kynoplanGnssPacketAllowedFromPhone(const meshtastic_MeshPacket &p, NodeNum ourNode)
{
    return kynoplanGnssPortPacket(p) && ourNode != 0 && p.to == ourNode && p.to != NODENUM_BROADCAST &&
           p.to != NODENUM_BROADCAST_NO_LORA;
}

// SPEC section 3.4: a client packet on the KynoPlan GNSS port is accepted only from the BLE PhoneAPI and
// only when addressed to this node. MeshService::handleToRadio refuses everything else.
inline bool kynoplanGnssClientPacketAllowed(const meshtastic_MeshPacket &p, NodeNum ourNode, KynoplanToRadioTransport transport)
{
    return transport == KynoplanToRadioTransport::BLE && kynoplanGnssPacketAllowedFromPhone(p, ourNode);
}

// Link markers, one per guard, defined in the guarded translation unit under KYNOPLAN_GNSS_STREAM. The future
// KynoPlan module must reference all of them so a build without a guard fails to link; today only the tests do.
extern const uint32_t kynoplanLocalOnlyGuardInstalled; // MeshService.cpp: client packets (handleToRadio)
extern const uint32_t kynoplanIngressGuardInstalled;   // Router.cpp: LoRa/MQTT/UDP ingress, local loopback, Router::send
extern const uint32_t kynoplanDuplicateGuardInstalled; // FloodingRouter.cpp: duplicate relay/ACK (reprocessPacket)
