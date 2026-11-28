// KynoPlan enhanced-GNSS traffic (private portnum 300) is local-only: BLE phone <-> this node, never LoRa or MQTT.
//
// Under test:
//   - kynoplanGnssPortPacket(), kynoplanGnssPacketAllowedFromPhone() and kynoplanGnssClientPacketAllowed() in
//     src/modules/optional/KynoPlanGnss/KynoPlanGnssPort.h - the pure decisions, tested in every build.
//   - The KYNOPLAN_GNSS_STREAM guards (they need the flag in the src build, so they run only under
//     [env:coverage-kynoplan] in variants/native/portduino/platformio.ini):
//       * MeshService::handleToRadio() (src/mesh/MeshService.cpp): refuses a client packet on port 300 unless it
//         came from the BLE PhoneAPI and is addressed to this node. PhoneAPI::handleToRadioPacket()
//         (src/mesh/PhoneAPI.cpp) passes the transport, BLE only for api_type == TYPE_BLE.
//       * passesRoutingAuthGate() (src/mesh/Router.cpp): rejects decoded port-300 mesh ingress (LoRa, MQTT, UDP)
//         before PacketHistory, relay, ACK, modules, NodeDB or MQTT uplink see it. On the already-decoded branch
//         the refusal runs before checkXeddsaReceivePolicy(), which would otherwise re-admit a warm-tier signer
//         (getOrCreateMeshNode) or set its signer bit.
//       * perhapsDecode() (src/mesh/Router.cpp): a PKI-decrypted port-300 packet is refused before the admin-key
//         fallback commits the sender's key to NodeDB (commitRemoteKey), and a channel-decrypted one before
//         checkXeddsaReceivePolicy() runs.
//       * Router::dispatchReceived() (src/mesh/Router.cpp): drops any port-300 packet not from RX_SRC_USER before
//         modules, MQTT uplink and the NodeDB hear record - in particular a device-originated local loopback.
//       * FloodingRouter::reprocessPacket() (src/mesh/FloodingRouter.cpp): a duplicate on port 300 is never relayed
//         or ACKed - the dupe/upgrade relay paths inside shouldFilterReceived() run before dispatchReceived().
//       * Router::send() (src/mesh/Router.cpp): drops a device-originated port-300 send before LoRa. It is not the
//         funnel for all egress: relays forward the received ciphertext (useReceivedPayload) and MQTT uplink of
//         received traffic happens in dispatchReceived(), which is why the ingress guards above exist.
//       * The link markers kynoplanLocalOnlyGuardInstalled (MeshService.cpp), kynoplanIngressGuardInstalled
//         (Router.cpp) and kynoplanDuplicateGuardInstalled (FloodingRouter.cpp).
//
// Why: SPEC section 3.4 (contract-v0.1) - a port-300 frame is accepted only from the BLE PhoneAPI, addressed to
// the device; everything else (LoRa, MQTT, USB serial/TCP, misaddressed) is dropped before any routing or state
// change and never reaches LoRa or MQTT (acceptance 14.1); a build without the guards must fail to link (14.2).
// A private portnum does not keep a packet local: Router::sendLocal() transmits anything not to us, and a frame
// heard from another node is relayed as received ciphertext and uplinked to MQTT. KynoPlan GNSS packets carry a
// high-rate precise track of the user, so every one of these paths must fail closed. An undecoded
// (client-encrypted or undecryptable) frame's port cannot be known, so it is not treated as KynoPlan traffic;
// that limitation is pinned below.
//
// Regressions guarded:
//   - Predicate relaxed (broadcast / other node / ourNode==0 / non-BLE transport accepted, or the decoded-variant
//     check dropped so encrypted.size==300 reads as port 300 through the union): the predicate cases fail.
//   - MeshService guard deleted, moved below the from/id rewrite, or ignoring the transport: the client packet is
//     rewritten or delivered, no NOT_AUTHORIZED QueueStatus is sent, a broadcast is looped back to modules.
//   - PhoneAPI passing BLE for every transport: the serial PhoneAPI case reaches the module.
//   - Ingress gate deleted: a port-300 frame from another node enters PacketHistory; with the other ingress
//     guards deleted too it is relayed over LoRa, uplinked to MQTT and delivered to modules.
//   - Gate refusal moved back below checkXeddsaReceivePolicy(): a signed, already-decoded port-300 frame
//     re-admits its warm-tier sender to the hot NodeDB, or sets a hot node's signer bit, before being dropped.
//   - perhapsDecode channel-decrypt refusal deleted: the same signed frame, channel-encrypted, re-admits or marks its
//     sender from inside perhapsDecode(), before the gate sees the port.
//   - perhapsDecode PKI refusal deleted: a port-300 DM decrypted via an admin key persists the sender's key.
//   - dispatchReceived drop deleted: a device-originated port-300 loopback reaches modules as RX_SRC_LOCAL.
//   - reprocessPacket refusal deleted: a repeated port-300 duplicate is relayed, or ACKed when it is to us.
//   - Router::send guard deleted: a device-originated port-300 packet reaches the radio and MQTT.
//   - A marker definition deleted (any of the three): this suite fails to link under coverage-kynoplan.
//   - Over-blocking: an allowed BLE packet to this node must still reach the module with RX_SRC_USER, and the
//     same traffic on an adjacent port must still be relayed, uplinked and ACKed (control cases).

#include "MeshTypes.h" // BEFORE TestUtil.h
#include "TestUtil.h"
#include <unity.h>

#include "modules/optional/KynoPlanGnss/KynoPlanGnssPort.h"

static constexpr NodeNum PRED_US = 0x0A0A0A0A;
static constexpr NodeNum PRED_OTHER = 0x0B0B0B0B;

static meshtastic_MeshPacket makePortPacket(uint32_t port, NodeNum to)
{
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.to = to;
    p.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    p.decoded.portnum = (meshtastic_PortNum)port;
    p.decoded.payload.size = 4;
    return p;
}

void test_predicate_port300_to_us_is_allowed(void)
{
    meshtastic_MeshPacket p = makePortPacket(KYNOPLAN_GNSS_PORTNUM, PRED_US);
    TEST_ASSERT_TRUE(kynoplanGnssPortPacket(p));
    TEST_ASSERT_TRUE(kynoplanGnssPacketAllowedFromPhone(p, PRED_US));
}

void test_predicate_port300_broadcast_is_refused(void)
{
    meshtastic_MeshPacket p = makePortPacket(KYNOPLAN_GNSS_PORTNUM, NODENUM_BROADCAST);
    TEST_ASSERT_TRUE(kynoplanGnssPortPacket(p));
    TEST_ASSERT_FALSE(kynoplanGnssPacketAllowedFromPhone(p, PRED_US));
    // Even a bogus ourNode equal to a broadcast address must not turn a broadcast into "to us".
    TEST_ASSERT_FALSE(kynoplanGnssPacketAllowedFromPhone(p, NODENUM_BROADCAST));
    p.to = NODENUM_BROADCAST_NO_LORA;
    TEST_ASSERT_FALSE(kynoplanGnssPacketAllowedFromPhone(p, PRED_US));
    TEST_ASSERT_FALSE(kynoplanGnssPacketAllowedFromPhone(p, NODENUM_BROADCAST_NO_LORA));
}

void test_predicate_port300_unicast_to_other_node_is_refused(void)
{
    meshtastic_MeshPacket p = makePortPacket(KYNOPLAN_GNSS_PORTNUM, PRED_OTHER);
    TEST_ASSERT_FALSE(kynoplanGnssPacketAllowedFromPhone(p, PRED_US));
}

// Before our node number is known it is 0; a client packet with to=0 must not count as "to us".
void test_predicate_unknown_own_node_refuses_to_zero(void)
{
    meshtastic_MeshPacket p = makePortPacket(KYNOPLAN_GNSS_PORTNUM, 0);
    TEST_ASSERT_FALSE(kynoplanGnssPacketAllowedFromPhone(p, 0));
}

void test_predicate_other_ports_are_not_kynoplan(void)
{
    const uint32_t ports[] = {0, meshtastic_PortNum_TEXT_MESSAGE_APP, meshtastic_PortNum_POSITION_APP, 256, 299, 301, 511};
    for (uint32_t port : ports) {
        meshtastic_MeshPacket p = makePortPacket(port, PRED_US);
        TEST_ASSERT_FALSE_MESSAGE(kynoplanGnssPortPacket(p), "only portnum 300 is the KynoPlan GNSS port");
        TEST_ASSERT_FALSE(kynoplanGnssPacketAllowedFromPhone(p, PRED_US));
    }
}

// decoded.portnum shares storage with encrypted.size: an encrypted packet whose size field reads 300 must
// not be taken for a decoded port-300 packet. Predicate only - 300 exceeds the encrypted buffer.
void test_predicate_undecoded_packets_are_not_kynoplan(void)
{
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.to = PRED_US;
    p.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    p.encrypted.size = KYNOPLAN_GNSS_PORTNUM;
    TEST_ASSERT_EQUAL_UINT32(KYNOPLAN_GNSS_PORTNUM, (uint32_t)p.decoded.portnum); // the alias is real
    TEST_ASSERT_FALSE(kynoplanGnssPortPacket(p));
    TEST_ASSERT_FALSE(kynoplanGnssPacketAllowedFromPhone(p, PRED_US));

    p.which_payload_variant = 0; // no payload variant at all
    TEST_ASSERT_FALSE(kynoplanGnssPortPacket(p));
    TEST_ASSERT_FALSE(kynoplanGnssPacketAllowedFromPhone(p, PRED_US));
}

// from is rewritten to 0 by handleToRadio and hop_limit/want_ack never matter for a local delivery, so
// none of them may change the verdict in either direction.
void test_predicate_ignores_from_hop_limit_and_want_ack(void)
{
    meshtastic_MeshPacket allowed = makePortPacket(KYNOPLAN_GNSS_PORTNUM, PRED_US);
    meshtastic_MeshPacket refused = makePortPacket(KYNOPLAN_GNSS_PORTNUM, NODENUM_BROADCAST);
    for (meshtastic_MeshPacket *p : {&allowed, &refused}) {
        p->from = PRED_OTHER;
        p->hop_limit = HOP_MAX;
        p->hop_start = HOP_MAX;
        p->want_ack = true;
    }
    TEST_ASSERT_TRUE(kynoplanGnssPacketAllowedFromPhone(allowed, PRED_US));
    TEST_ASSERT_FALSE(kynoplanGnssPacketAllowedFromPhone(refused, PRED_US));
}

// SPEC 3.4: only the BLE PhoneAPI may carry port 300. UNKNOWN (a caller that does not say) and OTHER
// (USB serial, TCP, HTTP) are refused even for a correctly addressed packet; addressing still applies to BLE.
void test_predicate_client_packet_requires_ble_transport(void)
{
    const meshtastic_MeshPacket toUs = makePortPacket(KYNOPLAN_GNSS_PORTNUM, PRED_US);
    TEST_ASSERT_TRUE(kynoplanGnssClientPacketAllowed(toUs, PRED_US, KynoplanToRadioTransport::BLE));
    TEST_ASSERT_FALSE(kynoplanGnssClientPacketAllowed(toUs, PRED_US, KynoplanToRadioTransport::OTHER));
    TEST_ASSERT_FALSE(kynoplanGnssClientPacketAllowed(toUs, PRED_US, KynoplanToRadioTransport::UNKNOWN));

    const meshtastic_MeshPacket bcast = makePortPacket(KYNOPLAN_GNSS_PORTNUM, NODENUM_BROADCAST);
    TEST_ASSERT_FALSE(kynoplanGnssClientPacketAllowed(bcast, PRED_US, KynoplanToRadioTransport::BLE));
    const meshtastic_MeshPacket other = makePortPacket(KYNOPLAN_GNSS_PORTNUM, PRED_OTHER);
    TEST_ASSERT_FALSE(kynoplanGnssClientPacketAllowed(other, PRED_US, KynoplanToRadioTransport::BLE));
}

// The harness is built, and its flag-independent control case runs, in both envs so the suite's persisted-state
// footprint (state-manifest.tsv) is the same with and without the flag; only the guard cases need the flag.
#if !(MESHTASTIC_EXCLUDE_PKI) && !(MESHTASTIC_EXCLUDE_XEDDSA)
#define KYNOPLAN_HARNESS 1
#include "support/AuthPipelineHarness.h"
#if defined(KYNOPLAN_GNSS_STREAM)
#define KYNOPLAN_PIPELINE_TESTS 1
#include "PhoneAPI.h"
#endif

static constexpr NodeNum CLIENT_CLAIMED_FROM = 0x00001234;
static constexpr uint32_t CONTROL_PORT = KYNOPLAN_GNSS_PORTNUM + 1;

/// Stands in for the KynoPlan module: records every port-300 packet dispatched to modules.
class KynoPlanPortProbe : public SinglePortModule
{
  public:
    // loopbackOk: the worst case - a module that also takes the device's own loopback (RX_SRC_LOCAL).
    KynoPlanPortProbe() : SinglePortModule("kynoplanProbe", (meshtastic_PortNum)KYNOPLAN_GNSS_PORTNUM) { loopbackOk = true; }
    ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override
    {
        calls++;
        lastSrc = currentRequestSource;
        lastFrom = mp.from;
        return ProcessMessage::CONTINUE;
    }
    uint32_t calls = 0;
    RxSource lastSrc = RX_SRC_LOCAL;
    NodeNum lastFrom = 0xFFFFFFFF;
};

static KynoPlanPortProbe *probe = nullptr;

void setUp(void)
{
    pipelineHarnessSetUp();
    // MQTT uplink live on the primary channel, so a leak would be visible in the uplink queue.
    moduleConfig.mqtt.enabled = true;
    moduleConfig.mqtt.encryption_enabled = true;
    strcpy(moduleConfig.mqtt.root, "msh");
    channels.getByIndex(0).settings.uplink_enabled = true;
    probe->calls = 0;
    probe->lastSrc = RX_SRC_LOCAL;
    probe->lastFrom = 0xFFFFFFFF;
}

void tearDown(void)
{
    pipelineHarnessTearDown();
}

/// A packet as a client app writes it: claimed sender, no id, so any rewrite by the service is visible.
static meshtastic_MeshPacket makeClientPacket(uint32_t port, NodeNum to)
{
    meshtastic_MeshPacket p = makeDecoded(CLIENT_CLAIMED_FROM, to, (meshtastic_PortNum)port, SMALL_PAYLOAD);
    p.id = 0;
    p.hop_limit = 3;
    return p;
}

// Control: the same client packets on an adjacent port do go to LoRa and MQTT. Without this the
// refusal cases could pass because the fixture never transmits or uplinks anything. It needs no flag, so it runs in
// both envs: it pins the default build's upstream behaviour, and the prefs it persists (warm.dat included) give the
// suite the same state footprint in both envs, which is what test/state-manifest.tsv declares.
void test_control_adjacent_port_reaches_radio_and_mqtt(void)
{
    meshtastic_MeshPacket bcast = makeClientPacket(CONTROL_PORT, NODENUM_BROADCAST);
    pipelineService->handleToRadio(bcast);
    TEST_ASSERT_EQUAL_UINT32(1, pipelineRadio->sendCalls);
    TEST_ASSERT_EQUAL(1, pipelineMqtt->queueSize());

    meshtastic_MeshPacket unicast = makeClientPacket(CONTROL_PORT, REMOTE_NODE);
    pipelineService->handleToRadio(unicast);
    TEST_ASSERT_EQUAL_UINT32(2, pipelineRadio->sendCalls);
    TEST_ASSERT_EQUAL(2, pipelineMqtt->queueSize());
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0, unicast.from, "the normal path rewrites from, which the refusal cases rely on");
}

#if defined(KYNOPLAN_PIPELINE_TESTS)
static int32_t takeQueueStatusResult()
{
    meshtastic_QueueStatus *qs = pipelineService->getQueueStatusForPhone();
    TEST_ASSERT_NOT_NULL_MESSAGE(qs, "the client must be answered with a QueueStatus");
    const int32_t res = qs->res;
    pipelineService->releaseQueueStatusToPool(qs);
    return res;
}

/// The client packet was refused before handleToRadio touched anything, and nothing left the node.
static void assertRefusedUntouched(const meshtastic_MeshPacket &p, NodeNum to)
{
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(CLIENT_CLAIMED_FROM, p.from, "guard must run before from is forced to 0");
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0, p.id, "guard must run before a packet id is assigned");
    TEST_ASSERT_EQUAL_HEX32(to, p.to);
    TEST_ASSERT_EQUAL_INT32(meshtastic_Routing_Error_NOT_AUTHORIZED, takeQueueStatusResult());
    TEST_ASSERT_NULL_MESSAGE(pipelineService->getQueueStatusForPhone(), "exactly one QueueStatus");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, pipelineRadio->sendCalls, "must never reach LoRa");
    TEST_ASSERT_EQUAL_MESSAGE(0, pipelineMqtt->queueSize(), "must never reach MQTT");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, probe->calls, "a refused packet is not looped back to modules either");
    TEST_ASSERT_EQUAL_MESSAGE(0, pipelineRouter->pendingCount(), "no retransmission state");
    TEST_ASSERT_EQUAL(0, drainPhoneQueue());
}

void test_handleToRadio_port300_broadcast_is_dropped(void)
{
    meshtastic_MeshPacket p = makeClientPacket(KYNOPLAN_GNSS_PORTNUM, NODENUM_BROADCAST);
    p.want_ack = true;
    pipelineService->handleToRadio(p, KynoplanToRadioTransport::BLE);
    assertRefusedUntouched(p, NODENUM_BROADCAST);
}

void test_handleToRadio_port300_broadcast_no_lora_is_dropped(void)
{
    meshtastic_MeshPacket p = makeClientPacket(KYNOPLAN_GNSS_PORTNUM, NODENUM_BROADCAST_NO_LORA);
    pipelineService->handleToRadio(p, KynoplanToRadioTransport::BLE);
    assertRefusedUntouched(p, NODENUM_BROADCAST_NO_LORA);
}

void test_handleToRadio_port300_unicast_to_other_node_is_dropped(void)
{
    meshtastic_MeshPacket p = makeClientPacket(KYNOPLAN_GNSS_PORTNUM, REMOTE_NODE);
    p.want_ack = true;
    pipelineService->handleToRadio(p, KynoplanToRadioTransport::BLE);
    assertRefusedUntouched(p, REMOTE_NODE);
}

// Transparent mode has its own branch for client packets; the guard sits above it.
void test_handleToRadio_port300_dropped_in_transparent_mode(void)
{
    config.lora.transparent_mode = true;
    meshtastic_MeshPacket p = makeClientPacket(KYNOPLAN_GNSS_PORTNUM, REMOTE_NODE);
    pipelineService->handleToRadio(p, KynoplanToRadioTransport::BLE);
    assertRefusedUntouched(p, REMOTE_NODE);
}

// The allowed shape is delivered locally only: the module sees it as client traffic (RX_SRC_USER, from 0),
// and nothing is transmitted or uplinked, whatever hop_limit/want_ack say.
void test_handleToRadio_port300_to_us_is_delivered_locally_only(void)
{
    meshtastic_MeshPacket p = makeClientPacket(KYNOPLAN_GNSS_PORTNUM, LOCAL_NODE);
    p.want_ack = true;
    p.hop_limit = HOP_MAX;
    pipelineService->handleToRadio(p, KynoplanToRadioTransport::BLE);

    TEST_ASSERT_EQUAL_UINT32(1, probe->calls);
    TEST_ASSERT_EQUAL(RX_SRC_USER, probe->lastSrc);
    TEST_ASSERT_EQUAL_HEX32(0, probe->lastFrom);
    TEST_ASSERT_EQUAL_INT32(ERRNO_OK, takeQueueStatusResult());
    TEST_ASSERT_EQUAL_UINT32(0, pipelineRadio->sendCalls);
    TEST_ASSERT_EQUAL(0, pipelineMqtt->queueSize());
}

// SPEC 3.4: a correctly addressed packet from any transport but BLE is refused before any rewrite. UNKNOWN is
// the default argument, so a caller that does not pass the transport fails closed.
void test_handleToRadio_port300_to_us_from_non_ble_transport_is_dropped(void)
{
    meshtastic_MeshPacket serial = makeClientPacket(KYNOPLAN_GNSS_PORTNUM, LOCAL_NODE);
    pipelineService->handleToRadio(serial, KynoplanToRadioTransport::OTHER);
    assertRefusedUntouched(serial, LOCAL_NODE);

    meshtastic_MeshPacket unspecified = makeClientPacket(KYNOPLAN_GNSS_PORTNUM, LOCAL_NODE);
    pipelineService->handleToRadio(unspecified);
    assertRefusedUntouched(unspecified, LOCAL_NODE);
}

/// A PhoneAPI over a permanently connected fake transport of the given kind.
class KynoPlanPhoneApiShim : public PhoneAPI
{
  public:
    explicit KynoPlanPhoneApiShim(bool ble) { api_type = ble ? TYPE_BLE : TYPE_SERIAL; }

  protected:
    bool checkIsConnected() override { return true; }
};

static bool writeToRadio(PhoneAPI &api, const meshtastic_MeshPacket &p)
{
    meshtastic_ToRadio tr = meshtastic_ToRadio_init_zero;
    tr.which_payload_variant = meshtastic_ToRadio_packet_tag;
    tr.packet = p;
    uint8_t buf[meshtastic_ToRadio_size];
    const size_t len = pb_encode_to_bytes(buf, sizeof(buf), &meshtastic_ToRadio_msg, &tr);
    TEST_ASSERT_GREATER_THAN(0, len);
    return api.handleToRadio(buf, len);
}

// The transport is plumbed from the real PhoneAPI entry point: a BLE PhoneAPI's packet reaches the module, the
// same bytes written over a serial PhoneAPI are refused with NOT_AUTHORIZED.
void test_phoneapi_passes_transport_ble_accepted_serial_refused(void)
{
    const meshtastic_MeshPacket p = makeClientPacket(KYNOPLAN_GNSS_PORTNUM, LOCAL_NODE);

    KynoPlanPhoneApiShim serial(false);
    writeToRadio(serial, p);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, probe->calls, "a serial PhoneAPI must not reach the module");
    TEST_ASSERT_EQUAL_INT32(meshtastic_Routing_Error_NOT_AUTHORIZED, takeQueueStatusResult());

    KynoPlanPhoneApiShim ble(true);
    writeToRadio(ble, p);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, probe->calls, "the BLE PhoneAPI is the one accepted transport");
    TEST_ASSERT_EQUAL(RX_SRC_USER, probe->lastSrc);
    TEST_ASSERT_EQUAL_INT32(ERRNO_OK, takeQueueStatusResult());
    TEST_ASSERT_EQUAL_UINT32(0, pipelineRadio->sendCalls);
    TEST_ASSERT_EQUAL(0, pipelineMqtt->queueSize());
}

// Known limitation, pinned: a client-encrypted packet's port is unknowable, so the guard leaves it alone.
void test_handleToRadio_client_encrypted_packet_is_not_inspected(void)
{
    meshtastic_MeshPacket p = makeClientPacket(KYNOPLAN_GNSS_PORTNUM, REMOTE_NODE);
    p = channelEncode(p);
    p.id = 0x7B000001;
    pipelineService->handleToRadio(p);
    TEST_ASSERT_EQUAL_UINT32(1, pipelineRadio->sendCalls);
}

// Device-originated sends: a KynoPlan module must use sendToPhone only. Any port-300 packet that reaches
// Router::send (via sendToMesh/sendLocal or a direct call) is dropped before LoRa and MQTT.
void test_router_send_drops_device_originated_port300(void)
{
    const NodeNum dests[] = {NODENUM_BROADCAST, REMOTE_NODE};
    for (NodeNum to : dests) {
        meshtastic_MeshPacket *viaService = pipelineRouter->allocForSending();
        TEST_ASSERT_NOT_NULL(viaService);
        viaService->to = to;
        viaService->want_ack = !isBroadcast(to);
        viaService->decoded.portnum = (meshtastic_PortNum)KYNOPLAN_GNSS_PORTNUM;
        pipelineService->sendToMesh(viaService, RX_SRC_LOCAL);

        meshtastic_MeshPacket *direct = pipelineRouter->allocForSending();
        TEST_ASSERT_NOT_NULL(direct);
        direct->to = to;
        direct->decoded.portnum = (meshtastic_PortNum)KYNOPLAN_GNSS_PORTNUM;
        TEST_ASSERT_EQUAL_INT32(meshtastic_Routing_Error_NOT_AUTHORIZED, pipelineRouter->send(direct));
    }
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, pipelineRadio->sendCalls, "must never reach LoRa");
    TEST_ASSERT_EQUAL_MESSAGE(0, pipelineMqtt->queueSize(), "must never reach MQTT");
    TEST_ASSERT_EQUAL_MESSAGE(0, pipelineRouter->pendingCount(), "a refused want_ack send leaves no retransmission");

    // Control: the same device-originated send on the adjacent port does go out and up.
    meshtastic_MeshPacket *control = pipelineRouter->allocForSending();
    TEST_ASSERT_NOT_NULL(control);
    control->to = REMOTE_NODE;
    control->decoded.portnum = (meshtastic_PortNum)CONTROL_PORT;
    TEST_ASSERT_EQUAL_INT32(ERRNO_OK, pipelineRouter->send(control));
    TEST_ASSERT_EQUAL_UINT32(1, pipelineRadio->sendCalls);
    TEST_ASSERT_EQUAL(1, pipelineMqtt->queueSize());
}

static constexpr NodeNum THIRD_NODE = 0x0E0E0E0E;

/// A frame from another node as heard off the air: hop_limit > 0 so it is relay-eligible, OK to MQTT, and
/// still on its first hop (hop_start == hop_limit) so a duplicate counts as a repeated original transmission.
static meshtastic_MeshPacket makeMeshFrame(uint32_t port, NodeNum to, PacketId id, bool encrypt = true)
{
    meshtastic_MeshPacket p = makeDecoded(REMOTE_NODE, to, (meshtastic_PortNum)port, SMALL_PAYLOAD);
    p.id = id;
    p.hop_limit = 3;
    p.hop_start = 3;
    p.want_ack = !isBroadcast(to);
    p.decoded.has_bitfield = true;
    p.decoded.bitfield = BITFIELD_OK_TO_MQTT_MASK;
    p.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    return encrypt ? channelEncode(p) : p;
}

static meshtastic_MeshPacket asMqttDownlink(meshtastic_MeshPacket p)
{
    p.via_mqtt = true;
    p.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT;
    return p;
}

/// Nothing at all happened for this frame: no LoRa send, no MQTT entry, no module call, no ACK, nothing for the
/// phone, no retransmission state and no PacketHistory entry (the gate runs before routing state is touched).
static void assertIngressDropped(const meshtastic_MeshPacket &p, const char *what)
{
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, pipelineRadio->sendCalls, what);
    TEST_ASSERT_EQUAL_MESSAGE(0, pipelineMqtt->queueSize(), what);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, probe->calls, what);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, pipelineRouting->ackCalls, what);
    TEST_ASSERT_EQUAL_MESSAGE(0, drainPhoneQueue(), what);
    TEST_ASSERT_EQUAL_MESSAGE(0, pipelineRouter->pendingCount(), what);
    TEST_ASSERT_FALSE_MESSAGE(pipelineRouter->historyContains(&p), what);
}

// Control: the same frames on the adjacent port are relayed over LoRa and uplinked to MQTT, so the zeros the
// port-300 cases assert are not an artefact of a fixture that never relays or publishes.
void test_control_adjacent_port_mesh_ingress_is_relayed_and_uplinked(void)
{
    const NodeNum dests[] = {NODENUM_BROADCAST, THIRD_NODE};
    PacketId id = 0x7C000001;
    for (NodeNum to : dests) {
        pipelineRadio->reset();
        pipelineMqtt->clearQueue();
        runPipelineIngress(makeMeshFrame(CONTROL_PORT, to, id++));
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, pipelineRadio->sendCalls, "the control frame is relayed");
        TEST_ASSERT_EQUAL_MESSAGE(1, pipelineMqtt->queueSize(), "the control frame is uplinked");
    }
}

// LoRa ingress from another node - to us, broadcast and to a third node, hop_limit > 0, OK to MQTT, under the
// relaying rebroadcast modes (ALL_SKIP_DECODING included: the gate decodes regardless) - is dropped outright.
void test_lora_ingress_port300_is_dropped_before_any_routing(void)
{
    const meshtastic_Config_DeviceConfig_RebroadcastMode modes[] = {
        meshtastic_Config_DeviceConfig_RebroadcastMode_ALL, meshtastic_Config_DeviceConfig_RebroadcastMode_ALL_SKIP_DECODING};
    const NodeNum dests[] = {LOCAL_NODE, NODENUM_BROADCAST, THIRD_NODE};
    PacketId id = 0x7B000010;
    for (auto mode : modes) {
        config.device.rebroadcast_mode = mode;
        for (NodeNum to : dests) {
            const meshtastic_MeshPacket p = makeMeshFrame(KYNOPLAN_GNSS_PORTNUM, to, id++);
            runPipelineIngress(p);
            char what[96];
            snprintf(what, sizeof(what), "LoRa port 300 to 0x%08x, mode %s", (unsigned)to, modeName(mode));
            assertIngressDropped(p, what);
        }
    }
}

// MQTT downlink from another node, both as ciphertext and already decoded, takes the same router ingress.
void test_mqtt_ingress_port300_is_dropped_before_any_routing(void)
{
    const NodeNum dests[] = {LOCAL_NODE, NODENUM_BROADCAST, THIRD_NODE};
    PacketId id = 0x7B000040;
    for (bool encrypted : {true, false}) {
        for (NodeNum to : dests) {
            const meshtastic_MeshPacket p = asMqttDownlink(makeMeshFrame(KYNOPLAN_GNSS_PORTNUM, to, id++, encrypted));
            runPipelineIngress(p);
            char what[96];
            snprintf(what, sizeof(what), "MQTT %s port 300 to 0x%08x", encrypted ? "encrypted" : "decoded", (unsigned)to);
            assertIngressDropped(p, what);
        }
    }
}

// The dupe paths in shouldFilterReceived() relay (broadcast) or re-ACK (to us, want_ack) a repeated original
// transmission. Driven directly, as if the gate had admitted the first copy, so this pins reprocessPacket's
// refusal on its own; the control port shows the same calls do relay and ACK.
void test_duplicate_port300_is_never_relayed_or_acked(void)
{
    PacketId id = 0x7B000060;
    for (uint32_t port : {CONTROL_PORT, KYNOPLAN_GNSS_PORTNUM}) {
        const bool control = port == CONTROL_PORT;
        for (NodeNum to : {LOCAL_NODE, NODENUM_BROADCAST}) {
            pipelineRadio->reset();
            pipelineRouting->reset();
            meshtastic_MeshPacket first = makeMeshFrame(port, to, id++);
            pipelineRouter->remember(&first);
            meshtastic_MeshPacket dupe = first;
            TEST_ASSERT_TRUE_MESSAGE(pipelineRouter->filter(&dupe), "a duplicate is always filtered");
            const uint32_t effect = isBroadcast(to) ? pipelineRadio->sendCalls : pipelineRouting->ackCalls;
            char what[96];
            snprintf(what, sizeof(what), "port %u dupe to 0x%08x: %s", (unsigned)port, (unsigned)to,
                     isBroadcast(to) ? "relays" : "ACKs");
            TEST_ASSERT_EQUAL_UINT32_MESSAGE(control ? 1 : 0, effect, what);
        }
    }
}

// A module's own port-300 packet to us or to broadcast is looped back by sendLocal() as RX_SRC_LOCAL, which a
// loopbackOk module (the probe) would see; only client traffic (RX_SRC_USER) may reach modules on this port.
void test_local_loopback_port300_never_reaches_modules(void)
{
    for (NodeNum to : {LOCAL_NODE, NODENUM_BROADCAST}) {
        meshtastic_MeshPacket *p = pipelineRouter->allocForSending();
        TEST_ASSERT_NOT_NULL(p);
        p->to = to;
        p->decoded.portnum = (meshtastic_PortNum)KYNOPLAN_GNSS_PORTNUM;
        p->decoded.has_bitfield = true;
        p->decoded.bitfield = BITFIELD_OK_TO_MQTT_MASK;
        if (pipelineRouter->sendLocal(p, RX_SRC_LOCAL) == ERRNO_SHOULD_RELEASE)
            packetPool.release(p); // the to-us delivery leaves ownership with the caller
    }
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, probe->calls, "a device-originated loopback must not reach modules");
    TEST_ASSERT_EQUAL_UINT32(0, pipelineRadio->sendCalls);
    TEST_ASSERT_EQUAL(0, pipelineMqtt->queueSize());
    TEST_ASSERT_EQUAL(0, drainPhoneQueue());
}

/// Sign a decoded frame as a remote signer would. The engine signs with the XEdDSA key of its last generated keypair,
/// and the NodeDB constructor generates one, so the caller makes the signer's identity after the harness setUp.
static void signWithLastGeneratedKey(meshtastic_MeshPacket &p)
{
    TEST_ASSERT_TRUE(crypto->xeddsa_sign(p.from, p.id, p.to, &p.decoded, p.decoded.xeddsa_signature.bytes));
    p.decoded.xeddsa_signature.size = XEDDSA_SIGNATURE_SIZE;
}

// A verified XEdDSA signature makes checkXeddsaReceivePolicy() write NodeDB: it sets the sender's signer bit and,
// for a sender known only in the warm tier, re-admits it to the hot store. A port-300 frame must be refused before
// that, so ingress leaves no NodeDB trace. Two ingress shapes reach the signer check separately: an already-decoded
// frame (SimRadio, or a decoded MQTT downlink) in passesRoutingAuthGate(), and a channel-encrypted frame after the
// channel decrypt in perhapsDecode(). The control port proves the fixture's signature does verify and does write
// NodeDB, so the port-300 zeros are not an artefact of a signature that never verified.

/// A hot node holding the key, signer bit clear: only a port-301 frame may set the bit.
static void assertSignedIngressNeverMarksSigner(bool encrypted, PacketId id)
{
    for (uint32_t port : {KYNOPLAN_GNSS_PORTNUM, CONTROL_PORT}) {
        const bool control = port == CONTROL_PORT;
        pipelineHarnessTearDown();
        pipelineHarnessSetUp();
        const RelayIdentity hot = makeIdentity(REMOTE_NODE);
        mockNodeDB->addNode(REMOTE_NODE);
        mockNodeDB->setPublicKey(REMOTE_NODE, hot.pub);
        meshtastic_MeshPacket p = makeMeshFrame(port, NODENUM_BROADCAST, id++, /*encrypt=*/false);
        signWithLastGeneratedKey(p);
        runPipelineIngress(encrypted ? channelEncode(p) : p);
        const meshtastic_NodeInfoLite *n = mockNodeDB->getMeshNode(REMOTE_NODE);
        TEST_ASSERT_NOT_NULL(n);
        TEST_ASSERT_EQUAL_MESSAGE(control, nodeInfoLiteHasXeddsaSigned(n),
                                  control ? "control: a verified signature marks the signer"
                                          : "a port-300 frame must not mark its sender a signer");
    }
}

#if WARM_NODE_COUNT > 0
/// A sender whose key is known only in the warm tier: a verified signature would re-admit it to the hot store
/// (getOrCreateMeshNode), so a port-300 frame must leave the hot store as it was.
static void assertSignedIngressNeverReadmitsWarmNode(bool encrypted, PacketId id)
{
    for (uint32_t port : {KYNOPLAN_GNSS_PORTNUM, CONTROL_PORT}) {
        const bool control = port == CONTROL_PORT;
        pipelineHarnessTearDown();
        pipelineHarnessSetUp();
        const RelayIdentity warm = makeIdentity(THIRD_NODE);
        TEST_ASSERT_TRUE(mockNodeDB->warmStore.absorb(THIRD_NODE, 1, warm.pub));
        const size_t before = mockNodeDB->getNumMeshNodes();
        meshtastic_MeshPacket p = makeDecoded(THIRD_NODE, NODENUM_BROADCAST, (meshtastic_PortNum)port, SMALL_PAYLOAD);
        p.id = id++;
        p.hop_limit = 3;
        p.hop_start = 3;
        p.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
        signWithLastGeneratedKey(p);
        runPipelineIngress(encrypted ? channelEncode(p) : p);
        const meshtastic_NodeInfoLite *n = mockNodeDB->getMeshNode(THIRD_NODE);
        if (control) {
            TEST_ASSERT_NOT_NULL_MESSAGE(n, "control: a verified warm signer is re-admitted");
            TEST_ASSERT_TRUE(nodeInfoLiteHasXeddsaSigned(n));
        } else {
            TEST_ASSERT_NULL_MESSAGE(n, "a port-300 frame must not re-admit its warm-tier sender");
            TEST_ASSERT_EQUAL(before, mockNodeDB->getNumMeshNodes());
        }
    }
}
#endif

void test_signed_decoded_port300_ingress_never_marks_signer(void)
{
    assertSignedIngressNeverMarksSigner(/*encrypted=*/false, 0x7B000080);
}

void test_signed_channel_encrypted_port300_ingress_never_marks_signer(void)
{
    assertSignedIngressNeverMarksSigner(/*encrypted=*/true, 0x7B0000B0);
}

#if WARM_NODE_COUNT > 0
void test_signed_decoded_port300_ingress_never_readmits_warm_node(void)
{
    assertSignedIngressNeverReadmitsWarmNode(/*encrypted=*/false, 0x7B000090);
}

void test_signed_channel_encrypted_port300_ingress_never_readmits_warm_node(void)
{
    assertSignedIngressNeverReadmitsWarmNode(/*encrypted=*/true, 0x7B0000C0);
}
#endif

// The admin-key fallback in perhapsDecode() commits the sender's key to NodeDB as soon as a PKI DM decrypts. On
// port 300 the packet is dropped anyway, so it must be refused before that commit; the control port shows the
// fixture does reach the fallback and commit the key.
void test_pki_admin_key_port300_does_not_commit_sender_key(void)
{
    PacketId id = 0x7B0000A0;
    for (uint32_t port : {KYNOPLAN_GNSS_PORTNUM, CONTROL_PORT}) {
        const bool control = port == CONTROL_PORT;
        pipelineHarnessTearDown();
        pipelineHarnessSetUp();
        const RelayIdentity us = installOurIdentity();
        const RelayIdentity admin = makeIdentity(ADMIN_NODE);
        config.security.admin_key[0].size = 32;
        memcpy(config.security.admin_key[0].bytes, admin.pub, 32);
        config.security.admin_key_count = 1;
        useDHKey(us.priv);
        TEST_ASSERT_NULL(mockNodeDB->getMeshNode(ADMIN_NODE));
        runPipelineIngress(makePkiUnicastBetween(admin, us, (meshtastic_PortNum)port, id++));
        const meshtastic_NodeInfoLite *n = mockNodeDB->getMeshNode(ADMIN_NODE);
        if (control) {
            TEST_ASSERT_NOT_NULL_MESSAGE(n, "control: the admin-key fallback creates the sender");
            TEST_ASSERT_EQUAL_MESSAGE(32, n->public_key.size, "control: the admin-key fallback commits the key");
        } else {
            TEST_ASSERT_TRUE_MESSAGE(n == nullptr || n->public_key.size == 0,
                                     "a port-300 PKI DM must not commit its sender's key");
            TEST_ASSERT_EQUAL(0, drainPhoneQueue());
        }
    }
}

// Fail closed at link time: each reference fails to link if the definition beside its guard is removed.
void test_guard_link_markers_are_installed(void)
{
    TEST_ASSERT_EQUAL_UINT32(1, kynoplanLocalOnlyGuardInstalled);
    TEST_ASSERT_EQUAL_UINT32(1, kynoplanIngressGuardInstalled);
    TEST_ASSERT_EQUAL_UINT32(1, kynoplanDuplicateGuardInstalled);
}
#endif // KYNOPLAN_PIPELINE_TESTS

#else // XEdDSA or PKI excluded: the ingress harness needs both, so only the predicate cases run

void setUp(void) {}
void tearDown(void) {}

#endif

void setup()
{
#if defined(KYNOPLAN_HARNESS)
    pipelineHarnessCreate();
    probe = new KynoPlanPortProbe();
#else
    initializeTestEnvironment();
#endif
    UNITY_BEGIN();
    RUN_TEST(test_predicate_port300_to_us_is_allowed);
    RUN_TEST(test_predicate_port300_broadcast_is_refused);
    RUN_TEST(test_predicate_port300_unicast_to_other_node_is_refused);
    RUN_TEST(test_predicate_unknown_own_node_refuses_to_zero);
    RUN_TEST(test_predicate_other_ports_are_not_kynoplan);
    RUN_TEST(test_predicate_undecoded_packets_are_not_kynoplan);
    RUN_TEST(test_predicate_ignores_from_hop_limit_and_want_ack);
    RUN_TEST(test_predicate_client_packet_requires_ble_transport);
#if defined(KYNOPLAN_HARNESS)
    RUN_TEST(test_control_adjacent_port_reaches_radio_and_mqtt);
#endif
#if defined(KYNOPLAN_PIPELINE_TESTS)
    RUN_TEST(test_handleToRadio_port300_broadcast_is_dropped);
    RUN_TEST(test_handleToRadio_port300_broadcast_no_lora_is_dropped);
    RUN_TEST(test_handleToRadio_port300_unicast_to_other_node_is_dropped);
    RUN_TEST(test_handleToRadio_port300_dropped_in_transparent_mode);
    RUN_TEST(test_handleToRadio_port300_to_us_is_delivered_locally_only);
    RUN_TEST(test_handleToRadio_port300_to_us_from_non_ble_transport_is_dropped);
    RUN_TEST(test_phoneapi_passes_transport_ble_accepted_serial_refused);
    RUN_TEST(test_handleToRadio_client_encrypted_packet_is_not_inspected);
    RUN_TEST(test_router_send_drops_device_originated_port300);
    RUN_TEST(test_control_adjacent_port_mesh_ingress_is_relayed_and_uplinked);
    RUN_TEST(test_lora_ingress_port300_is_dropped_before_any_routing);
    RUN_TEST(test_mqtt_ingress_port300_is_dropped_before_any_routing);
    RUN_TEST(test_signed_decoded_port300_ingress_never_marks_signer);
    RUN_TEST(test_signed_channel_encrypted_port300_ingress_never_marks_signer);
#if WARM_NODE_COUNT > 0
    RUN_TEST(test_signed_decoded_port300_ingress_never_readmits_warm_node);
    RUN_TEST(test_signed_channel_encrypted_port300_ingress_never_readmits_warm_node);
#endif
    RUN_TEST(test_pki_admin_key_port300_does_not_commit_sender_key);
    RUN_TEST(test_duplicate_port300_is_never_relayed_or_acked);
    RUN_TEST(test_local_loopback_port300_never_reaches_modules);
    RUN_TEST(test_guard_link_markers_are_installed);
#endif
#if defined(KYNOPLAN_HARNESS)
    const int result = UNITY_END();
    pipelineHarnessDestroy();
    exit(result);
#else
    exit(UNITY_END());
#endif
}

void loop() {}
