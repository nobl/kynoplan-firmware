// Unit tests for kynoplan::EnrollmentStore in src/modules/optional/KynoPlanGnss/EnrollmentStore.cpp - the persistent
// KynoPlan enrollment state: device identity key pair, four client slots and the enrollment failure counter, kept in
// one CRC-protected file (/prefs/kynoplan_gnss.bin) written through SafeFile.
//
// Contract pinned here (SPEC sections 6.1, 6.2, 6.5, 7.4):
//  - every mutation is persisted before success is returned, and on a failed write the in-memory state is exactly what
//    it was before the call (no half state: no slot added, none revoked, key unchanged), with ERROR_STORAGE returned;
//  - replace_all and revoke_all_others are one write, so a lost phone is never left half-revoked;
//  - a missing file loads as an empty, usable store (MISSING). A truncated, over-long, bit-flipped or wrong-magic file is
//    CORRUPT, a failed read is READ_ERROR and a newer format is UNSUPPORTED_VERSION; all three leave the store failed
//    closed: empty, every write refused with ERROR_STORAGE, the lockout reported as the 24 h cap, available() false, until
//    a later good load() (the retry for READ_ERROR) or wipe(). A bad read must never let the next write mint a new
//    identity over the real one or drop a persisted lockout;
//  - the failure counter and lockout survive a reboot, double from 10 min at the 3rd failure to the 24 h cap, count down
//    with uptime only, are written at most every 10 min (the first write after boot after 1 min, so frequent reboots
//    still count down) and at expiry, and a success (or completed enrollment) resets them; state a failed write left
//    unsaved (even a sub-threshold failure count) is retried from tick() with backoff, never on every tick;
//  - FsStorage reads the file as MISSING only on positive evidence (readEnrollmentFile): a stat error that LittleFS
//    exists() reports as "absent", or a file that opens although exists() said no, is never a fresh store;
//  - the identity is set once and only a wipe (or factory reset) removes it;
//  - EnrollmentStore::onFactoryReset() (called from NodeDB::factoryReset()) deletes the file, empties the registered
//    store's RAM and latches every store read-only until reboot, so nothing re-persists the identity in the window before
//    the reboot;
//  - the file is not reachable by name through XModem or admin delete_file_request (isProtectedPath), including any
//    spelling with a ".." segment.
//
// Regressions guarded: a slot that appears in RAM but not on flash after a failed save; replace_all that revokes others
// before the new key is safe; a rotated key that moves slot or loses its label; a collision check skipped on rotate; a
// lockout that restarts from full after every reboot or never expires (including on a device that reboots more often
// than every 10 min); a failure counter that a failed write or a reboot clears; a failed write never retried, or
// retried on every tick; a filesystem stat error read as a missing file; a CRC that is not checked (or covers too
// little); a truncated file accepted; a transient read error or a downgrade that regenerates the identity and clears
// the lockout; a factory reset whose in-RAM copy writes the file back, or a NodeDB::factoryReset() that no longer calls
// the hook (pinned through the real NodeDB under KYNOPLAN_GNSS_STREAM); the identity silently regenerated while one
// exists; the file surviving rmDir("/prefs"); the identity file deletable over the admin API.
#include "Arduino.h" // declares setup()/loop() with the linkage the framework's main() calls
#include "FSCommon.h"
#include "TestUtil.h"
#include "modules/optional/KynoPlanGnss/EnrollmentStore.h"
#include "xmodem.h"
#if defined(KYNOPLAN_GNSS_STREAM)
#include "mesh/Channels.h"
#include "mesh/NodeDB.h"
#include "modules/AdminModule.h"
#include "support/AdminModuleTestShim.h"
#endif
#include <ErriezCRC32.h>
#include <cstring>
#include <stdint.h>
#include <unity.h>
#include <vector>

using namespace kynoplan;

namespace
{

constexpr size_t FILE_SIZE = 493;

class MemStorage : public EnrollmentStorage
{
  public:
    std::vector<uint8_t> data;
    bool exists = false;
    bool failWrite = false;
    bool failRemove = false;
    bool failRead = false;
    int writes = 0;
    int attempts = 0; // every write call, failed or not

    ReadStatus read(uint8_t *buf, size_t cap, size_t &n) override
    {
        n = 0;
        if (!exists)
            return ReadStatus::MISSING;
        if (failRead)
            return ReadStatus::ERROR;
        n = data.size() < cap ? data.size() : cap;
        memcpy(buf, data.data(), n);
        return ReadStatus::OK;
    }
    bool write(const uint8_t *buf, size_t len) override
    {
        attempts++;
        if (failWrite)
            return false; // like SafeFile: the previous file is untouched
        data.assign(buf, buf + len);
        exists = true;
        writes++;
        return true;
    }
    bool remove() override
    {
        if (failRemove)
            return false;
        data.clear();
        exists = false;
        return true;
    }
};

MemStorage mem;

void fillKey(uint8_t *k, size_t len, uint8_t seed)
{
    k[0] = 0x04;
    for (size_t i = 1; i < len; i++)
        k[i] = static_cast<uint8_t>(seed + i);
}

EnrollmentSlot makeSlot(uint8_t seed, const char *label = "phone")
{
    EnrollmentSlot s;
    memset(&s, 0, sizeof(s));
    fillKey(s.clientPublicKey, ENROLL_PUBKEY_LEN, seed);
    for (size_t i = 0; i < ENROLL_KEY_ID_LEN; i++)
        s.keyId[i] = static_cast<uint8_t>(seed * 3 + i);
    s.labelLen = static_cast<uint8_t>(strlen(label));
    memcpy(s.label, label, s.labelLen);
    s.enrolledUnixS = 1700000000u + seed;
    return s;
}

EnrollmentSlot idSlot(uint8_t seed) // for find()/revoke() arguments
{
    return makeSlot(seed);
}

void setIdentityOn(EnrollmentStore &st, uint8_t seed = 0x40)
{
    uint8_t priv[ENROLL_PRIVKEY_LEN], pub[ENROLL_PUBKEY_LEN];
    for (size_t i = 0; i < sizeof(priv); i++)
        priv[i] = static_cast<uint8_t>(seed ^ i);
    fillKey(pub, sizeof(pub), seed);
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.setIdentity(priv, pub));
}

// A store loaded from mem, as the module does at boot.
void reload(EnrollmentStore &st, uint32_t nowS = 0)
{
    st.load(nowS);
}

void fixCrc(std::vector<uint8_t> &img)
{
    uint32_t crc = crc32Buffer(img.data(), img.size() - 4);
    memcpy(img.data() + img.size() - 4, &crc, 4);
}

} // namespace

void setUp(void)
{
    mem = MemStorage();
}

#if defined(KYNOPLAN_GNSS_STREAM) && defined(FSCom)
static void factoryResetFixtureDown();
#endif

void tearDown(void)
{
#if defined(KYNOPLAN_GNSS_STREAM) && defined(FSCom)
    factoryResetFixtureDown(); // also after a failed assertion
#endif
    // The factory-reset latch is process-wide (it lasts until reboot on a device); later cases need a fresh one.
    EnrollmentStore::setFactoryResetTarget(nullptr);
    EnrollmentStore::clearFactoryResetLatchForTest();
}

void test_missing_file_loads_empty_and_reports_missing(void)
{
    EnrollmentStore st(mem);
    TEST_ASSERT_EQUAL(LoadStatus::MISSING, st.load(0));
    TEST_ASSERT_FALSE(st.hasIdentity());
    TEST_ASSERT_EQUAL(0, st.slotsUsed());
    TEST_ASSERT_EQUAL(0, st.failureCount());
    TEST_ASSERT_EQUAL(0, mem.writes); // loading never writes
}

void test_roundtrip_identity_slots_and_counter(void)
{
    EnrollmentStore a(mem);
    a.load(0);
    setIdentityOn(a);
    TEST_ASSERT_EQUAL(EnrollResult::OK, a.addSlot(makeSlot(1, "alice"), false));
    TEST_ASSERT_EQUAL(EnrollResult::OK, a.addSlot(makeSlot(2, "0123456789abcdef"), false));
    TEST_ASSERT_EQUAL(EnrollResult::OK, a.recordFailure(100));
    TEST_ASSERT_EQUAL(FILE_SIZE, mem.data.size());

    EnrollmentStore b(mem);
    TEST_ASSERT_EQUAL(LoadStatus::OK, b.load(500));
    TEST_ASSERT_TRUE(b.hasIdentity());
    uint8_t priv[ENROLL_PRIVKEY_LEN];
    TEST_ASSERT_TRUE(b.copyIdentityPrivate(priv));
    for (size_t i = 0; i < sizeof(priv); i++)
        TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(0x40 ^ i), priv[i]);
    uint8_t pub[ENROLL_PUBKEY_LEN];
    fillKey(pub, sizeof(pub), 0x40);
    TEST_ASSERT_EQUAL_MEMORY(pub, b.identityPublic(), sizeof(pub));
    TEST_ASSERT_EQUAL(2, b.slotsUsed());
    EnrollmentSlot want = makeSlot(2, "0123456789abcdef");
    const EnrollmentSlot *got = b.find(want.keyId);
    TEST_ASSERT_NOT_NULL(got);
    TEST_ASSERT_EQUAL_MEMORY(want.clientPublicKey, got->clientPublicKey, ENROLL_PUBKEY_LEN);
    TEST_ASSERT_EQUAL(16, got->labelLen);
    TEST_ASSERT_EQUAL_MEMORY("0123456789abcdef", got->label, 16);
    TEST_ASSERT_EQUAL(want.enrolledUnixS, got->enrolledUnixS);
    TEST_ASSERT_EQUAL(1, b.failureCount());
}

void test_identity_set_once_and_private_key_hidden_without_identity(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    uint8_t priv[ENROLL_PRIVKEY_LEN] = {1};
    TEST_ASSERT_FALSE(st.copyIdentityPrivate(priv));
    setIdentityOn(st, 0x40);
    uint8_t other[ENROLL_PRIVKEY_LEN] = {9};
    uint8_t otherPub[ENROLL_PUBKEY_LEN];
    fillKey(otherPub, sizeof(otherPub), 0x50);
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_INVALID, st.setIdentity(other, otherPub));
    uint8_t pub[ENROLL_PUBKEY_LEN];
    fillKey(pub, sizeof(pub), 0x40);
    TEST_ASSERT_EQUAL_MEMORY(pub, st.identityPublic(), sizeof(pub));
}

void test_every_flipped_byte_is_corrupt_and_loads_empty(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    setIdentityOn(st);
    st.addSlot(makeSlot(1), false);
    const std::vector<uint8_t> good = mem.data;
    TEST_ASSERT_EQUAL(FILE_SIZE, good.size());
    for (size_t i = 0; i < good.size(); i++) {
        mem.data = good;
        mem.data[i] ^= 0x01;
        EnrollmentStore b(mem);
        TEST_ASSERT_EQUAL_MESSAGE(LoadStatus::CORRUPT, b.load(0), "flipped byte accepted");
        TEST_ASSERT_FALSE(b.hasIdentity());
        TEST_ASSERT_EQUAL(0, b.slotsUsed());
        TEST_ASSERT_EQUAL(LoadStatus::CORRUPT, b.lastLoadStatus());
        TEST_ASSERT_FALSE(b.available());
    }
}

void test_truncated_and_overlong_files_are_corrupt(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    setIdentityOn(st);
    st.addSlot(makeSlot(1), false);
    const std::vector<uint8_t> good = mem.data;
    for (size_t len = 0; len < good.size(); len++) {
        mem.data.assign(good.begin(), good.begin() + len);
        EnrollmentStore b(mem);
        TEST_ASSERT_EQUAL_MESSAGE(LoadStatus::CORRUPT, b.load(0), "truncated file accepted");
        TEST_ASSERT_EQUAL(0, b.slotsUsed());
    }
    mem.data = good;
    mem.data.push_back(0); // trailing byte, even with a matching prefix
    EnrollmentStore b(mem);
    TEST_ASSERT_EQUAL(LoadStatus::CORRUPT, b.load(0));
}

void test_wrong_magic_is_corrupt_and_newer_version_is_unsupported_even_with_valid_crc(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    setIdentityOn(st);
    const std::vector<uint8_t> good = mem.data;

    mem.data = good;
    mem.data[0] ^= 0xFF; // magic
    fixCrc(mem.data);
    EnrollmentStore a(mem);
    TEST_ASSERT_EQUAL(LoadStatus::CORRUPT, a.load(0));

    mem.data = good;
    mem.data[4] = EnrollmentStore::VERSION + 1; // version byte follows the magic
    fixCrc(mem.data);
    EnrollmentStore b(mem);
    TEST_ASSERT_EQUAL(LoadStatus::UNSUPPORTED_VERSION, b.load(0));
    TEST_ASSERT_FALSE(b.hasIdentity());

    // A newer format may be longer; the version is judged before the length.
    mem.data = good;
    mem.data[4] = EnrollmentStore::VERSION + 1;
    mem.data.resize(600, 0x5A);
    EnrollmentStore c(mem);
    TEST_ASSERT_EQUAL(LoadStatus::UNSUPPORTED_VERSION, c.load(0));

    mem.data = good;
    mem.data[4] = 0; // no version 0 was ever written: damage, not a newer format
    fixCrc(mem.data);
    EnrollmentStore d(mem);
    TEST_ASSERT_EQUAL(LoadStatus::CORRUPT, d.load(0));
}

// Every mutator and tick() on a failed-closed store: nothing may reach storage and the lockout must read as capped.
static void assertFailedClosed(EnrollmentStore &st, const std::vector<uint8_t> &fileBefore)
{
    const int writes = mem.writes;
    TEST_ASSERT_FALSE(st.available());
    TEST_ASSERT_FALSE(st.hasIdentity());
    TEST_ASSERT_EQUAL(ENROLL_LOCKOUT_MAX_S, st.lockoutRemainingS(0));
    TEST_ASSERT_EQUAL(ENROLL_LOCKOUT_MAX_S, st.lockoutRemainingS(1000000));
    uint8_t priv[ENROLL_PRIVKEY_LEN] = {7}, pub[ENROLL_PUBKEY_LEN];
    fillKey(pub, sizeof(pub), 0x60);
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.setIdentity(priv, pub));
    TEST_ASSERT_FALSE(st.hasIdentity());
    EnrollmentSlot one = makeSlot(1);
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.addSlot(one, false));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.addSlot(one, true));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.revoke(one.keyId));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.revokeAllOthers(one.keyId));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.rotate(one.keyId, pub, one.keyId));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.recordFailure(10));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.recordSuccess());
    for (uint32_t t = 0; t <= 2 * ENROLL_LOCKOUT_MAX_S; t += 300)
        st.tick(t);
    TEST_ASSERT_EQUAL(0, st.slotsUsed());
    TEST_ASSERT_EQUAL(ENROLL_LOCKOUT_MAX_S, st.lockoutRemainingS(2 * ENROLL_LOCKOUT_MAX_S));
    TEST_ASSERT_EQUAL(writes, mem.writes);
    TEST_ASSERT_TRUE(fileBefore == mem.data); // the bad file is kept for diagnosis, never overwritten
}

void test_corrupt_read_error_and_newer_version_fail_closed(void)
{
    // A real file with an identity and a running lockout - what a bad load must not let a write destroy.
    {
        EnrollmentStore st(mem);
        st.load(0);
        setIdentityOn(st);
        for (int i = 0; i < 3; i++)
            st.recordFailure(0);
    }
    const std::vector<uint8_t> good = mem.data;

    mem.data = good;
    mem.data[100] ^= 0x01;
    const std::vector<uint8_t> flipped = mem.data;
    EnrollmentStore corrupt(mem);
    TEST_ASSERT_EQUAL(LoadStatus::CORRUPT, corrupt.load(0));
    assertFailedClosed(corrupt, flipped);
    // CORRUPT is final: reloading the same bytes does not turn it into a usable store.
    TEST_ASSERT_EQUAL(LoadStatus::CORRUPT, corrupt.load(0));
    TEST_ASSERT_FALSE(corrupt.available());

    mem.data = good;
    mem.failRead = true;
    EnrollmentStore readErr(mem);
    TEST_ASSERT_EQUAL(LoadStatus::READ_ERROR, readErr.load(0));
    assertFailedClosed(readErr, good);
    mem.failRead = false;

    mem.data = good;
    mem.data[4] = EnrollmentStore::VERSION + 1;
    fixCrc(mem.data);
    const std::vector<uint8_t> newer = mem.data;
    EnrollmentStore unsupported(mem);
    TEST_ASSERT_EQUAL(LoadStatus::UNSUPPORTED_VERSION, unsupported.load(0));
    assertFailedClosed(unsupported, newer);
}

void test_read_error_then_successful_reload_restores_identity_and_lockout(void)
{
    {
        EnrollmentStore st(mem);
        st.load(0);
        setIdentityOn(st);
        st.addSlot(makeSlot(1), false);
        for (int i = 0; i < 3; i++)
            st.recordFailure(0);
    }
    mem.failRead = true;
    EnrollmentStore st(mem);
    TEST_ASSERT_EQUAL(LoadStatus::READ_ERROR, st.load(0));
    TEST_ASSERT_FALSE(st.available());
    mem.failRead = false;
    TEST_ASSERT_EQUAL(LoadStatus::OK, st.load(10)); // the retry
    TEST_ASSERT_TRUE(st.available());
    TEST_ASSERT_TRUE(st.hasIdentity());
    TEST_ASSERT_EQUAL(1, st.slotsUsed());
    TEST_ASSERT_EQUAL(3, st.failureCount());
    TEST_ASSERT_EQUAL(600, st.lockoutRemainingS(10));
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.recordFailure(10)); // writable again
    TEST_ASSERT_EQUAL(1200, st.lockoutRemainingS(10));
}

void test_wipe_lifts_failed_closed_store(void)
{
    mem.exists = true;
    mem.data.assign(10, 0xAA);
    EnrollmentStore st(mem);
    TEST_ASSERT_EQUAL(LoadStatus::CORRUPT, st.load(0));
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.wipe());
    TEST_ASSERT_FALSE(mem.exists);
    TEST_ASSERT_EQUAL(LoadStatus::MISSING, st.lastLoadStatus());
    TEST_ASSERT_TRUE(st.available());
    TEST_ASSERT_EQUAL(0, st.lockoutRemainingS(0));
    setIdentityOn(st);
    EnrollmentStore b(mem);
    TEST_ASSERT_EQUAL(LoadStatus::OK, b.load(0));
    TEST_ASSERT_TRUE(b.hasIdentity());
}

void test_factory_reset_wipes_target_and_latches_every_store_until_reboot(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    setIdentityOn(st);
    st.addSlot(makeSlot(1), false);
    for (int i = 0; i < 3; i++)
        st.recordFailure(0);
    EnrollmentStore::setFactoryResetTarget(&st);
    TEST_ASSERT_TRUE(st.available());

    EnrollmentStore::onFactoryReset();
    TEST_ASSERT_FALSE(mem.exists);
    TEST_ASSERT_FALSE(st.hasIdentity());
    uint8_t priv[ENROLL_PRIVKEY_LEN];
    TEST_ASSERT_FALSE(st.copyIdentityPrivate(priv));
    TEST_ASSERT_EQUAL(0, st.slotsUsed());
    TEST_ASSERT_EQUAL(0, st.failureCount());

    // The 7 s before the reboot: a failure, a tick or a fresh identity must not recreate the file.
    const int writes = mem.writes;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.recordFailure(5));
    st.tick(5);
    st.tick(5 + ENROLL_LOCKOUT_PERSIST_INTERVAL_S);
    uint8_t pub[ENROLL_PUBKEY_LEN];
    fillKey(pub, sizeof(pub), 0x70);
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.setIdentity(priv, pub));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.addSlot(makeSlot(2), false));
    TEST_ASSERT_EQUAL(writes, mem.writes);
    TEST_ASSERT_FALSE(mem.exists);

    // Neither a reload (which finds no file) nor wipe() lifts the latch; another instance is latched too.
    TEST_ASSERT_EQUAL(LoadStatus::MISSING, st.load(6));
    TEST_ASSERT_FALSE(st.available());
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.wipe());
    TEST_ASSERT_FALSE(st.available());
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.setIdentity(priv, pub));
    EnrollmentStore other(mem);
    TEST_ASSERT_EQUAL(LoadStatus::MISSING, other.load(6));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, other.setIdentity(priv, pub));
    TEST_ASSERT_EQUAL(writes, mem.writes);
    TEST_ASSERT_FALSE(mem.exists);
}

void test_factory_reset_without_target_still_latches(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    EnrollmentStore::onFactoryReset();
    TEST_ASSERT_FALSE(st.available());
    uint8_t priv[ENROLL_PRIVKEY_LEN] = {1}, pub[ENROLL_PUBKEY_LEN];
    fillKey(pub, sizeof(pub), 0x71);
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.setIdentity(priv, pub));
    TEST_ASSERT_EQUAL(0, mem.writes);
}

void test_four_slots_then_full(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    for (uint8_t i = 1; i <= 4; i++)
        TEST_ASSERT_EQUAL(EnrollResult::OK, st.addSlot(makeSlot(i), false));
    const int writes = mem.writes;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_SLOTS_FULL, st.addSlot(makeSlot(5), false));
    TEST_ASSERT_EQUAL(4, st.slotsUsed());
    TEST_ASSERT_EQUAL(writes, mem.writes); // a refusal writes nothing
    EnrollmentSlot five = idSlot(5);
    TEST_ASSERT_NULL(st.find(five.keyId));
}

void test_key_id_collision_rejected_without_change(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    st.addSlot(makeSlot(1, "first"), false);
    EnrollmentSlot dup = makeSlot(2, "second");
    memcpy(dup.keyId, makeSlot(1).keyId, ENROLL_KEY_ID_LEN);
    const int writes = mem.writes;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_KEY_ID_COLLISION, st.addSlot(dup, false));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_KEY_ID_COLLISION, st.addSlot(dup, true)); // replace_all does not bypass it
    TEST_ASSERT_EQUAL(1, st.slotsUsed());
    TEST_ASSERT_EQUAL(writes, mem.writes);
    EnrollmentSlot first = makeSlot(1);
    TEST_ASSERT_EQUAL_MEMORY("first", st.find(first.keyId)->label, 5);
}

void test_invalid_slot_arguments_rejected(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    EnrollmentSlot s = makeSlot(1);
    s.clientPublicKey[0] = 0x03;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_INVALID, st.addSlot(s, false));
    s = makeSlot(1);
    s.labelLen = 17;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_INVALID, st.addSlot(s, false));
    TEST_ASSERT_EQUAL(0, st.slotsUsed());
}

void test_replace_all_revokes_others_in_one_write(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    for (uint8_t i = 1; i <= 4; i++)
        st.addSlot(makeSlot(i), false);
    const int writes = mem.writes;
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.addSlot(makeSlot(9, "new phone"), true));
    TEST_ASSERT_EQUAL(writes + 1, mem.writes);
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_EQUAL(1, b.slotsUsed());
    EnrollmentSlot nine = idSlot(9), one = idSlot(1);
    TEST_ASSERT_NOT_NULL(b.find(nine.keyId));
    TEST_ASSERT_NULL(b.find(one.keyId));
}

void test_replace_all_write_failure_keeps_every_old_slot(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    for (uint8_t i = 1; i <= 4; i++)
        st.addSlot(makeSlot(i), false);
    const std::vector<uint8_t> before = mem.data;
    mem.failWrite = true;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.addSlot(makeSlot(9), true));
    TEST_ASSERT_EQUAL(4, st.slotsUsed());
    EnrollmentSlot nine = idSlot(9);
    TEST_ASSERT_NULL(st.find(nine.keyId));
    for (uint8_t i = 1; i <= 4; i++) {
        EnrollmentSlot s = idSlot(i);
        TEST_ASSERT_NOT_NULL(st.find(s.keyId));
    }
    TEST_ASSERT_TRUE(before == mem.data);
}

void test_add_resets_failure_counter_in_same_write(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    st.recordFailure(0);
    st.recordFailure(0);
    st.recordFailure(0);
    TEST_ASSERT_EQUAL(600, st.lockoutRemainingS(0));
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.addSlot(makeSlot(1), false));
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_EQUAL(0, b.failureCount());
    TEST_ASSERT_EQUAL(0, b.lockoutRemainingS(0));
}

void test_revoke_one_and_unknown(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    st.addSlot(makeSlot(1), false);
    st.addSlot(makeSlot(2), false);
    EnrollmentSlot one = idSlot(1), two = idSlot(2), three = idSlot(3);
    const int writes = mem.writes;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_NOT_FOUND, st.revoke(three.keyId));
    TEST_ASSERT_EQUAL(writes, mem.writes);
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.revoke(one.keyId));
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_NULL(b.find(one.keyId));
    TEST_ASSERT_NOT_NULL(b.find(two.keyId));
    // The freed slot is reusable, and the survivor keeps its place.
    TEST_ASSERT_EQUAL(EnrollResult::OK, b.addSlot(makeSlot(3), false));
    TEST_ASSERT_EQUAL(2, b.slotsUsed());
}

void test_revoke_all_others_keeps_only_caller(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    for (uint8_t i = 1; i <= 3; i++)
        st.addSlot(makeSlot(i), false);
    EnrollmentSlot two = idSlot(2), nine = idSlot(9);
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_NOT_FOUND, st.revokeAllOthers(nine.keyId));
    TEST_ASSERT_EQUAL(3, st.slotsUsed()); // an unknown caller revokes nothing
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.revokeAllOthers(two.keyId));
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_EQUAL(1, b.slotsUsed());
    TEST_ASSERT_NOT_NULL(b.find(two.keyId));
}

void test_rotate_keeps_slot_and_label_and_removes_old_key(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    st.addSlot(makeSlot(1, "a"), false);
    st.addSlot(makeSlot(2, "bob"), false);
    EnrollmentSlot two = idSlot(2);
    EnrollmentSlot repl = makeSlot(7);
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.rotate(two.keyId, repl.clientPublicKey, repl.keyId));
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_NULL(b.find(two.keyId));
    const EnrollmentSlot *g = b.find(repl.keyId);
    TEST_ASSERT_NOT_NULL(g);
    TEST_ASSERT_EQUAL_MEMORY(repl.clientPublicKey, g->clientPublicKey, ENROLL_PUBKEY_LEN);
    TEST_ASSERT_EQUAL(3, g->labelLen);
    TEST_ASSERT_EQUAL_MEMORY("bob", g->label, 3);
    TEST_ASSERT_EQUAL(two.enrolledUnixS, g->enrolledUnixS);
    EnrollmentSlot list[ENROLL_SLOT_COUNT];
    TEST_ASSERT_EQUAL(2, b.list(list, ENROLL_SLOT_COUNT));
    TEST_ASSERT_EQUAL_MEMORY(makeSlot(1).keyId, list[0].keyId, ENROLL_KEY_ID_LEN); // slot order unchanged
    TEST_ASSERT_EQUAL_MEMORY(repl.keyId, list[1].keyId, ENROLL_KEY_ID_LEN);
}

void test_rotate_collision_unknown_caller_and_bad_key(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    st.addSlot(makeSlot(1), false);
    st.addSlot(makeSlot(2), false);
    EnrollmentSlot one = idSlot(1), two = idSlot(2), nine = makeSlot(9);
    const int writes = mem.writes;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_KEY_ID_COLLISION, st.rotate(one.keyId, two.clientPublicKey, two.keyId));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_KEY_ID_COLLISION, st.rotate(one.keyId, one.clientPublicKey, one.keyId));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_NOT_FOUND, st.rotate(nine.keyId, nine.clientPublicKey, nine.keyId));
    nine.clientPublicKey[0] = 0x02;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_INVALID, st.rotate(one.keyId, nine.clientPublicKey, nine.keyId));
    TEST_ASSERT_EQUAL(writes, mem.writes);
    TEST_ASSERT_NOT_NULL(st.find(one.keyId));
}

void test_write_failure_rolls_back_every_mutation(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    setIdentityOn(st);
    st.addSlot(makeSlot(1, "keep"), false);
    st.addSlot(makeSlot(2, "other"), false);
    EnrollmentSlot one = idSlot(1), two = idSlot(2), nine = makeSlot(9);
    const std::vector<uint8_t> before = mem.data;
    mem.failWrite = true;

    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.addSlot(nine, false));
    TEST_ASSERT_NULL(st.find(nine.keyId));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.revoke(two.keyId));
    TEST_ASSERT_NOT_NULL(st.find(two.keyId));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.revokeAllOthers(one.keyId));
    TEST_ASSERT_NOT_NULL(st.find(two.keyId));
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.rotate(one.keyId, nine.clientPublicKey, nine.keyId));
    TEST_ASSERT_NOT_NULL(st.find(one.keyId));
    TEST_ASSERT_NULL(st.find(nine.keyId));
    TEST_ASSERT_EQUAL(2, st.slotsUsed());
    TEST_ASSERT_TRUE(before == mem.data);

    mem.failWrite = false; // and the store still works afterwards
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.revoke(two.keyId));
}

void test_identity_write_failure_leaves_no_identity(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    mem.failWrite = true;
    uint8_t priv[ENROLL_PRIVKEY_LEN] = {5}, pub[ENROLL_PUBKEY_LEN];
    fillKey(pub, sizeof(pub), 1);
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.setIdentity(priv, pub));
    TEST_ASSERT_FALSE(st.hasIdentity());
    mem.failWrite = false;
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.setIdentity(priv, pub));
    TEST_ASSERT_TRUE(st.hasIdentity());
}

void test_lockout_schedule_doubles_to_24h_cap(void)
{
    TEST_ASSERT_EQUAL(0, EnrollmentStore::lockoutForFailures(0));
    TEST_ASSERT_EQUAL(0, EnrollmentStore::lockoutForFailures(2));
    TEST_ASSERT_EQUAL(600, EnrollmentStore::lockoutForFailures(3));
    TEST_ASSERT_EQUAL(1200, EnrollmentStore::lockoutForFailures(4));
    TEST_ASSERT_EQUAL(2400, EnrollmentStore::lockoutForFailures(5));
    TEST_ASSERT_EQUAL(76800, EnrollmentStore::lockoutForFailures(10)); // 600 * 2^7, last value below the cap
    TEST_ASSERT_EQUAL(86400, EnrollmentStore::lockoutForFailures(11));
    TEST_ASSERT_EQUAL(86400, EnrollmentStore::lockoutForFailures(255));
}

void test_failures_below_threshold_do_not_lock_but_persist(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    st.recordFailure(10);
    st.recordFailure(20);
    TEST_ASSERT_EQUAL(0, st.lockoutRemainingS(20));
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_EQUAL(2, b.failureCount());
    TEST_ASSERT_EQUAL(0, b.lockoutRemainingS(0));
    b.recordFailure(0);
    TEST_ASSERT_EQUAL(600, b.lockoutRemainingS(0)); // the persisted count carries over: this is the 3rd
}

void test_lockout_counts_down_with_uptime_and_survives_reboot(void)
{
    EnrollmentStore st(mem);
    st.load(1000);
    st.recordFailure(1000);
    st.recordFailure(1000);
    st.recordFailure(1000);
    TEST_ASSERT_EQUAL(600, st.lockoutRemainingS(1000));
    TEST_ASSERT_EQUAL(100, st.lockoutRemainingS(1500));
    TEST_ASSERT_EQUAL(0, st.lockoutRemainingS(1600));
    TEST_ASSERT_EQUAL(0, st.lockoutRemainingS(5000));

    // Reboot immediately: uptime restarts near zero but the remaining lockout and count are kept, not reset to 0.
    EnrollmentStore b(mem);
    b.load(5);
    TEST_ASSERT_EQUAL(3, b.failureCount());
    TEST_ASSERT_EQUAL(600, b.lockoutRemainingS(5));
    TEST_ASSERT_EQUAL(1, b.lockoutRemainingS(604));
    TEST_ASSERT_EQUAL(0, b.lockoutRemainingS(605));
}

void test_fourth_failure_doubles_and_cap_holds_across_reload(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    for (int i = 0; i < 4; i++)
        st.recordFailure(0);
    TEST_ASSERT_EQUAL(1200, st.lockoutRemainingS(0));
    for (int i = 0; i < 20; i++)
        st.recordFailure(0);
    TEST_ASSERT_EQUAL(86400, st.lockoutRemainingS(0));
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_EQUAL(24, b.failureCount());
    TEST_ASSERT_EQUAL(86400, b.lockoutRemainingS(0));
}

void test_success_resets_counter_and_lockout_persistently(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    for (int i = 0; i < 5; i++)
        st.recordFailure(0);
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.recordSuccess());
    TEST_ASSERT_EQUAL(0, st.failureCount());
    TEST_ASSERT_EQUAL(0, st.lockoutRemainingS(0));
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_EQUAL(0, b.failureCount());
    TEST_ASSERT_EQUAL(0, b.lockoutRemainingS(0));
}

// The countdown is flash wear on a 1 Hz tick: one write per 10 min, plus one at expiry.
void test_tick_persists_decrement_at_most_every_10_min_and_at_expiry(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    for (int i = 0; i < 5; i++)
        st.recordFailure(0); // 2400 s
    const int base = mem.writes;
    for (uint32_t t = 1; t < 600; t++)
        st.tick(t);
    TEST_ASSERT_EQUAL(base, mem.writes);
    st.tick(600);
    TEST_ASSERT_EQUAL(base + 1, mem.writes);
    for (uint32_t t = 601; t < 1200; t++)
        st.tick(t);
    TEST_ASSERT_EQUAL(base + 1, mem.writes);
    st.tick(1200);
    TEST_ASSERT_EQUAL(base + 2, mem.writes);

    // A reboot at t=1300 loses less than 10 min of countdown: the file says 1200 s (as of t=1200).
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_EQUAL(1200, b.lockoutRemainingS(0));

    // Expiry is written at once (not at the next 10 min mark), so a later reboot does not re-lock.
    st.tick(2401);
    TEST_ASSERT_EQUAL(base + 3, mem.writes);
    EnrollmentStore c(mem);
    c.load(0);
    TEST_ASSERT_EQUAL(0, c.lockoutRemainingS(0));
    st.tick(3000); // idle: nothing left to persist
    TEST_ASSERT_EQUAL(base + 3, mem.writes);
}

void test_failure_counts_even_when_the_write_fails(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    mem.failWrite = true;
    for (int i = 0; i < 4; i++)
        TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.recordFailure(0));
    TEST_ASSERT_EQUAL(4, st.failureCount());
    TEST_ASSERT_EQUAL(1200, st.lockoutRemainingS(0));
    mem.failWrite = false;
    st.tick(600); // the unsaved state is retried by the next tick once the retry backoff has passed
    TEST_ASSERT_EQUAL(1, mem.writes);
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_EQUAL(4, b.failureCount());
    TEST_ASSERT_EQUAL(600, b.lockoutRemainingS(0));
}

void test_success_write_failure_keeps_counter(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    for (int i = 0; i < 3; i++)
        st.recordFailure(0);
    mem.failWrite = true;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.recordSuccess());
    TEST_ASSERT_EQUAL(3, st.failureCount());
    TEST_ASSERT_EQUAL(600, st.lockoutRemainingS(0));
}

// A failure below the lockout threshold changes no countdown, so only the unsaved mark brings it to flash; without
// it a reboot forgets the failure and an attacker gets the first two guesses back after every power cycle.
void test_sub_threshold_failure_unsaved_by_failed_write_is_retried_by_tick(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    mem.failWrite = true;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.recordFailure(0));
    TEST_ASSERT_EQUAL(1, st.failureCount());
    TEST_ASSERT_EQUAL(0, st.lockoutRemainingS(0));
    mem.failWrite = false;
    for (uint32_t t = 1; t <= ENROLL_PERSIST_RETRY_MIN_S; t++)
        st.tick(t);
    TEST_ASSERT_EQUAL(1, mem.writes);
    EnrollmentStore b(mem);
    TEST_ASSERT_EQUAL(LoadStatus::OK, b.load(0));
    TEST_ASSERT_EQUAL(1, b.failureCount());
    for (uint32_t t = ENROLL_PERSIST_RETRY_MIN_S + 1; t < 3000; t++)
        st.tick(t); // saved: nothing more to write
    TEST_ASSERT_EQUAL(1, mem.writes);
}

// A flash that keeps failing is retried with backoff, not hammered on every 1 Hz tick; that includes the expiry write,
// which is otherwise due at once. Retrying must not stop either, and a later success writes the real state.
void test_failing_writes_are_retried_with_bounded_backoff_including_at_expiry(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    for (int i = 0; i < 3; i++)
        st.recordFailure(0); // 600 s, persisted
    mem.failWrite = true;
    for (uint32_t t = 1; t < 600; t++)
        st.tick(t);
    const int before = mem.attempts;
    for (uint32_t t = 600; t < 3600; t++)
        st.tick(t);
    const int retries = mem.attempts - before;
    // Expiry at 600, then retries 10, 20, 40 ... s apart, capped at 600: 10 attempts in these 3000 s (not 3000).
    TEST_ASSERT_GREATER_OR_EQUAL(5, retries);
    TEST_ASSERT_LESS_OR_EQUAL(12, retries);
    mem.failWrite = false;
    for (uint32_t t = 3600; t <= 3600 + ENROLL_LOCKOUT_PERSIST_INTERVAL_S; t++)
        st.tick(t);
    TEST_ASSERT_EQUAL(4, mem.writes); // 3 failures, then one successful retry
    EnrollmentStore b(mem);
    b.load(0);
    TEST_ASSERT_EQUAL(0, b.lockoutRemainingS(0));
}

// A device that reboots more often than the 10 min write interval (brown-outs, a crash loop) must still count the
// lockout down: the first write after boot comes after ENROLL_LOCKOUT_FIRST_PERSIST_S. Without it every boot restarts
// from the same persisted value and the lockout never ends. Each boot writes once, and the file never claims less time
// than truly remains (here each 100 s boot burns 98 s but only 60 s are credited).
void test_lockout_counts_down_across_boots_shorter_than_persist_interval(void)
{
    {
        EnrollmentStore st(mem);
        st.load(0);
        for (int i = 0; i < 3; i++)
            st.recordFailure(0); // 600 s
    }
    uint32_t expected = 600;
    for (int boot = 1; boot <= 10; boot++) {
        EnrollmentStore st(mem);
        TEST_ASSERT_EQUAL(LoadStatus::OK, st.load(2));
        TEST_ASSERT_EQUAL(expected, st.lockoutRemainingS(2));
        const int writes = mem.writes;
        for (uint32_t t = 3; t < 100; t++)
            st.tick(t);
        TEST_ASSERT_EQUAL_MESSAGE(writes + 1, mem.writes, "one countdown write per short boot");
        expected -= ENROLL_LOCKOUT_FIRST_PERSIST_S;
    }
    EnrollmentStore after(mem);
    after.load(2);
    TEST_ASSERT_EQUAL(0, after.lockoutRemainingS(2));
}

// Stands in for FSCom in readEnrollmentFile(): the stat result is passed in, open() succeeds only when readable.
struct FakeFile {
    const std::vector<uint8_t> *data;
    bool failRead;
    explicit operator bool() const { return data != nullptr; }
    int read(uint8_t *buf, size_t cap)
    {
        if (failRead)
            return -1;
        const size_t n = data->size() < cap ? data->size() : cap;
        memcpy(buf, data->data(), n);
        return static_cast<int>(n);
    }
    void close() {}
};
struct FakeFs {
    std::vector<uint8_t> data;
    bool readable = false;
    bool failRead = false;
    FakeFile open(const char *, int) { return FakeFile{readable ? &data : nullptr, failRead}; }
};

// LittleFS exists() (nRF52) is false for any lfs_stat error, not only for a missing file. Reading that as MISSING
// leaves the store writable and empty, so the next start mints a new identity over the real one and drops the
// lockout. MISSING needs a NOT_FOUND stat and a failed open; a file that opens is read whatever the stat said.
void test_read_enrollment_file_needs_positive_evidence_for_missing(void)
{
    FakeFs fs;
    fs.data = {1, 2, 3, 4, 5};
    uint8_t buf[16];
    size_t n = 99;

    fs.readable = true; // exists() said no, but the file opens: it is there
    TEST_ASSERT_EQUAL(EnrollmentStorage::ReadStatus::OK, readEnrollmentFile(fs, FileStat::NOT_FOUND, 0, buf, sizeof(buf), n));
    TEST_ASSERT_EQUAL(5, n);
    TEST_ASSERT_EQUAL_UINT8(5, buf[4]);
    TEST_ASSERT_EQUAL(EnrollmentStorage::ReadStatus::OK, readEnrollmentFile(fs, FileStat::ERROR, 0, buf, sizeof(buf), n));
    fs.failRead = true;
    TEST_ASSERT_EQUAL(EnrollmentStorage::ReadStatus::ERROR, readEnrollmentFile(fs, FileStat::NOT_FOUND, 0, buf, sizeof(buf), n));
    TEST_ASSERT_EQUAL(0, n);

    fs.readable = false;
    TEST_ASSERT_EQUAL(EnrollmentStorage::ReadStatus::ERROR, readEnrollmentFile(fs, FileStat::ERROR, 0, buf, sizeof(buf), n));
    TEST_ASSERT_EQUAL(EnrollmentStorage::ReadStatus::ERROR, readEnrollmentFile(fs, FileStat::FOUND, 0, buf, sizeof(buf), n));
    TEST_ASSERT_EQUAL(EnrollmentStorage::ReadStatus::MISSING,
                      readEnrollmentFile(fs, FileStat::NOT_FOUND, 0, buf, sizeof(buf), n));
}

void test_wipe_removes_everything_and_failed_wipe_keeps_state(void)
{
    EnrollmentStore st(mem);
    st.load(0);
    setIdentityOn(st);
    st.addSlot(makeSlot(1), false);
    st.recordFailure(0);
    mem.failRemove = true;
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.wipe());
    TEST_ASSERT_TRUE(st.hasIdentity());
    TEST_ASSERT_EQUAL(1, st.slotsUsed());
    mem.failRemove = false;
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.wipe());
    TEST_ASSERT_FALSE(st.hasIdentity());
    TEST_ASSERT_EQUAL(0, st.slotsUsed());
    TEST_ASSERT_EQUAL(0, st.failureCount());
    TEST_ASSERT_FALSE(mem.exists);
    uint8_t priv[ENROLL_PRIVKEY_LEN];
    TEST_ASSERT_FALSE(st.copyIdentityPrivate(priv));
    EnrollmentStore b(mem);
    TEST_ASSERT_EQUAL(LoadStatus::MISSING, b.load(0));
    setIdentityOn(st, 0x77); // a new identity may now be set
}

void test_protected_path_covers_file_and_tmp(void)
{
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("/prefs/kynoplan_gnss.bin"));
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("prefs/kynoplan_gnss.bin"));
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("//prefs/kynoplan_gnss.bin.tmp"));
    // Path spellings a file-transfer client could use to reach the same file must all be refused.
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("/prefs//kynoplan_gnss.bin"));
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("/prefs/./kynoplan_gnss.bin"));
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("\\prefs\\kynoplan_gnss.bin"));
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("/PREFS/KynoPlan_GNSS.bin"));
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("/./prefs/kynoplan_gnss.bin"));
    // ".." is not resolved: any path with such a segment is refused, since it may land on the file.
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("/x/../prefs/kynoplan_gnss.bin"));
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("/prefs/sub/../kynoplan_gnss.bin"));
    TEST_ASSERT_TRUE(EnrollmentStore::isProtectedPath("..\\prefs\\kynoplan_gnss.bin"));
    TEST_ASSERT_FALSE(EnrollmentStore::isProtectedPath("/prefs/..x/kynoplan_gnss.bin")); // "..x" is a name
    TEST_ASSERT_FALSE(EnrollmentStore::isProtectedPath("/prefs/config.proto"));
    TEST_ASSERT_FALSE(EnrollmentStore::isProtectedPath(nullptr));
}

#ifdef FSCom

#if defined(KYNOPLAN_GNSS_STREAM)
// XModem file transfer is open to every connected client; with KYNOPLAN_GNSS_STREAM it must refuse the identity
// key file under every spelling (SPEC 6.1), while ordinary files stay transferable.
void test_xmodem_refuses_identity_file(void)
{
    TEST_ASSERT_FALSE(XModemAdapter::isValidFilename("/prefs/kynoplan_gnss.bin"));
    TEST_ASSERT_FALSE(XModemAdapter::isValidFilename("/prefs/kynoplan_gnss.bin.tmp"));
    TEST_ASSERT_FALSE(XModemAdapter::isValidFilename("/prefs//./KYNOPLAN_GNSS.BIN"));
    TEST_ASSERT_TRUE(XModemAdapter::isValidFilename("/prefs/config.proto"));
}

static void writeFile(const char *path)
{
    File f = FSCom.open(path, FILE_O_WRITE);
    const uint8_t b[4] = {1, 2, 3, 4};
    f.write(b, sizeof(b));
    f.close();
}

static void adminDelete(AdminModuleTestShim &admin, const char *path)
{
    meshtastic_AdminMessage m = meshtastic_AdminMessage_init_zero;
    m.which_payload_variant = meshtastic_AdminMessage_delete_file_request_tag;
    strncpy(m.delete_file_request, path, sizeof(m.delete_file_request) - 1);
    meshtastic_MeshPacket mp = meshtastic_MeshPacket_init_zero;
    mp.from = 0; // a local phone client: the most trusted admin caller
    mp.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    mp.decoded.portnum = meshtastic_PortNum_ADMIN_APP;
    admin.handleReceivedProtobuf(mp, &m, RX_SRC_USER);
    admin.drainReply();
}

// Admin delete_file_request is open to any local client; only factory reset may remove the identity (SPEC 6.1, 6.5).
// The control file proves the request reaches the delete, so the refusal is not a fixture artefact.
void test_admin_delete_file_refuses_identity_file(void)
{
    rmDir("/prefs");
    FSCom.mkdir("/prefs");
    channels.initDefaults();
    AdminModuleTestShim admin;
    writeFile(ENROLLMENT_FILE_PATH);
    writeFile("/prefs/kynoplan_gnss.bin.tmp");
    writeFile("/prefs/unrelated.bin");

    adminDelete(admin, "/prefs/kynoplan_gnss.bin");
    adminDelete(admin, "/prefs//./KYNOPLAN_GNSS.BIN");
    adminDelete(admin, "/prefs/kynoplan_gnss.bin.tmp");
    adminDelete(admin, "/prefs/unrelated.bin");
    TEST_ASSERT_TRUE(FSCom.exists(ENROLLMENT_FILE_PATH));
    TEST_ASSERT_TRUE(FSCom.exists("/prefs/kynoplan_gnss.bin.tmp"));
    TEST_ASSERT_FALSE(FSCom.exists("/prefs/unrelated.bin"));
    rmDir("/prefs");
}

// The real NodeDB::factoryReset() (src/mesh/NodeDB.cpp) must reach EnrollmentStore::onFactoryReset(). Its own
// rmDir("/prefs") deletes the file either way, so the writes tried after the reset are what prove the hook: without the
// latch the store still holds the identity and writes the file straight back in the seconds before the reboot.
// The NodeDB and the factory-default protos it persists are removed again (tearDown), so the sandbox ends as it began.
static NodeDB *savedNodeDB = nullptr;
static bool factoryResetFixtureUp = false;
static bool messagesFileExisted = false;
static constexpr const char *MESSAGES_FILE = "/Messages_default.msgs"; // factoryReset() clears the message store

static void factoryResetFixtureDown()
{
    if (!factoryResetFixtureUp)
        return;
    delete nodeDB;
    nodeDB = savedNodeDB;
    rmDir("/prefs");
    if (!messagesFileExisted)
        FSCom.remove(MESSAGES_FILE);
    factoryResetFixtureUp = false;
}

void test_nodedb_factory_reset_wipes_and_latches_enrollment_store(void)
{
    rmDir("/prefs");
    messagesFileExisted = FSCom.exists(MESSAGES_FILE);
    savedNodeDB = nodeDB;
    nodeDB = new NodeDB();
    factoryResetFixtureUp = true;
    EnrollmentStore st; // default storage: the real file on the portduino FS
    TEST_ASSERT_EQUAL(LoadStatus::MISSING, st.load(0));
    setIdentityOn(st);
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.recordFailure(0));
    TEST_ASSERT_TRUE(FSCom.exists(ENROLLMENT_FILE_PATH));
    EnrollmentStore::setFactoryResetTarget(&st);

    TEST_ASSERT_TRUE(nodeDB->factoryReset());

    TEST_ASSERT_FALSE_MESSAGE(st.available(), "factory reset must latch the store read-only");
    TEST_ASSERT_FALSE(st.hasIdentity());
    uint8_t priv[ENROLL_PRIVKEY_LEN];
    TEST_ASSERT_FALSE(st.copyIdentityPrivate(priv));
    TEST_ASSERT_EQUAL(0, st.failureCount());
    TEST_ASSERT_FALSE(FSCom.exists(ENROLLMENT_FILE_PATH));
    // What the module may still do before the reboot: none of it may write the file back.
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.recordFailure(5));
    st.tick(5 + ENROLL_LOCKOUT_PERSIST_INTERVAL_S);
    uint8_t pub[ENROLL_PUBKEY_LEN];
    fillKey(pub, sizeof(pub), 0x72);
    TEST_ASSERT_EQUAL(EnrollResult::ERROR_STORAGE, st.setIdentity(priv, pub));
    TEST_ASSERT_FALSE(FSCom.exists(ENROLLMENT_FILE_PATH));
}
#endif // KYNOPLAN_GNSS_STREAM

// Real filesystem path: SafeFile on the portduino FS, the same code the device runs.
void test_real_fs_roundtrip_size_and_factory_reset_removal(void)
{
    rmDir("/prefs");
    EnrollmentStore st; // default storage
    TEST_ASSERT_EQUAL(LoadStatus::MISSING, st.load(0));
    setIdentityOn(st);
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.addSlot(makeSlot(1, "real"), false));
    TEST_ASSERT_TRUE(FSCom.exists(ENROLLMENT_FILE_PATH));
    File f = FSCom.open(ENROLLMENT_FILE_PATH, FILE_O_READ);
    TEST_ASSERT_TRUE(f);
    TEST_ASSERT_EQUAL(FILE_SIZE, f.size());
    f.close();
    TEST_ASSERT_FALSE(FSCom.exists("/prefs/kynoplan_gnss.bin.tmp")); // the atomic rename left no tmp

    EnrollmentStore b;
    TEST_ASSERT_EQUAL(LoadStatus::OK, b.load(0));
    TEST_ASSERT_TRUE(b.hasIdentity());
    EnrollmentSlot one = idSlot(1);
    TEST_ASSERT_NOT_NULL(b.find(one.keyId));

    // NodeDB::factoryReset() starts with rmDir("/prefs"); the identity and every enrollment must go with it.
    rmDir("/prefs");
    TEST_ASSERT_FALSE(FSCom.exists(ENROLLMENT_FILE_PATH));
    EnrollmentStore c;
    TEST_ASSERT_EQUAL(LoadStatus::MISSING, c.load(0));
    TEST_ASSERT_FALSE(c.hasIdentity());
    TEST_ASSERT_EQUAL(0, c.slotsUsed());
}

void test_real_fs_stale_tmp_and_truncated_file(void)
{
    rmDir("/prefs");
    FSCom.mkdir("/prefs");
    {
        File t = FSCom.open("/prefs/kynoplan_gnss.bin.tmp", FILE_O_WRITE);
        const uint8_t junk[40] = {1};
        t.write(junk, sizeof(junk));
        t.close();
    }
    EnrollmentStore st;
    st.load(0);
    TEST_ASSERT_EQUAL(EnrollResult::OK, st.addSlot(makeSlot(1), false));
    EnrollmentStore b;
    TEST_ASSERT_EQUAL(LoadStatus::OK, b.load(0)); // junk in the old tmp did not leak into the saved file

    // A file cut short on flash (power loss in a non-atomic filesystem) loads empty, flagged corrupt.
    {
        File t = FSCom.open(ENROLLMENT_FILE_PATH, FILE_O_WRITE);
        const uint8_t part[100] = {0x4B, 0x50, 0x45, 0x4E};
        t.write(part, sizeof(part));
        t.close();
    }
    EnrollmentStore c;
    TEST_ASSERT_EQUAL(LoadStatus::CORRUPT, c.load(0));
    TEST_ASSERT_EQUAL(0, c.slotsUsed());
    rmDir("/prefs");
}

#endif // FSCom

void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_missing_file_loads_empty_and_reports_missing);
    RUN_TEST(test_roundtrip_identity_slots_and_counter);
    RUN_TEST(test_identity_set_once_and_private_key_hidden_without_identity);
    RUN_TEST(test_every_flipped_byte_is_corrupt_and_loads_empty);
    RUN_TEST(test_truncated_and_overlong_files_are_corrupt);
    RUN_TEST(test_wrong_magic_is_corrupt_and_newer_version_is_unsupported_even_with_valid_crc);
    RUN_TEST(test_corrupt_read_error_and_newer_version_fail_closed);
    RUN_TEST(test_read_error_then_successful_reload_restores_identity_and_lockout);
    RUN_TEST(test_wipe_lifts_failed_closed_store);
    RUN_TEST(test_factory_reset_wipes_target_and_latches_every_store_until_reboot);
    RUN_TEST(test_factory_reset_without_target_still_latches);
    RUN_TEST(test_four_slots_then_full);
    RUN_TEST(test_key_id_collision_rejected_without_change);
    RUN_TEST(test_invalid_slot_arguments_rejected);
    RUN_TEST(test_replace_all_revokes_others_in_one_write);
    RUN_TEST(test_replace_all_write_failure_keeps_every_old_slot);
    RUN_TEST(test_add_resets_failure_counter_in_same_write);
    RUN_TEST(test_revoke_one_and_unknown);
    RUN_TEST(test_revoke_all_others_keeps_only_caller);
    RUN_TEST(test_rotate_keeps_slot_and_label_and_removes_old_key);
    RUN_TEST(test_rotate_collision_unknown_caller_and_bad_key);
    RUN_TEST(test_write_failure_rolls_back_every_mutation);
    RUN_TEST(test_identity_write_failure_leaves_no_identity);
    RUN_TEST(test_lockout_schedule_doubles_to_24h_cap);
    RUN_TEST(test_failures_below_threshold_do_not_lock_but_persist);
    RUN_TEST(test_lockout_counts_down_with_uptime_and_survives_reboot);
    RUN_TEST(test_fourth_failure_doubles_and_cap_holds_across_reload);
    RUN_TEST(test_success_resets_counter_and_lockout_persistently);
    RUN_TEST(test_tick_persists_decrement_at_most_every_10_min_and_at_expiry);
    RUN_TEST(test_failure_counts_even_when_the_write_fails);
    RUN_TEST(test_success_write_failure_keeps_counter);
    RUN_TEST(test_sub_threshold_failure_unsaved_by_failed_write_is_retried_by_tick);
    RUN_TEST(test_failing_writes_are_retried_with_bounded_backoff_including_at_expiry);
    RUN_TEST(test_lockout_counts_down_across_boots_shorter_than_persist_interval);
    RUN_TEST(test_read_enrollment_file_needs_positive_evidence_for_missing);
    RUN_TEST(test_wipe_removes_everything_and_failed_wipe_keeps_state);
    RUN_TEST(test_protected_path_covers_file_and_tmp);
#ifdef FSCom
#if defined(KYNOPLAN_GNSS_STREAM)
    RUN_TEST(test_xmodem_refuses_identity_file);
    RUN_TEST(test_admin_delete_file_refuses_identity_file);
    RUN_TEST(test_nodedb_factory_reset_wipes_and_latches_enrollment_store);
#endif
    RUN_TEST(test_real_fs_roundtrip_size_and_factory_reset_removal);
    RUN_TEST(test_real_fs_stale_tmp_and_truncated_file);
#endif
    exit(UNITY_END());
}

void loop() {}
