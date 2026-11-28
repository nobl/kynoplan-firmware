#if defined(KYNOPLAN_GNSS_STREAM) || defined(PIO_UNIT_TESTING)

#include "EnrollmentStore.h"
#include "configuration.h"
#include <ErriezCRC32.h>
#include <ctype.h>
#include <string.h>

#include "FSCommon.h"
#include "SPILock.h"
#include "SafeFile.h"
#include "security/SecureZero.h"

namespace kynoplan
{

namespace
{

// On-disk image, little-endian, fixed size. Changing any field means a new VERSION.
struct DiskImage {
    uint32_t magic;
    uint8_t version;
    uint8_t hasIdentity;
    uint8_t failureCount;
    uint8_t reserved;
    uint32_t lockoutRemainingS;
    uint8_t identityPriv[ENROLL_PRIVKEY_LEN];
    uint8_t identityPub[ENROLL_PUBKEY_LEN];
    EnrollmentSlot slots[ENROLL_SLOT_COUNT];
    uint32_t crc; // crc32 over every preceding byte
} __attribute__((packed));

static_assert(sizeof(EnrollmentSlot) == 95, "slot layout is part of the file format");
static_assert(sizeof(DiskImage) == 493, "file layout is part of the file format");

using meshtastic_security::secure_zero;

// magic + version: enough to tell a newer format from damage, whatever the file length.
constexpr size_t HEADER_LEN = offsetof(DiskImage, version) + 1;

uint32_t fileMagic(const uint8_t *raw)
{
    uint32_t m;
    memcpy(&m, raw, sizeof(m));
    return m;
}

bool sameKeyId(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, ENROLL_KEY_ID_LEN) == 0;
}

#ifdef FSCom
// Caller holds spiLock.
FileStat statEnrollmentFile()
{
#if defined(ARCH_NRF52) || defined(ARCH_STM32)
    // exists() reports false for every lfs_stat error; only LFS_ERR_NOENT is evidence the file is absent.
    struct lfs_info info;
    FSCom._lockFS();
    const int rc = lfs_stat(FSCom._getFS(), ENROLLMENT_FILE_PATH, &info);
    FSCom._unlockFS();
    return rc == LFS_ERR_OK ? FileStat::FOUND : rc == LFS_ERR_NOENT ? FileStat::NOT_FOUND : FileStat::ERROR;
#else
    return FSCom.exists(ENROLLMENT_FILE_PATH) ? FileStat::FOUND : FileStat::NOT_FOUND;
#endif
}
#endif

class FsStorage : public EnrollmentStorage
{
  public:
    ReadStatus read(uint8_t *buf, size_t cap, size_t &n) override
    {
        n = 0;
#ifdef FSCom
        concurrency::LockGuard g(spiLock);
        return readEnrollmentFile(FSCom, statEnrollmentFile(), FILE_O_READ, buf, cap, n);
#else
        (void)buf;
        (void)cap;
        return ReadStatus::MISSING;
#endif
    }

    bool write(const uint8_t *buf, size_t len) override
    {
#ifdef FSCom
        {
            concurrency::LockGuard g(spiLock);
            FSCom.mkdir("/prefs");
        }
        auto sf = SafeFile(ENROLLMENT_FILE_PATH, true);
        const size_t written = sf.write(buf, len);
        return sf.close() && written == len;
#else
        (void)buf;
        (void)len;
        return false;
#endif
    }

    bool remove() override
    {
#ifdef FSCom
        concurrency::LockGuard g(spiLock);
        // Gone only on evidence: a stat error must not let wipe() clear RAM while the identity file stays on flash.
        return FSCom.remove(ENROLLMENT_FILE_PATH) || statEnrollmentFile() == FileStat::NOT_FOUND;
#else
        return true;
#endif
    }
};

} // namespace

EnrollmentStorage &defaultEnrollmentStorage()
{
    static FsStorage storage;
    return storage;
}

uint32_t EnrollmentStore::lockoutForFailures(uint32_t failures)
{
    if (failures < ENROLL_FAILURES_BEFORE_LOCKOUT)
        return 0;
    const uint32_t doublings = failures - ENROLL_FAILURES_BEFORE_LOCKOUT;
    // 600 << 8 already exceeds the cap; bound the shift so it cannot overflow.
    if (doublings >= 8)
        return ENROLL_LOCKOUT_MAX_S;
    const uint32_t s = ENROLL_LOCKOUT_BASE_S << doublings;
    return s > ENROLL_LOCKOUT_MAX_S ? ENROLL_LOCKOUT_MAX_S : s;
}

std::atomic<bool> EnrollmentStore::factoryResetLatched_{false};
EnrollmentStore *EnrollmentStore::factoryResetTarget_ = nullptr;

uint32_t EnrollmentStore::lockoutRemainingS(uint32_t nowS) const
{
    if (!available())
        return ENROLL_LOCKOUT_MAX_S;
    const uint32_t elapsed = nowS >= st_.lockoutBaseS ? nowS - st_.lockoutBaseS : 0;
    return elapsed >= st_.lockoutRemainingS ? 0 : st_.lockoutRemainingS - elapsed;
}

void EnrollmentStore::clearState()
{
    secure_zero(&st_, sizeof(st_));
    st_.lockoutBaseS = lastNowS_;
    persistedRemainingS_ = 0;
    persistedSinceLoad_ = false;
    unsaved_ = false;
    retryDelayS_ = ENROLL_PERSIST_RETRY_MIN_S;
}

LoadStatus EnrollmentStore::load(uint32_t nowS)
{
    lastNowS_ = nowS;
    lastPersistS_ = nowS;
    clearState();

    DiskImage img;
    size_t n = 0;
    // One byte of headroom: a file longer than the image is corrupt, not silently truncated.
    uint8_t raw[sizeof(DiskImage) + 1];
    const auto rs = storage_.read(raw, sizeof(raw), n);
    LoadStatus status = LoadStatus::OK;
    if (rs == EnrollmentStorage::ReadStatus::MISSING) {
        status = LoadStatus::MISSING;
    } else if (rs == EnrollmentStorage::ReadStatus::ERROR) {
        status = LoadStatus::READ_ERROR;
    } else if (n >= HEADER_LEN && fileMagic(raw) == MAGIC && raw[offsetof(DiskImage, version)] > VERSION) {
        // Checked before the length: a newer format may have a different size.
        status = LoadStatus::UNSUPPORTED_VERSION;
    } else if (n != sizeof(DiskImage)) {
        status = LoadStatus::CORRUPT;
    } else {
        memcpy(&img, raw, sizeof(img));
        if (img.magic != MAGIC || img.version != VERSION || crc32Buffer(&img, offsetof(DiskImage, crc)) != img.crc) {
            status = LoadStatus::CORRUPT;
        } else {
            st_.hasIdentity = img.hasIdentity ? 1 : 0;
            st_.failureCount = img.failureCount;
            st_.lockoutRemainingS = img.lockoutRemainingS > ENROLL_LOCKOUT_MAX_S ? ENROLL_LOCKOUT_MAX_S : img.lockoutRemainingS;
            memcpy(st_.identityPriv, img.identityPriv, sizeof(st_.identityPriv));
            memcpy(st_.identityPub, img.identityPub, sizeof(st_.identityPub));
            memcpy(st_.slots, img.slots, sizeof(st_.slots));
            persistedRemainingS_ = st_.lockoutRemainingS;
        }
        secure_zero(&img, sizeof(img));
    }
    secure_zero(raw, sizeof(raw));
    // Fail closed on anything but OK/MISSING: an empty but writable store would mint a new identity and drop the lockout.
    failedClosed_ = status != LoadStatus::OK && status != LoadStatus::MISSING;
    if (failedClosed_) {
        clearState();
        LOG_WARN("KynoPlan enrollment store unreadable (status %u), feature unavailable", (unsigned)status);
    }
    loadStatus_ = status;
    return status;
}

bool EnrollmentStore::persist()
{
    if (!available())
        return false;
    DiskImage img;
    memset(&img, 0, sizeof(img));
    img.magic = MAGIC;
    img.version = VERSION;
    img.hasIdentity = st_.hasIdentity;
    img.failureCount = st_.failureCount;
    img.lockoutRemainingS = lockoutRemainingS(lastNowS_);
    memcpy(img.identityPriv, st_.identityPriv, sizeof(img.identityPriv));
    memcpy(img.identityPub, st_.identityPub, sizeof(img.identityPub));
    memcpy(img.slots, st_.slots, sizeof(img.slots));
    img.crc = crc32Buffer(&img, offsetof(DiskImage, crc));
    const bool ok = storage_.write(reinterpret_cast<const uint8_t *>(&img), sizeof(img));
    secure_zero(&img, sizeof(img));
    lastPersistS_ = lastNowS_;
    if (ok) {
        persistedRemainingS_ = lockoutRemainingS(lastNowS_);
        loadStatus_ = LoadStatus::OK;
        persistedSinceLoad_ = true;
        unsaved_ = false;
        retryDelayS_ = ENROLL_PERSIST_RETRY_MIN_S;
    } else {
        LOG_ERROR("KynoPlan enrollment store write failed");
    }
    return ok;
}

bool EnrollmentStore::persistOrRetryLater()
{
    if (persist())
        return true;
    if (unsaved_)
        retryDelayS_ =
            retryDelayS_ >= ENROLL_LOCKOUT_PERSIST_INTERVAL_S / 2 ? ENROLL_LOCKOUT_PERSIST_INTERVAL_S : retryDelayS_ * 2;
    else
        retryDelayS_ = ENROLL_PERSIST_RETRY_MIN_S;
    unsaved_ = true;
    return false;
}

EnrollResult EnrollmentStore::commit(State &previous)
{
    const bool ok = persist();
    if (!ok)
        st_ = previous;
    secure_zero(&previous, sizeof(previous));
    return ok ? EnrollResult::OK : EnrollResult::ERROR_STORAGE;
}

int EnrollmentStore::slotIndex(const uint8_t keyId[ENROLL_KEY_ID_LEN]) const
{
    for (size_t i = 0; i < ENROLL_SLOT_COUNT; i++)
        if ((st_.slots[i].flags & SLOT_FLAG_USED) && sameKeyId(st_.slots[i].keyId, keyId))
            return static_cast<int>(i);
    return -1;
}

const EnrollmentSlot *EnrollmentStore::find(const uint8_t keyId[ENROLL_KEY_ID_LEN]) const
{
    const int i = slotIndex(keyId);
    return i < 0 ? nullptr : &st_.slots[i];
}

size_t EnrollmentStore::slotsUsed() const
{
    size_t n = 0;
    for (const auto &s : st_.slots)
        n += (s.flags & SLOT_FLAG_USED) ? 1 : 0;
    return n;
}

size_t EnrollmentStore::list(EnrollmentSlot *out, size_t max) const
{
    size_t n = 0;
    for (const auto &s : st_.slots)
        if ((s.flags & SLOT_FLAG_USED) && n < max)
            out[n++] = s;
    return n;
}

bool EnrollmentStore::copyIdentityPrivate(uint8_t out[ENROLL_PRIVKEY_LEN]) const
{
    if (!st_.hasIdentity)
        return false;
    memcpy(out, st_.identityPriv, ENROLL_PRIVKEY_LEN);
    return true;
}

EnrollResult EnrollmentStore::setIdentity(const uint8_t priv[ENROLL_PRIVKEY_LEN], const uint8_t pub[ENROLL_PUBKEY_LEN])
{
    if (!available())
        return EnrollResult::ERROR_STORAGE;
    if (st_.hasIdentity || pub[0] != 0x04)
        return EnrollResult::ERROR_INVALID;
    State previous = st_;
    memcpy(st_.identityPriv, priv, ENROLL_PRIVKEY_LEN);
    memcpy(st_.identityPub, pub, ENROLL_PUBKEY_LEN);
    st_.hasIdentity = 1;
    return commit(previous);
}

EnrollResult EnrollmentStore::addSlot(const EnrollmentSlot &slot, bool replaceAll)
{
    if (!available())
        return EnrollResult::ERROR_STORAGE;
    if (slot.clientPublicKey[0] != 0x04 || slot.labelLen > ENROLL_LABEL_MAX)
        return EnrollResult::ERROR_INVALID;
    if (slotIndex(slot.keyId) >= 0)
        return EnrollResult::ERROR_KEY_ID_COLLISION;
    State previous = st_;
    int target = -1;
    if (replaceAll) {
        memset(st_.slots, 0, sizeof(st_.slots));
        target = 0;
    } else {
        for (size_t i = 0; i < ENROLL_SLOT_COUNT && target < 0; i++)
            if (!(st_.slots[i].flags & SLOT_FLAG_USED))
                target = static_cast<int>(i);
        if (target < 0) {
            secure_zero(&previous, sizeof(previous));
            return EnrollResult::ERROR_SLOTS_FULL;
        }
    }
    st_.slots[target] = slot;
    // Bytes of the label past labelLen are not meaningful; keep them zero so the file is deterministic.
    memset(st_.slots[target].label + slot.labelLen, 0, ENROLL_LABEL_MAX - slot.labelLen);
    st_.slots[target].flags = SLOT_FLAG_USED;
    st_.failureCount = 0;
    st_.lockoutRemainingS = 0;
    return commit(previous);
}

EnrollResult EnrollmentStore::revoke(const uint8_t keyId[ENROLL_KEY_ID_LEN])
{
    if (!available())
        return EnrollResult::ERROR_STORAGE;
    const int i = slotIndex(keyId);
    if (i < 0)
        return EnrollResult::ERROR_NOT_FOUND;
    State previous = st_;
    memset(&st_.slots[i], 0, sizeof(EnrollmentSlot));
    return commit(previous);
}

EnrollResult EnrollmentStore::revokeAllOthers(const uint8_t callerKeyId[ENROLL_KEY_ID_LEN])
{
    if (!available())
        return EnrollResult::ERROR_STORAGE;
    const int keep = slotIndex(callerKeyId);
    if (keep < 0)
        return EnrollResult::ERROR_NOT_FOUND;
    State previous = st_;
    for (size_t i = 0; i < ENROLL_SLOT_COUNT; i++)
        if (static_cast<int>(i) != keep)
            memset(&st_.slots[i], 0, sizeof(EnrollmentSlot));
    return commit(previous);
}

EnrollResult EnrollmentStore::rotate(const uint8_t callerKeyId[ENROLL_KEY_ID_LEN], const uint8_t newPub[ENROLL_PUBKEY_LEN],
                                     const uint8_t newKeyId[ENROLL_KEY_ID_LEN])
{
    if (!available())
        return EnrollResult::ERROR_STORAGE;
    const int i = slotIndex(callerKeyId);
    if (i < 0)
        return EnrollResult::ERROR_NOT_FOUND;
    if (newPub[0] != 0x04)
        return EnrollResult::ERROR_INVALID;
    if (slotIndex(newKeyId) >= 0)
        return EnrollResult::ERROR_KEY_ID_COLLISION;
    State previous = st_;
    memcpy(st_.slots[i].clientPublicKey, newPub, ENROLL_PUBKEY_LEN);
    memcpy(st_.slots[i].keyId, newKeyId, ENROLL_KEY_ID_LEN);
    return commit(previous);
}

EnrollResult EnrollmentStore::recordFailure(uint32_t nowS)
{
    lastNowS_ = nowS;
    if (!available())
        return EnrollResult::ERROR_STORAGE; // the lockout already reads as capped
    if (st_.failureCount < 255)
        st_.failureCount++;
    // Rebase so the remaining time is exact from now on.
    st_.lockoutRemainingS = lockoutForFailures(st_.failureCount);
    st_.lockoutBaseS = nowS;
    return persistOrRetryLater() ? EnrollResult::OK : EnrollResult::ERROR_STORAGE;
}

EnrollResult EnrollmentStore::recordSuccess()
{
    if (!available())
        return EnrollResult::ERROR_STORAGE;
    State previous = st_;
    st_.failureCount = 0;
    st_.lockoutRemainingS = 0;
    return commit(previous);
}

void EnrollmentStore::tick(uint32_t nowS)
{
    lastNowS_ = nowS;
    if (!available())
        return;
    const uint32_t sinceS = nowS >= lastPersistS_ ? nowS - lastPersistS_ : 0;
    if (unsaved_) {
        // Backoff even at expiry: a flash that keeps failing must not be written every tick.
        if (sinceS < retryDelayS_)
            return;
    } else {
        const uint32_t remaining = lockoutRemainingS(nowS);
        if (remaining == persistedRemainingS_)
            return;
        const uint32_t dueS = persistedSinceLoad_ ? ENROLL_LOCKOUT_PERSIST_INTERVAL_S : ENROLL_LOCKOUT_FIRST_PERSIST_S;
        if (remaining != 0 && sinceS < dueS)
            return;
    }
    persistOrRetryLater();
}

EnrollResult EnrollmentStore::wipe()
{
    if (!storage_.remove())
        return EnrollResult::ERROR_STORAGE;
    clearState();
    failedClosed_ = false; // the factory-reset latch, if set, still holds
    loadStatus_ = LoadStatus::MISSING;
    return EnrollResult::OK;
}

void EnrollmentStore::setFactoryResetTarget(EnrollmentStore *store)
{
    factoryResetTarget_ = store;
}

void EnrollmentStore::onFactoryReset()
{
    // Latch first so no persist starts after this point until reboot; NodeDB's rmDir("/prefs") removes the file too.
    factoryResetLatched_ = true;
    EnrollmentStore *t = factoryResetTarget_;
    if (!t)
        return;
    if (!t->storage_.remove())
        LOG_ERROR("KynoPlan enrollment store delete failed on factory reset");
    t->clearState();
    t->loadStatus_ = LoadStatus::MISSING;
}

bool EnrollmentStore::isProtectedPath(const char *path)
{
    if (!path)
        return false;
    // Normalise before comparing: separators of either kind collapse, "." segments drop, case folds, so
    // "/prefs//./KYNOPLAN_gnss.bin" cannot slip past. Overlong paths and any ".." segment count as protected.
    char norm[96];
    size_t n = 0;
    for (const char *seg = path; *seg;) {
        while (*seg == '/' || *seg == '\\')
            seg++;
        const char *end = seg;
        while (*end && *end != '/' && *end != '\\')
            end++;
        const size_t len = (size_t)(end - seg);
        // Any ".." could resolve onto the file; refuse rather than resolve.
        if (len == 2 && seg[0] == '.' && seg[1] == '.')
            return true;
        if (len && !(len == 1 && seg[0] == '.')) {
            if (n + len + 1 >= sizeof(norm))
                return true;
            if (n)
                norm[n++] = '/';
            for (size_t i = 0; i < len; i++)
                norm[n++] = (char)tolower((unsigned char)seg[i]);
        }
        seg = end;
    }
    norm[n] = '\0';
    // Prefix match so the SafeFile ".tmp" sibling is covered too.
    const char *protectedPath = ENROLLMENT_FILE_PATH + 1;
    return strncmp(norm, protectedPath, strlen(protectedPath)) == 0;
}

} // namespace kynoplan

#endif
