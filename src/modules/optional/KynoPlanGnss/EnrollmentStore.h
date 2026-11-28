#pragma once

#if defined(KYNOPLAN_GNSS_STREAM) || defined(PIO_UNIT_TESTING)

#include <atomic>
#include <stddef.h>
#include <stdint.h>

// Persistent KynoPlan enrollment state: device identity key pair, 4 client slots and the enrollment failure counter,
// in one versioned, CRC-protected file in /prefs. The identity private key lives only here; /prefs is deleted by
// NodeDB::factoryReset(), which also calls EnrollmentStore::onFactoryReset() for the in-RAM copy (SPEC 6.1, 6.5).
namespace kynoplan
{

constexpr size_t ENROLL_SLOT_COUNT = 4;
constexpr size_t ENROLL_PUBKEY_LEN = 65;
constexpr size_t ENROLL_PRIVKEY_LEN = 32;
constexpr size_t ENROLL_KEY_ID_LEN = 8;
constexpr size_t ENROLL_LABEL_MAX = 16;

constexpr const char *ENROLLMENT_FILE_PATH = "/prefs/kynoplan_gnss.bin";

// Failure counter policy (SPEC 7.4): from the 3rd failure the lockout is 10 min, doubling per further failure, 24 h cap.
constexpr uint32_t ENROLL_FAILURES_BEFORE_LOCKOUT = 3;
constexpr uint32_t ENROLL_LOCKOUT_BASE_S = 600;
constexpr uint32_t ENROLL_LOCKOUT_MAX_S = 86400;
// Countdown writes are flash wear; a reboot loses at most this much countdown (the lockout only gets longer).
constexpr uint32_t ENROLL_LOCKOUT_PERSIST_INTERVAL_S = 600;
// The first countdown write after load() comes this early, so frequent reboots still count down; a reboot loop shorter
// than this makes no progress, but the persisted lockout is never shorter than the true one.
constexpr uint32_t ENROLL_LOCKOUT_FIRST_PERSIST_S = 60;
// A failed write is retried from tick(), the delay doubling from this up to ENROLL_LOCKOUT_PERSIST_INTERVAL_S.
constexpr uint32_t ENROLL_PERSIST_RETRY_MIN_S = 10;

enum class EnrollResult : uint8_t {
    OK = 0,
    ERROR_STORAGE,          // the file could not be written; nothing changed
    ERROR_SLOTS_FULL,       // all slots used and replace_all not requested
    ERROR_KEY_ID_COLLISION, // the key_id is already enrolled
    ERROR_NOT_FOUND,        // no slot with that key_id
    ERROR_INVALID,          // malformed argument (key prefix, label length) or identity already present
};

// Every status other than OK and MISSING leaves the store failed closed: empty, all writes refused with ERROR_STORAGE,
// lockout reported as ENROLL_LOCKOUT_MAX_S, available() false. Only a later OK/MISSING load() or wipe() lifts it, so a
// bad read never regenerates the identity or clears a lockout. CORRUPT is not retried into a new identity either:
// recovery is factory reset or an explicit wipe().
enum class LoadStatus : uint8_t {
    OK = 0,
    MISSING,             // no file: first start or after a factory reset
    CORRUPT,             // wrong length, bad magic, version 0 or CRC mismatch
    READ_ERROR,          // the filesystem failed to open or read an existing file; load() may be retried
    UNSUPPORTED_VERSION, // valid magic, newer format (written by newer firmware before a downgrade)
};

struct EnrollmentSlot {
    uint8_t clientPublicKey[ENROLL_PUBKEY_LEN];
    uint8_t keyId[ENROLL_KEY_ID_LEN];
    uint8_t label[ENROLL_LABEL_MAX];
    uint8_t labelLen;
    uint8_t flags; // bit 0: slot in use
    uint32_t enrolledUnixS;
} __attribute__((packed));

constexpr uint8_t SLOT_FLAG_USED = 0x01;

// Byte storage behind the store. The default implementation uses the Meshtastic filesystem and SafeFile; tests inject
// failures through it.
class EnrollmentStorage
{
  public:
    enum class ReadStatus : uint8_t { OK, MISSING, ERROR };
    virtual ~EnrollmentStorage() {}
    // Reads up to cap bytes; n is the number read.
    virtual ReadStatus read(uint8_t *buf, size_t cap, size_t &n) = 0;
    // Atomically replaces the whole file; false means the previous content is untouched.
    virtual bool write(const uint8_t *buf, size_t len) = 0;
    virtual bool remove() = 0;
};

// Result of a stat of the file. FSCom.exists() folds stat errors into false on LittleFS, so it cannot give ERROR.
enum class FileStat : uint8_t { FOUND, NOT_FOUND, ERROR };

// Reads the file through fs (FSCom in the device build). MISSING needs both a NOT_FOUND stat and a failed open: a file
// that opens is read whatever the stat said, and a failed stat is ERROR, so a flaky stat never reads as a fresh store.
template <class Fs, class Mode>
EnrollmentStorage::ReadStatus readEnrollmentFile(Fs &fs, FileStat stat, Mode readMode, uint8_t *buf, size_t cap, size_t &n)
{
    n = 0;
    auto f = fs.open(ENROLLMENT_FILE_PATH, readMode);
    if (!f)
        return stat == FileStat::NOT_FOUND ? EnrollmentStorage::ReadStatus::MISSING : EnrollmentStorage::ReadStatus::ERROR;
    const int got = static_cast<int>(f.read(buf, cap));
    f.close();
    if (got < 0)
        return EnrollmentStorage::ReadStatus::ERROR;
    n = static_cast<size_t>(got);
    return EnrollmentStorage::ReadStatus::OK;
}

// SafeFile (write tmp, hash readback, rename) on FSCom at ENROLLMENT_FILE_PATH; read-only failure everywhere without FSCom.
EnrollmentStorage &defaultEnrollmentStorage();

// Not thread-safe: every call, like NodeDB::factoryReset() which wipes it, must run on the main loop thread.
class EnrollmentStore
{
  public:
    static constexpr uint32_t MAGIC = 0x4E45504Bu; // "KPEN"
    static constexpr uint8_t VERSION = 1;

    explicit EnrollmentStore(EnrollmentStorage &storage = defaultEnrollmentStorage()) : storage_(storage) {}

    // nowS is monotonic uptime seconds. Safe to call again to retry after READ_ERROR; see LoadStatus for failure handling.
    LoadStatus load(uint32_t nowS);
    LoadStatus lastLoadStatus() const { return loadStatus_; }
    // False while failed closed after a bad load, or after a factory reset until reboot: the feature is unavailable.
    bool available() const { return !failedClosed_ && !factoryResetLatched_.load(); }

    // Identity key pair, generated by the caller. Refused once an identity exists; only wipe() (factory reset) clears it.
    bool hasIdentity() const { return st_.hasIdentity != 0; }
    EnrollResult setIdentity(const uint8_t priv[ENROLL_PRIVKEY_LEN], const uint8_t pub[ENROLL_PUBKEY_LEN]);
    const uint8_t *identityPublic() const { return st_.identityPub; }
    bool copyIdentityPrivate(uint8_t out[ENROLL_PRIVKEY_LEN]) const;

    // A successful add also resets the failure counter in the same write. replaceAll revokes every other slot atomically.
    EnrollResult addSlot(const EnrollmentSlot &slot, bool replaceAll);
    EnrollResult revoke(const uint8_t keyId[ENROLL_KEY_ID_LEN]);
    EnrollResult revokeAllOthers(const uint8_t callerKeyId[ENROLL_KEY_ID_LEN]);
    // Replaces the caller's key, keeping slot position, label and enrollment time.
    EnrollResult rotate(const uint8_t callerKeyId[ENROLL_KEY_ID_LEN], const uint8_t newPub[ENROLL_PUBKEY_LEN],
                        const uint8_t newKeyId[ENROLL_KEY_ID_LEN]);

    const EnrollmentSlot *find(const uint8_t keyId[ENROLL_KEY_ID_LEN]) const;
    size_t list(EnrollmentSlot *out, size_t max) const;
    size_t slotsUsed() const;

    // A failed write still counts the failure in memory (fail closed): rolling it back would reward an attacker who can
    // make the flash write fail. The result is ERROR_STORAGE in that case.
    EnrollResult recordFailure(uint32_t nowS);
    EnrollResult recordSuccess();
    uint32_t failureCount() const { return st_.failureCount; }
    // ENROLL_LOCKOUT_MAX_S while !available() (fail closed).
    uint32_t lockoutRemainingS(uint32_t nowS) const;
    // Persists the decremented lockout at most every ENROLL_LOCKOUT_PERSIST_INTERVAL_S (first after load() sooner, and
    // at expiry), and retries any state a failed write left unsaved with backoff.
    void tick(uint32_t nowS);
    static uint32_t lockoutForFailures(uint32_t failures);

    // Deletes the file and empties the store, lifting a failed-closed load. State is kept if the delete fails.
    EnrollResult wipe();

    // The store NodeDB::factoryReset() must wipe (the module's instance); nullptr detaches.
    static void setFactoryResetTarget(EnrollmentStore *store);
    // Called by NodeDB::factoryReset(): latches every store read-only until reboot, then wipes the target's file and RAM.
    static void onFactoryReset();
#if defined(PIO_UNIT_TESTING)
    static void clearFactoryResetLatchForTest() { factoryResetLatched_ = false; }
#endif

    // True for paths XModem and admin delete_file_request must refuse. The PhoneAPI file manifest still lists the file
    // (name and size only, never content).
    static bool isProtectedPath(const char *path);

  private:
    struct State {
        uint8_t hasIdentity;
        uint8_t failureCount;
        uint32_t lockoutRemainingS; // as of lockoutBaseS
        uint32_t lockoutBaseS;
        uint8_t identityPriv[ENROLL_PRIVKEY_LEN];
        uint8_t identityPub[ENROLL_PUBKEY_LEN];
        EnrollmentSlot slots[ENROLL_SLOT_COUNT];
    };

    bool persist();
    // persist() for state already changed in RAM: a failure marks it unsaved for tick() to retry.
    bool persistOrRetryLater();
    int slotIndex(const uint8_t keyId[ENROLL_KEY_ID_LEN]) const;
    // Persists, restoring previous on failure; previous holds the private key and is wiped either way.
    EnrollResult commit(State &previous);
    void clearState();

    static std::atomic<bool> factoryResetLatched_;
    static EnrollmentStore *factoryResetTarget_;

    EnrollmentStorage &storage_;
    State st_ = {};
    LoadStatus loadStatus_ = LoadStatus::MISSING;
    bool failedClosed_ = false;
    uint32_t lastNowS_ = 0;
    uint32_t lastPersistS_ = 0;
    uint32_t persistedRemainingS_ = 0;
    bool persistedSinceLoad_ = false;
    bool unsaved_ = false; // RAM holds state a failed write did not save
    uint32_t retryDelayS_ = ENROLL_PERSIST_RETRY_MIN_S;
};

} // namespace kynoplan

#endif
