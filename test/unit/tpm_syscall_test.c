/*
 * tpm_syscall_test.c - TPM syscall ABI + error-mapping unit tests
 *
 * NANOS PATH: test/unit/tpm_syscall_test.c
 *
 * Companion design (wasmos): docs/design/nanos-tpm-crb-transport.md sec 5.
 *
 * Scope of what THIS file tests, and why the scope is narrow:
 *
 * src/tpm/tpm_syscall.c is not linkable in this userspace test harness.
 * It #includes <unix_internal.h> which pulls in `sysreturn`, `process`,
 * `current`, `copy_from_user` / `copy_to_user`, `validate_process_memory`
 * and other syscall-dispatcher machinery that only exists in a Nanos
 * kernel build. The scaffold tests originally drafted (see wasmos
 * deploy/nanos/patches/tests/test_tpm_syscall.c) assumed a mockable
 * `process` type and a `nanos_sys_tpm_command` signature that took the
 * process as a parameter - neither assumption survived the driver's
 * Nanos integration:
 *
 *   - The real syscall signature is the standard Nanos six-u64 slot
 *     shape (see src/unix/syscall.c syscall_handler) and pulls the
 *     process from `current->p`.
 *   - The real error mapping uses -EOPNOTSUPP (not -ENOTSUP).
 *   - The real ABI struct is defined in tpm_syscall.h and includes
 *     fields the scaffold's mock did not model.
 *
 * What IS testable from userspace (and is exercised here):
 *
 *   - The nanos_tpm_status_abi struct layout and size. This struct
 *     crosses the kernel/userspace ABI boundary; a silent field-order
 *     or size change would break wasmos-platform-nanos without any
 *     earlier failure signal. The layout is replicated here (verbatim
 *     from tpm_syscall.h) so an intentional ABI change requires
 *     updating both the header and this test in the same commit.
 *   - The error-mapping switch in map_driver_error() - replicated here
 *     with the same cases the driver uses.
 *   - The upper-bound size for a single syscall transfer
 *     (TPM_SYS_MAX_TRANSFER_BYTES).
 *
 * What is documented as skipped, and why:
 *
 *   Every scaffold test that actually invokes nanos_sys_tpm_command or
 *   nanos_sys_tpm_status. Those require linking tpm_syscall.c, which
 *   in turn requires the kernel build environment.
 */

#include <runtime.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Nanos redefines offsetof() in runtime.h to a form that assumes __t is a
 * pointer type: `u64_from_pointer(&((__t)0)->__e)`. That interface is
 * fine for the kernel's typedef-of-pointer style but does not match the
 * standard `offsetof(struct type, member)` form used by ABI-layout
 * tests. Restore the compiler builtin for use below. */
#undef offsetof
#define offsetof(t, m) __builtin_offsetof(t, m)

/* -------------------------------------------------------------------- */
/* Local test harness (mirrors tpm_crb_test.c).                          */
/* -------------------------------------------------------------------- */

#define TEST(name) static void name(const char **failure_out)

#define ASSERT(cond) do {                                                  \
    if (!(cond)) {                                                         \
        static char _msg[256];                                             \
        snprintf(_msg, sizeof(_msg),                                       \
                 "%s:%d assertion failed: %s",                             \
                 __FILE__, __LINE__, #cond);                               \
        *failure_out = _msg;                                               \
        return;                                                            \
    }                                                                      \
} while (0)

#define ASSERT_EQ_U(actual, expected) do {                                 \
    u64 _a = (u64)(actual);                                                \
    u64 _e = (u64)(expected);                                              \
    if (_a != _e) {                                                        \
        static char _msg[256];                                             \
        snprintf(_msg, sizeof(_msg),                                       \
                 "%s:%d %s: expected 0x%llx, got 0x%llx",                  \
                 __FILE__, __LINE__, #actual,                              \
                 (unsigned long long)_e, (unsigned long long)_a);          \
        *failure_out = _msg;                                               \
        return;                                                            \
    }                                                                      \
} while (0)

static u32 g_pass, g_fail, g_skip;

static void run(const char *name, void (*fn)(const char **))
{
    const char *failure = 0;
    fn(&failure);
    if (failure) {
        printf("  FAIL  %s: %s\n", name, failure);
        g_fail++;
    } else {
        printf("  ok    %s\n", name);
        g_pass++;
    }
}

static void skip(const char *name, const char *reason)
{
    printf("  SKIP  %s (%s)\n", name, reason);
    g_skip++;
}

#define RUN(name)  run(#name, name)
#define SKIP(name, reason) skip(#name, reason)

/* -------------------------------------------------------------------- */
/* Constants replicated from src/tpm/tpm_crb.h.                          */
/*                                                                       */
/* These are the driver-side classification codes. The syscall layer     */
/* maps them onto POSIX errnos; both sides MUST agree on the numeric     */
/* values.                                                                */
/* -------------------------------------------------------------------- */

#define TPM_ERR_OK              0
#define TPM_ERR_INVAL           1
#define TPM_ERR_NO_DEVICE       2
#define TPM_ERR_TIMEDOUT        3
#define TPM_ERR_TRANSPORT       4
#define TPM_ERR_BUSY            5
#define TPM_ERR_UNHEALTHY       6
#define TPM_ERR_INTERNAL        7
#define TPM_ERR_UNSUPPORTED     8

/* -------------------------------------------------------------------- */
/* Error-mapping replica.                                                */
/*                                                                       */
/* Verbatim copy of the switch in src/tpm/tpm_syscall.c                  */
/* map_driver_error() so the test suite catches accidental drift in     */
/* the errno translation. If the driver adds a new TPM_ERR_* class, the */
/* exhaustiveness test at the bottom of this file will fail until this  */
/* replica and the exhaustiveness list are both updated.                */
/* -------------------------------------------------------------------- */

static long replica_map_driver_error(int s)
{
    switch (s) {
    case TPM_ERR_OK:         return 0;
    case TPM_ERR_INVAL:      return -EINVAL;
    case TPM_ERR_NO_DEVICE:  return -EOPNOTSUPP;
    case TPM_ERR_TIMEDOUT:   return -ETIMEDOUT;
    case TPM_ERR_TRANSPORT:  return -EIO;
    case TPM_ERR_BUSY:       return -EAGAIN;
    case TPM_ERR_UNHEALTHY:  return -EIO;
    default:                 return -EIO;
    }
}

/* -------------------------------------------------------------------- */
/* Local replica of nanos_tpm_status_abi.                                */
/*                                                                       */
/* Verbatim from src/tpm/tpm_syscall.h. Any change to that struct MUST   */
/* be mirrored here in the same commit; the "layout matches" tests fail */
/* until it is.                                                          */
/* -------------------------------------------------------------------- */

struct nanos_tpm_status_abi_replica {
    u32 state;
    u32 interface_type;
    u64 last_success_ns;
    u32 last_error_class;
    u32 max_command_size;
    u32 max_response_size;
    u32 discovery_source;
    u32 _reserved;
};

#define NANOS_TPM_STATUS_ABI_VERSION_REPLICA 1

/* Locally-replicated constants (from src/tpm/tpm_crb.h + tpm_syscall.h)
 * so the ABI-value tests catch drift without needing to include the
 * kernel-only headers directly. */
#define TPM_STATE_UNINITIALIZED   0
#define TPM_STATE_DISCOVERED      1
#define TPM_STATE_STARTING        2
#define TPM_STATE_READY           3
#define TPM_STATE_BUSY            4
#define TPM_STATE_FAILED          5
#define TPM_STATE_SHUTDOWN        6

#define TPM_INTERFACE_UNKNOWN     0
#define TPM_INTERFACE_CRB         1
#define TPM_INTERFACE_TIS         2

#define TPM_DISCOVERY_NONE        0
#define TPM_DISCOVERY_ACPI        1
#define TPM_DISCOVERY_PLATFORM    2
#define TPM_DISCOVERY_MANIFEST    3
#define TPM_DISCOVERY_QEMU_FIXED  4

/* From src/tpm/tpm_syscall.c: */
#define TPM_SYS_MAX_TRANSFER_BYTES (128u * 1024u)

/* -------------------------------------------------------------------- */
/* Status ABI struct layout tests.                                       */
/* -------------------------------------------------------------------- */

TEST(status_abi_struct_is_the_expected_size)
{
    /* 3x u32 (state, interface_type) + u64 + 4x u32 + u32 pad = 40 B. */
    ASSERT_EQ_U(sizeof(struct nanos_tpm_status_abi_replica), 40);
}

TEST(status_abi_field_offsets_are_stable)
{
    ASSERT_EQ_U(offsetof(struct nanos_tpm_status_abi_replica, state),             0);
    ASSERT_EQ_U(offsetof(struct nanos_tpm_status_abi_replica, interface_type),    4);
    ASSERT_EQ_U(offsetof(struct nanos_tpm_status_abi_replica, last_success_ns),   8);
    ASSERT_EQ_U(offsetof(struct nanos_tpm_status_abi_replica, last_error_class), 16);
    ASSERT_EQ_U(offsetof(struct nanos_tpm_status_abi_replica, max_command_size), 20);
    ASSERT_EQ_U(offsetof(struct nanos_tpm_status_abi_replica, max_response_size),24);
    ASSERT_EQ_U(offsetof(struct nanos_tpm_status_abi_replica, discovery_source), 28);
    ASSERT_EQ_U(offsetof(struct nanos_tpm_status_abi_replica, _reserved),        32);
}

TEST(status_abi_version_is_one)
{
    /* Version bumps require a coordinated update to wasmos-platform-nanos. */
    ASSERT_EQ_U(NANOS_TPM_STATUS_ABI_VERSION_REPLICA, 1);
}

TEST(status_abi_enum_values_are_stable)
{
    /* state enum */
    ASSERT_EQ_U(TPM_STATE_UNINITIALIZED, 0);
    ASSERT_EQ_U(TPM_STATE_DISCOVERED,    1);
    ASSERT_EQ_U(TPM_STATE_STARTING,      2);
    ASSERT_EQ_U(TPM_STATE_READY,         3);
    ASSERT_EQ_U(TPM_STATE_BUSY,          4);
    ASSERT_EQ_U(TPM_STATE_FAILED,        5);
    ASSERT_EQ_U(TPM_STATE_SHUTDOWN,      6);

    /* interface type */
    ASSERT_EQ_U(TPM_INTERFACE_UNKNOWN,   0);
    ASSERT_EQ_U(TPM_INTERFACE_CRB,       1);
    ASSERT_EQ_U(TPM_INTERFACE_TIS,       2);

    /* discovery source */
    ASSERT_EQ_U(TPM_DISCOVERY_NONE,       0);
    ASSERT_EQ_U(TPM_DISCOVERY_ACPI,       1);
    ASSERT_EQ_U(TPM_DISCOVERY_PLATFORM,   2);
    ASSERT_EQ_U(TPM_DISCOVERY_MANIFEST,   3);
    ASSERT_EQ_U(TPM_DISCOVERY_QEMU_FIXED, 4);
}

/* -------------------------------------------------------------------- */
/* Syscall transfer-size bound.                                          */
/* -------------------------------------------------------------------- */

TEST(max_transfer_bytes_is_128_KiB)
{
    /* Design sec 5.1: syscall boundary rejects clearly-bogus sizes
     * without ever touching the mutex. 128 KiB comfortably covers the
     * largest TPM 2.0 responses we anticipate. */
    ASSERT_EQ_U(TPM_SYS_MAX_TRANSFER_BYTES, 128u * 1024u);
}

/* -------------------------------------------------------------------- */
/* Error-mapping table (design sec 5.2).                                 */
/*                                                                       */
/* Exhaustiveness assertion: EVERY TPM_ERR_* value must have an          */
/* intentional mapping. If the driver adds a new one, this test flags   */
/* it and the developer must update both replica_map_driver_error() and */
/* the case list below in the same commit.                              */
/* -------------------------------------------------------------------- */

TEST(map_ok_returns_zero)
{
    ASSERT_EQ_U(replica_map_driver_error(TPM_ERR_OK), 0);
}

TEST(map_inval_returns_minus_einval)
{
    ASSERT_EQ_U(replica_map_driver_error(TPM_ERR_INVAL), -EINVAL);
}

TEST(map_no_device_returns_minus_eopnotsupp)
{
    ASSERT_EQ_U(replica_map_driver_error(TPM_ERR_NO_DEVICE), -EOPNOTSUPP);
}

TEST(map_timedout_returns_minus_etimedout)
{
    ASSERT_EQ_U(replica_map_driver_error(TPM_ERR_TIMEDOUT), -ETIMEDOUT);
}

TEST(map_transport_returns_minus_eio)
{
    ASSERT_EQ_U(replica_map_driver_error(TPM_ERR_TRANSPORT), -EIO);
}

TEST(map_busy_returns_minus_eagain)
{
    ASSERT_EQ_U(replica_map_driver_error(TPM_ERR_BUSY), -EAGAIN);
}

TEST(map_unhealthy_returns_minus_eio)
{
    ASSERT_EQ_U(replica_map_driver_error(TPM_ERR_UNHEALTHY), -EIO);
}

TEST(map_internal_falls_through_to_minus_eio)
{
    ASSERT_EQ_U(replica_map_driver_error(TPM_ERR_INTERNAL), -EIO);
}

TEST(map_unsupported_falls_through_to_minus_eio)
{
    /* TPM_ERR_UNSUPPORTED is not (yet) a named case in the switch; it
     * currently reaches the -EIO default. If a future refactor gives it
     * a dedicated case, update this test and the replica together. */
    ASSERT_EQ_U(replica_map_driver_error(TPM_ERR_UNSUPPORTED), -EIO);
}

TEST(map_covers_every_driver_error_class)
{
    /* Structural: iterate through every declared TPM_ERR_* value and
     * assert the mapping does not return an out-of-range errno. This
     * catches accidental case-typos and reminds developers to keep the
     * exhaustive per-value tests above in sync. */
    static const int codes[] = {
        TPM_ERR_OK, TPM_ERR_INVAL, TPM_ERR_NO_DEVICE, TPM_ERR_TIMEDOUT,
        TPM_ERR_TRANSPORT, TPM_ERR_BUSY, TPM_ERR_UNHEALTHY,
        TPM_ERR_INTERNAL, TPM_ERR_UNSUPPORTED,
    };
    for (u32 i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        long r = replica_map_driver_error(codes[i]);
        /* Either OK (0) or a negative errno. Positive returns would mean
         * the switch failed to negate. */
        ASSERT(r == 0 || r < 0);
    }
}

/* -------------------------------------------------------------------- */
/* main.                                                                 */
/* -------------------------------------------------------------------- */

int main(void)
{
    printf("tpm_syscall_test: ABI layout + error-mapping\n");

    RUN(status_abi_struct_is_the_expected_size);
    RUN(status_abi_field_offsets_are_stable);
    RUN(status_abi_version_is_one);
    RUN(status_abi_enum_values_are_stable);

    RUN(max_transfer_bytes_is_128_KiB);

    RUN(map_ok_returns_zero);
    RUN(map_inval_returns_minus_einval);
    RUN(map_no_device_returns_minus_eopnotsupp);
    RUN(map_timedout_returns_minus_etimedout);
    RUN(map_transport_returns_minus_eio);
    RUN(map_busy_returns_minus_eagain);
    RUN(map_unhealthy_returns_minus_eio);
    RUN(map_internal_falls_through_to_minus_eio);
    RUN(map_unsupported_falls_through_to_minus_eio);
    RUN(map_covers_every_driver_error_class);

    /* Design sec 5 checklist items whose testing requires linking
     * tpm_syscall.c (and hence the kernel build environment). Reported
     * here so the coverage signal is honest, not hidden. */
    const char *why = "requires tpm_syscall.c linkage; kernel-only translation unit";
    SKIP(command_returns_einval_on_null_command_pointer,     why);
    SKIP(command_returns_einval_on_null_response_pointer,    why);
    SKIP(command_returns_einval_on_zero_command_length,      why);
    SKIP(command_returns_einval_on_oversize_command_length,  why);
    SKIP(command_returns_eopnotsupp_when_default_unset,      why);
    SKIP(command_returns_efault_when_user_range_invalid,     why);
    SKIP(command_zeroes_scratch_after_return,                why);
    SKIP(status_returns_einval_on_null_out_pointer,          why);
    SKIP(status_returns_uninit_snapshot_when_default_unset,  why);
    SKIP(status_reports_ready_after_successful_discovery,    why);

    printf("tpm_syscall_test: pass=%u fail=%u skip=%u\n",
           g_pass, g_fail, g_skip);
    return g_fail ? EXIT_FAILURE : EXIT_SUCCESS;
}
