/*
 * WasmOS TPM 2.0 CRB transport driver — public interface
 *
 * INTENDED NANOS PATH: kernel/tpm/tpm_crb.h
 * (adjust to match the target Nanos SHA's kernel layout).
 *
 * Companion design: docs/design/nanos-tpm-crb-transport.md §4 in the
 * wasmos repository. This header exports the kernel-internal API that
 * the Nanos syscall shim (see 0002-tpm-syscall-abi.patch) uses to
 * submit TPM 2.0 commands from a userspace ELF (the WasmOS ELF).
 *
 * This driver deliberately implements ONLY raw single-caller serialized
 * transport. No key hierarchy, no session management, no policy — all
 * of that lives above the kernel in the wasmos-security crate.
 */

#ifndef _KERNEL_TPM_TPM_CRB_H_
#define _KERNEL_TPM_TPM_CRB_H_

#include <kernel.h>
#include "tpm_crb_mmio.h"

/* -------------------------------------------------------------------- */
/* State machine (design doc §4.1)                                       */
/* -------------------------------------------------------------------- */

typedef enum {
    TPM_STATE_UNINITIALIZED = 0,
    TPM_STATE_DISCOVERED    = 1,
    TPM_STATE_STARTING      = 2,
    TPM_STATE_READY         = 3,
    TPM_STATE_BUSY          = 4,
    TPM_STATE_FAILED        = 5,
    TPM_STATE_SHUTDOWN      = 6,
} tpm_state;

/* -------------------------------------------------------------------- */
/* Interface identifiers (design doc §5.3)                               */
/* -------------------------------------------------------------------- */

#define TPM_INTERFACE_UNKNOWN 0
#define TPM_INTERFACE_CRB     1
#define TPM_INTERFACE_TIS     2  /* deferred to a future patch */

/* -------------------------------------------------------------------- */
/* Discovery-source enumeration (design doc §4.4)                        */
/* -------------------------------------------------------------------- */

typedef enum {
    TPM_DISCOVERY_NONE      = 0,
    TPM_DISCOVERY_ACPI      = 1,  /* preferred */
    TPM_DISCOVERY_PLATFORM  = 2,  /* platform-provided device desc */
    TPM_DISCOVERY_MANIFEST  = 3,  /* Nanos boot manifest */
    TPM_DISCOVERY_QEMU_FIXED = 4, /* fixed 0xfed40000, final fallback */
} tpm_discovery_source;

/* -------------------------------------------------------------------- */
/* Error classification (design doc §4.3, §5.2)                          */
/*                                                                       */
/* These are DISTINCT from TPM response codes embedded in a TPM response */
/* body. A `status`/`long` from the driver reflects only the transport   */
/* outcome — TPM_RC_* codes live in the response buffer and are the      */
/* caller's responsibility to interpret.                                 */
/* -------------------------------------------------------------------- */

#define TPM_ERR_OK              0
#define TPM_ERR_INVAL           1  /* malformed request / bad args */
#define TPM_ERR_NO_DEVICE       2  /* discovery failed or not initialized */
#define TPM_ERR_TIMEDOUT        3  /* deadline exceeded */
#define TPM_ERR_TRANSPORT       4  /* CRB / hardware transport failure */
#define TPM_ERR_BUSY            5  /* single-in-flight rejection */
#define TPM_ERR_UNHEALTHY       6  /* recovery failed; explicit reinit required */
#define TPM_ERR_INTERNAL        7  /* driver-internal invariant violation */

/* -------------------------------------------------------------------- */
/* Per-instance timeout configuration (design doc §4.6)                  */
/*                                                                       */
/* All values are in nanoseconds. Defaults are conservative and MUST NOT */
/* be hard-coded from observed swtpm behaviour; real TPMs are materially */
/* slower on key generation and large hashes.                            */
/* -------------------------------------------------------------------- */

typedef struct nanos_tpm_timeouts {
    u64 locality_ns;    /* time to acquire locality */
    u64 readiness_ns;   /* time from locality-acquired to command-ready */
    u64 execution_ns;   /* per-command execution deadline (caller override) */
    u64 cancel_ns;      /* time for CRB cancel to complete */
    u64 recovery_ns;    /* total time budget for the recovery flow */
} nanos_tpm_timeouts;

/* Conservative defaults — override via nanos_tpm_configure(). */
#define NANOS_TPM_DEFAULT_LOCALITY_NS   ((u64)200  * 1000 * 1000) /* 200 ms */
#define NANOS_TPM_DEFAULT_READINESS_NS  ((u64)200  * 1000 * 1000)
#define NANOS_TPM_DEFAULT_EXECUTION_NS  ((u64)30ULL * 1000 * 1000 * 1000) /* 30 s */
#define NANOS_TPM_DEFAULT_CANCEL_NS     ((u64)500  * 1000 * 1000)
#define NANOS_TPM_DEFAULT_RECOVERY_NS   ((u64)2ULL  * 1000 * 1000 * 1000) /* 2 s */

/* -------------------------------------------------------------------- */
/* Driver object (design doc §4.2)                                       */
/* -------------------------------------------------------------------- */

typedef struct nanos_tpm {
    tpm_state           state;
    void               *mmio_base;
    u64                 mmio_length;
    u32                 interface_type;
    u32                 locality;
    u32                 maximum_command_size;
    u32                 maximum_response_size;
    mutex               command_lock;
    timestamp           last_success;
    status              last_error;

    /* Register-access seam so unit tests can inject fake MMIO.         */
    const crb_mmio_ops *mmio_ops;

    /* Effective timeouts (design doc §4.6).                            */
    nanos_tpm_timeouts  timeouts;

    /* Discovery provenance (design doc §4.4).                          */
    tpm_discovery_source discovery_source;
} *nanos_tpm;

/* -------------------------------------------------------------------- */
/* Discovery + lifecycle                                                 */
/* -------------------------------------------------------------------- */

/*
 * Discover a TPM interface using the ordered strategy in §4.4:
 *   1. ACPI TPM2 table
 *   2. Platform-provided device description
 *   3. Nanos boot manifest
 *   4. Fixed QEMU dev address (0xfed40000) as final fallback
 *
 * Returns TPM_ERR_OK and populates *out on success; the driver object
 * is owned by the kernel and must be freed via nanos_tpm_destroy().
 *
 * The `ops` argument is normally NULL — pass a fake ops table only
 * from unit tests.
 */
status nanos_tpm_discover(nanos_tpm *out, const crb_mmio_ops *ops);

/*
 * Override the per-instance timeout table (design doc §4.6).
 */
status nanos_tpm_configure(nanos_tpm tpm, const nanos_tpm_timeouts *t);

/*
 * Release driver resources. Idempotent.
 */
void nanos_tpm_destroy(nanos_tpm tpm);

/* -------------------------------------------------------------------- */
/* Transport (design doc §4.3)                                           */
/* -------------------------------------------------------------------- */

/*
 * Submit `command_length` bytes at `command`; block until a response
 * is available or `deadline` (a monotonic timestamp) is exceeded.
 *
 * On success returns TPM_ERR_OK and writes the response length via
 * `*response_length`, which MUST be <= `response_capacity`.
 *
 * The response body may itself encode a TPM_RC_* error code; that is
 * the caller's responsibility to interpret and is NOT a transport
 * failure from this driver's perspective.
 */
status nanos_tpm_transmit(
    nanos_tpm tpm,
    const void *command,
    bytes command_length,
    void *response,
    bytes response_capacity,
    bytes *response_length,
    timestamp deadline);

/* -------------------------------------------------------------------- */
/* Health reporting (design doc §5.3)                                    */
/* -------------------------------------------------------------------- */

typedef struct nanos_tpm_health {
    tpm_state state;
    u32       interface_type;
    timestamp last_success;
    status    last_error;
    u32       maximum_command_size;
    u32       maximum_response_size;
} nanos_tpm_health;

/*
 * Fill *out with a copy of the driver's health snapshot. Safe to call
 * from any context; does not submit a TPM command.
 */
status nanos_tpm_get_health(nanos_tpm tpm, nanos_tpm_health *out);

/* -------------------------------------------------------------------- */
/* Recovery (design doc §4.5)                                            */
/* -------------------------------------------------------------------- */

/*
 * Attempt recovery from a wedged / failed state:
 *   1. CRB cancellation (if supported by the current interface).
 *   2. Reset driver-local state.
 *   3. Revalidate interface registers.
 *   4. Mark unhealthy (TPM_STATE_FAILED) if any step fails.
 *
 * Returns TPM_ERR_OK on successful recovery to TPM_STATE_READY.
 * Returns TPM_ERR_UNHEALTHY otherwise; the driver will reject further
 * transmit calls until nanos_tpm_reinitialize() is called.
 *
 * This function MUST NOT reboot the unikernel — TPM failure is a
 * policy decision that wasmos-* crates own.
 */
status nanos_tpm_recover(nanos_tpm tpm);

/*
 * Explicit re-initialization after an unrecoverable failure. Callers
 * (typically the wasmos-security probe) invoke this only after
 * evaluating deployment policy.
 */
status nanos_tpm_reinitialize(nanos_tpm tpm);

/* -------------------------------------------------------------------- */
/* Global accessor for the syscall shim                                  */
/* -------------------------------------------------------------------- */

nanos_tpm nanos_tpm_default(void);
void nanos_tpm_set_default(nanos_tpm tpm);

#endif /* _KERNEL_TPM_TPM_CRB_H_ */
