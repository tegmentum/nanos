/*
 * WasmOS TPM syscall ABI — public header
 *
 * INTENDED NANOS PATH: kernel/tpm/tpm_syscall.h
 *
 * Companion design: docs/design/nanos-tpm-crb-transport.md §5 in the
 * wasmos repository.
 *
 * User-space ABI: keep this file BINARY-STABLE across kernel updates.
 * Adding fields to nanos_tpm_status_abi requires bumping
 * NANOS_TPM_STATUS_ABI_VERSION.
 */

#ifndef _KERNEL_TPM_TPM_SYSCALL_H_
#define _KERNEL_TPM_TPM_SYSCALL_H_

#include <kernel.h>

/* Not part of the syscall payload; wasmos-platform-nanos checks this
 * at load time to detect a kernel/userspace mismatch.  Consult via
 * uname()-shaped mechanism or a dedicated getauxval-equivalent. */
#define NANOS_TPM_STATUS_ABI_VERSION 1

/*
 * User-visible mirror of nanos_tpm_health.
 *
 * NOTE: this MUST NOT include kernel-internal types such as `status`
 * or `timestamp` directly — encode everything as fixed-width integers
 * so the layout is stable across Nanos revisions.
 */
struct nanos_tpm_status_abi {
    u32 state;                /* matches tpm_state enum in tpm_crb.h */
    u32 interface_type;       /* 1 = CRB, 2 = TIS (reserved) */
    u64 last_success_ns;      /* monotonic timestamp, 0 if never */
    u32 last_error_class;     /* matches TPM_ERR_* in tpm_crb.h */
    u32 max_command_size;
    u32 max_response_size;
    u32 discovery_source;     /* matches tpm_discovery_source enum */
    u32 _reserved;            /* keep the struct 8-byte-aligned */
};

/*
 * Syscall entry points — invoked by the syscall dispatcher.
 *
 * The `p` argument is the calling process, which the implementation
 * uses to translate + validate user-space buffer pointers.  In a
 * classic Nanos syscall shim these are read from the current thread
 * context; the exact wiring is Nanos-fork-specific and belongs in the
 * integration commit.
 */

/*
 * nanos_tpm_command — submit a raw TPM 2.0 command.
 *
 * Returns:
 *   0           on success; *response_length set to the actual
 *               response size (which the caller must validate against
 *               the TPM response code embedded in the response body).
 *   -EINVAL     malformed buffers, oversized command, or oversized
 *               response capacity request.
 *   -ENOTSUP    the TPM is not initialized on this kernel.
 *   -ETIMEDOUT  deadline exceeded.
 *   -EIO        transport / hardware failure.
 *   -EAGAIN     driver-busy (single-in-flight enforcement rejects
 *               simultaneous callers).
 *   -EFAULT     a user pointer was not addressable.
 *
 * The syscall NEVER blocks longer than `timeout_ns` nanoseconds.
 * A timeout of 0 selects the driver's per-instance default.
 */
long nanos_sys_tpm_command(
    process p,
    const void *user_command,
    u64 command_length,
    void *user_response,
    u64 response_capacity,
    u64 *user_response_length,
    u64 timeout_ns);

/*
 * nanos_tpm_status — non-blocking health probe.
 *
 * Returns:
 *   0        on success; *user_out populated with the driver snapshot.
 *   -EINVAL  user_out was NULL.
 *   -EFAULT  user_out is not addressable.
 *   -ENOTSUP the TPM subsystem was not registered at kernel init
 *            (fallback in the syscall's implementation returns a
 *             zeroed struct with state = TPM_STATE_UNINITIALIZED).
 */
long nanos_sys_tpm_status(
    process p,
    struct nanos_tpm_status_abi *user_out);

#endif /* _KERNEL_TPM_TPM_SYSCALL_H_ */
