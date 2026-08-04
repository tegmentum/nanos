/*
 * WasmOS TPM syscall ABI - public header
 *
 * NANOS PATH: src/tpm/tpm_syscall.h
 *
 * Companion design: docs/design/nanos-tpm-crb-transport.md sec 5 in the
 * wasmos repository.
 *
 * User-space ABI: keep this file BINARY-STABLE across kernel updates.
 * Adding fields to nanos_tpm_status_abi requires bumping
 * NANOS_TPM_STATUS_ABI_VERSION.
 *
 * The syscall handlers use Nanos's standard six-u64-argument dispatch
 * signature (see src/unix/syscall.c), so both functions unpack their
 * user-space arguments from the raw register values that the platform
 * syscall stub passes in. `current->p` supplies the calling process.
 */

/* Nanos headers use no include guards - each header is expected to be
 * included exactly once from a .c file that has already pulled in
 * <runtime.h> / <kernel.h> / <unix_internal.h>.  Do NOT #include those
 * here. `struct syscall`, `process`, and `sysreturn` come from
 * <unix_internal.h>. */

/* Not part of the syscall payload; wasmos-platform-nanos checks this
 * at load time to detect a kernel/userspace mismatch.  Consult via a
 * dedicated auxv-shaped mechanism (out of scope for this driver). */
#define NANOS_TPM_STATUS_ABI_VERSION 1

/*
 * User-visible mirror of nanos_tpm_health.
 *
 * NOTE: this MUST NOT include kernel-internal types such as `int`
 * or `timestamp` directly - encode everything as fixed-width integers
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
 * Syscall entry points, using the standard Nanos syscall signature.
 * The dispatcher (src/unix/syscall.c syscall_handler) invokes these
 * with the raw register-loaded u64 values from the trap frame.
 *
 * nanos_sys_tpm_command args (user-visible):
 *   arg0 = const void *user_command
 *   arg1 = u64 command_length
 *   arg2 = void *user_response
 *   arg3 = u64 response_capacity
 *   arg4 = u64 *user_response_length
 *   arg5 = u64 timeout_ns  (0 => driver's per-instance default)
 *
 * Returns:
 *   0           on success; *user_response_length populated
 *   -EINVAL     malformed buffers or oversized transfer
 *   -ENOTSUP    TPM not initialized on this kernel
 *   -ETIMEDOUT  deadline exceeded
 *   -EIO        transport / hardware failure
 *   -EAGAIN     driver-busy (single-in-flight rejection)
 *   -EFAULT     a user pointer was not addressable
 *
 * nanos_sys_tpm_status args (user-visible):
 *   arg0 = struct nanos_tpm_status_abi *user_out
 *
 * Returns:
 *   0        on success; *user_out populated with the driver snapshot
 *   -EINVAL  user_out was NULL
 *   -EFAULT  user_out is not addressable
 */
sysreturn nanos_sys_tpm_command(u64 user_command,
                                u64 command_length,
                                u64 user_response,
                                u64 response_capacity,
                                u64 user_response_length,
                                u64 timeout_ns);

sysreturn nanos_sys_tpm_status(u64 user_out,
                               u64 arg1, u64 arg2, u64 arg3,
                               u64 arg4, u64 arg5);

/* Registration hook - called from register_other_syscalls() in
 * src/unix/unix.c. Registers the two new syscall handlers in the
 * given syscall dispatch table. */
void register_tpm_syscalls(struct syscall *map);
