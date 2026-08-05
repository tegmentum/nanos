/*
 * WasmOS TPM syscall ABI - implementation
 *
 * NANOS PATH: src/tpm/tpm_syscall.c
 *
 * Companion design: docs/design/nanos-tpm-crb-transport.md sec 5 in the
 * wasmos repository.  The two functions here are thin argument-
 * validation shims around the CRB driver in tpm_crb.c; they must
 * NEVER call into the driver with user pointers or with sizes they
 * have not themselves bounds-checked.
 *
 * Nanos integration notes:
 *   - We use Nanos's canonical copy_from_user / copy_to_user helpers
 *     (see src/unix/unix_internal.h) and validate_process_memory() for
 *     range validation. The current process is obtained via `current->p`.
 *   - Nanos syscall handlers are `sysreturn (u64,u64,u64,u64,u64,u64)`;
 *     the second syscall takes only one user argument and pads with
 *     unused slots so the dispatcher signature matches.
 *   - Errno constants come from Nanos's per-arch errno.h (pulled in via
 *     unix_internal.h). No local #define for TPM_SYS_* is needed.
 */

/* unix_internal.h itself pulls in <kernel.h> (and hence <runtime.h>);
 * including <kernel.h> a second time here would re-enter the header
 * without guards and confuse forward declarations. */
#include <unix_internal.h>
#include <tpm/tpm_crb.h>
#include <tpm/tpm_syscall.h>

/* Upper bound on a single command / response transfer accepted at the
 * syscall boundary.  This mirrors the driver's TPM_MAX_REASONABLE_BUFFER
 * (see tpm_crb.c) - kept here so the syscall can reject clearly-bogus
 * requests without ever touching the mutex. */
#define TPM_SYS_MAX_TRANSFER_BYTES (128u * 1024u)

static inline void secure_zero(void *p, u64 n)
{
    volatile u8 *b = (volatile u8 *)p;
    while (n--)
        *b++ = 0;
}

static inline heap tpm_sys_heap(void)
{
    return heap_locked(get_kernel_heaps());
}

/* -------------------------------------------------------------------- */
/* Error mapping (design doc sec 5.2).                                   */
/* -------------------------------------------------------------------- */

static sysreturn map_driver_error(int s)
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
/* nanos_sys_tpm_command                                                 */
/* -------------------------------------------------------------------- */

sysreturn nanos_sys_tpm_command(u64 user_command,
                                u64 command_length,
                                u64 user_response,
                                u64 response_capacity,
                                u64 user_response_length,
                                u64 timeout_ns)
{
    /* Argument validation happens BEFORE any allocation - cheap
     * rejection of obviously-malformed calls. */
    if (!user_command || !user_response || !user_response_length)
        return -EINVAL;
    if (command_length == 0 || command_length > TPM_SYS_MAX_TRANSFER_BYTES)
        return -EINVAL;
    if (response_capacity == 0 || response_capacity > TPM_SYS_MAX_TRANSFER_BYTES)
        return -EINVAL;

    process p = current->p;
    if (!validate_process_memory(p, pointer_from_u64(user_command),
                                 command_length, false) ||
        !validate_process_memory(p, pointer_from_u64(user_response),
                                 response_capacity, true) ||
        !validate_process_memory(p, pointer_from_u64(user_response_length),
                                 sizeof(u64), true))
        return -EFAULT;

    nanos_tpm tpm = nanos_tpm_default();
    if (!tpm)
        return -EOPNOTSUPP;

    /* Kernel-owned scratch buffers.  We copy in-and-out rather than
     * letting the driver touch user memory directly - this keeps the
     * MMIO layer trivially reviewable and defends against TOCTOU
     * concurrent-modification of user buffers during a transmit. */
    heap h = tpm_sys_heap();
    void *kcmd = allocate(h, command_length);
    if (kcmd == INVALID_ADDRESS)
        return -EIO;
    void *krsp = allocate(h, response_capacity);
    if (krsp == INVALID_ADDRESS) {
        deallocate(h, kcmd, command_length);
        return -EIO;
    }

    sysreturn ret;
    int s;

    if (!copy_from_user(pointer_from_u64(user_command), kcmd, command_length)) {
        ret = -EFAULT;
        goto out;
    }

    /* Deadline: 0 means "use the driver's per-instance default".
     * A non-zero value is treated as a nanosecond budget from now;
     * the driver converts to a Nanos-format timestamp internally. */
    timestamp deadline;
    if (timeout_ns == 0)
        deadline = 0;
    else
        deadline = now(CLOCK_ID_MONOTONIC_RAW) + nanoseconds(timeout_ns);

    bytes actual_len = 0;
    s = nanos_tpm_transmit(tpm,
                           kcmd, (bytes)command_length,
                           krsp, (bytes)response_capacity,
                           &actual_len,
                           deadline);

    if (s != TPM_ERR_OK) {
        ret = map_driver_error(s);
        goto out;
    }

    /* Copy response length and body back to userspace. */
    u64 ulen = (u64)actual_len;
    if (!copy_to_user(pointer_from_u64(user_response_length), &ulen, sizeof(ulen))) {
        ret = -EFAULT;
        goto out;
    }
    if (!copy_to_user(pointer_from_u64(user_response), krsp, actual_len)) {
        ret = -EFAULT;
        goto out;
    }

    ret = 0;

out:
    /* Design doc sec 4.3: "Clear temporary buffers after use when they
     * may contain sensitive values."  Command may include auth
     * secrets; response may include sealed-blob plaintext. */
    secure_zero(kcmd, command_length);
    secure_zero(krsp, response_capacity);
    deallocate(h, kcmd, command_length);
    deallocate(h, krsp, response_capacity);
    return ret;
}

/* -------------------------------------------------------------------- */
/* nanos_sys_tpm_status                                                  */
/* -------------------------------------------------------------------- */

sysreturn nanos_sys_tpm_status(u64 user_out,
                               u64 arg1, u64 arg2, u64 arg3,
                               u64 arg4, u64 arg5)
{
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (!user_out)
        return -EINVAL;

    process p = current->p;
    if (!validate_process_memory(p, pointer_from_u64(user_out),
                                 sizeof(struct nanos_tpm_status_abi), true))
        return -EFAULT;

    struct nanos_tpm_status_abi snap;
    secure_zero(&snap, sizeof(snap));

    nanos_tpm tpm = nanos_tpm_default();
    if (!tpm) {
        /* Report an uninitialized-looking snapshot rather than -EOPNOTSUPP
         * so wasmos-platform-nanos can distinguish "kernel doesn't
         * know about TPM" from "TPM present but not ready".  Callers
         * that need the distinction check .state against the enum. */
        snap.state          = TPM_STATE_UNINITIALIZED;
        snap.interface_type = TPM_INTERFACE_UNKNOWN;
        if (!copy_to_user(pointer_from_u64(user_out), &snap, sizeof(snap)))
            return -EFAULT;
        return 0;
    }

    nanos_tpm_health h;
    int s = nanos_tpm_get_health(tpm, &h);
    if (s != TPM_ERR_OK)
        return map_driver_error(s);

    snap.state             = (u32)h.state;
    snap.interface_type    = h.interface_type;
    snap.last_success_ns   = nsec_from_timestamp(h.last_success);
    snap.last_error_class  = (u32)h.last_error;
    snap.max_command_size  = h.maximum_command_size;
    snap.max_response_size = h.maximum_response_size;
    /* discovery_source is not part of the health snapshot; read it
     * directly from the tpm object (single-word read, no race that
     * matters for a self-reporting probe). */
    snap.discovery_source  = (u32)tpm->discovery_source;

    if (!copy_to_user(pointer_from_u64(user_out), &snap, sizeof(snap)))
        return -EFAULT;
    return 0;
}

/* -------------------------------------------------------------------- */
/* Syscall registration.                                                 */
/*                                                                       */
/* Called from register_other_syscalls() in src/unix/unix.c. Uses the    */
/* raw _register_syscall() to avoid depending on the register_syscall()  */
/* convenience macro (which pastes SYS_ prefixes and would collide with  */
/* the unfamiliar identifier under some code paths).                     */
/* -------------------------------------------------------------------- */

void register_tpm_syscalls(struct syscall *map)
{
    _register_syscall(map, SYS_nanos_tpm_command,
                      (sysreturn (*)())nanos_sys_tpm_command);
    _register_syscall(map, SYS_nanos_tpm_status,
                      (sysreturn (*)())nanos_sys_tpm_status);
}
