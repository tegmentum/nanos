/*
 * WasmOS TPM syscall ABI — implementation
 *
 * INTENDED NANOS PATH: kernel/tpm/tpm_syscall.c
 *
 * Companion design: docs/design/nanos-tpm-crb-transport.md §5 in the
 * wasmos repository.  The two functions here are thin argument-
 * validation shims around the CRB driver in tpm_crb.c; they must
 * NEVER call into the driver with user pointers or with sizes they
 * have not themselves bounds-checked.
 */

#include "tpm_syscall.h"
#include "tpm_crb.h"

/* Match Nanos's errno convention (mirrors POSIX values). */
#define TPM_SYS_EINVAL     22
#define TPM_SYS_ENOTSUP    95
#define TPM_SYS_ETIMEDOUT 110
#define TPM_SYS_EIO         5
#define TPM_SYS_EAGAIN     11
#define TPM_SYS_EFAULT     14

/* Upper bound on a single command / response transfer accepted at the
 * syscall boundary.  This mirrors the driver's TPM_MAX_REASONABLE_BUFFER
 * (see tpm_crb.c) — kept here so the syscall can reject clearly-bogus
 * requests without ever touching the mutex. */
#define TPM_SYS_MAX_TRANSFER_BYTES (128u * 1024u)

static inline void secure_zero(void *p, u64 n)
{
    volatile u8 *b = (volatile u8 *)p;
    while (n--)
        *b++ = 0;
}

/* -------------------------------------------------------------------- */
/* User-pointer validation helpers.                                      */
/*                                                                       */
/* validate_user_range() is the ONLY interface between the syscall shim  */
/* and process memory — everything downstream operates on kernel-owned   */
/* buffers.  The exact implementation is Nanos-fork-specific; the       */
/* target Nanos SHA's syscall infrastructure will already have          */
/* equivalents.  Replace at integration time.                            */
/* -------------------------------------------------------------------- */

static boolean validate_user_range(process p, const void *addr, u64 len)
{
    /* TODO(nanos-integration): call into the target Nanos SHA's
     * VM-region validator; something like:
     *     return validate_user_memory(p, addr, len, VMAP_FLAG_USER);
     * The stub below assumes an existing helper. */
    return process_check_user_range(p, addr, len);
}

static status copy_from_user(process p, void *kdst, const void *usrc, u64 n)
{
    if (!validate_user_range(p, usrc, n))
        return TPM_ERR_INVAL;
    /* TODO(nanos-integration): use the target Nanos SHA's user-copy
     * primitive.  Failure to copy must return TPM_ERR_INVAL and NOT
     * dereference the user pointer directly. */
    if (!process_copy_from_user(p, kdst, usrc, n))
        return TPM_ERR_INVAL;
    return TPM_ERR_OK;
}

static status copy_to_user(process p, void *udst, const void *ksrc, u64 n)
{
    if (!validate_user_range(p, udst, n))
        return TPM_ERR_INVAL;
    if (!process_copy_to_user(p, udst, ksrc, n))
        return TPM_ERR_INVAL;
    return TPM_ERR_OK;
}

/* -------------------------------------------------------------------- */
/* Error mapping (design doc §5.2).                                      */
/* -------------------------------------------------------------------- */

static long map_driver_error(status s)
{
    switch (s) {
    case TPM_ERR_OK:         return 0;
    case TPM_ERR_INVAL:      return -TPM_SYS_EINVAL;
    case TPM_ERR_NO_DEVICE:  return -TPM_SYS_ENOTSUP;
    case TPM_ERR_TIMEDOUT:   return -TPM_SYS_ETIMEDOUT;
    case TPM_ERR_TRANSPORT:  return -TPM_SYS_EIO;
    case TPM_ERR_BUSY:       return -TPM_SYS_EAGAIN;
    case TPM_ERR_UNHEALTHY:  return -TPM_SYS_EIO;
    default:                 return -TPM_SYS_EIO;
    }
}

/* -------------------------------------------------------------------- */
/* nanos_sys_tpm_command                                                 */
/* -------------------------------------------------------------------- */

long nanos_sys_tpm_command(
    process p,
    const void *user_command,
    u64 command_length,
    void *user_response,
    u64 response_capacity,
    u64 *user_response_length,
    u64 timeout_ns)
{
    /* Argument validation happens BEFORE any allocation — cheap
     * rejection of obviously-malformed calls. */
    if (!user_command || !user_response || !user_response_length)
        return -TPM_SYS_EINVAL;
    if (command_length == 0 || command_length > TPM_SYS_MAX_TRANSFER_BYTES)
        return -TPM_SYS_EINVAL;
    if (response_capacity == 0 || response_capacity > TPM_SYS_MAX_TRANSFER_BYTES)
        return -TPM_SYS_EINVAL;

    nanos_tpm tpm = nanos_tpm_default();
    if (!tpm)
        return -TPM_SYS_ENOTSUP;

    /* Kernel-owned scratch buffers.  We copy in-and-out rather than
     * letting the driver touch user memory directly — this keeps the
     * MMIO layer trivially reviewable and defends against TOCTOU
     * concurrent-modification of user buffers during a transmit. */
    void *kcmd = allocate(command_length);
    if (!kcmd)
        return -TPM_SYS_EIO;
    void *krsp = allocate(response_capacity);
    if (!krsp) {
        deallocate(kcmd, command_length);
        return -TPM_SYS_EIO;
    }

    long ret;
    status s;

    s = copy_from_user(p, kcmd, user_command, command_length);
    if (s != TPM_ERR_OK) {
        ret = -TPM_SYS_EFAULT;
        goto out;
    }

    /* Deadline: 0 means "use the driver's per-instance default".
     * A non-zero value is treated as a nanosecond budget from now. */
    timestamp deadline = (timeout_ns == 0)
        ? TIMESTAMP_INFINITY  /* driver clamps against its own timeouts */
        : (now() + timeout_ns);

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
    s = copy_to_user(p, user_response_length, &ulen, sizeof(ulen));
    if (s != TPM_ERR_OK) {
        ret = -TPM_SYS_EFAULT;
        goto out;
    }
    s = copy_to_user(p, user_response, krsp, actual_len);
    if (s != TPM_ERR_OK) {
        ret = -TPM_SYS_EFAULT;
        goto out;
    }

    ret = 0;

out:
    /* Design doc §4.3: "Clear temporary buffers after use when they
     * may contain sensitive values."  Command may include auth
     * secrets; response may include sealed-blob plaintext. */
    secure_zero(kcmd, command_length);
    secure_zero(krsp, response_capacity);
    deallocate(kcmd, command_length);
    deallocate(krsp, response_capacity);
    return ret;
}

/* -------------------------------------------------------------------- */
/* nanos_sys_tpm_status                                                  */
/* -------------------------------------------------------------------- */

long nanos_sys_tpm_status(
    process p,
    struct nanos_tpm_status_abi *user_out)
{
    if (!user_out)
        return -TPM_SYS_EINVAL;

    struct nanos_tpm_status_abi snap;
    secure_zero(&snap, sizeof(snap));

    nanos_tpm tpm = nanos_tpm_default();
    if (!tpm) {
        /* Report an uninitialized-looking snapshot rather than -ENOTSUP
         * so wasmos-platform-nanos can distinguish "kernel doesn't
         * know about TPM" from "TPM present but not ready".  Callers
         * that need the distinction check .state against the enum. */
        snap.state          = 0; /* TPM_STATE_UNINITIALIZED */
        snap.interface_type = 0; /* TPM_INTERFACE_UNKNOWN */
        if (copy_to_user(p, user_out, &snap, sizeof(snap)) != TPM_ERR_OK)
            return -TPM_SYS_EFAULT;
        return 0;
    }

    nanos_tpm_health h;
    status s = nanos_tpm_get_health(tpm, &h);
    if (s != TPM_ERR_OK)
        return map_driver_error(s);

    snap.state             = (u32)h.state;
    snap.interface_type    = h.interface_type;
    snap.last_success_ns   = (u64)h.last_success;
    snap.last_error_class  = (u32)h.last_error;
    snap.max_command_size  = h.maximum_command_size;
    snap.max_response_size = h.maximum_response_size;
    snap.discovery_source  = (u32)tpm->discovery_source;

    if (copy_to_user(p, user_out, &snap, sizeof(snap)) != TPM_ERR_OK)
        return -TPM_SYS_EFAULT;
    return 0;
}
