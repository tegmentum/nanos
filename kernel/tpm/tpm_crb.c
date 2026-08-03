/*
 * WasmOS TPM 2.0 CRB transport driver — implementation
 *
 * INTENDED NANOS PATH: kernel/tpm/tpm_crb.c
 * (adjust to match the target Nanos SHA's kernel layout — this driver
 * is deliberately not wired into any Makefile; do that in the
 * integration commit for the target checkout).
 *
 * Companion design: docs/design/nanos-tpm-crb-transport.md §4 in the
 * wasmos repository. All section references below cite that doc.
 *
 * Invariants:
 *   - Single-in-flight transmit (serialized by command_lock).
 *   - Command/response sizes validated against CRB-reported maxima.
 *   - Response buffer length is bounds-checked against caller capacity
 *     BEFORE any bytes are copied out of the CRB region.
 *   - Temporary buffers holding potentially sensitive data are zeroed
 *     with an unwritable-through-optimizer helper.
 *   - No user pointer reaches this file directly — the syscall shim
 *     (see 0002-tpm-syscall-abi.patch) has already copied user data
 *     into kernel buffers before calling in.
 */

#include "tpm_crb.h"
#include "tpm_crb_mmio.h"

/* -------------------------------------------------------------------- */
/* Minimum plausible sizes.  A CRB device reporting less than this is   */
/* rejected during discovery as clearly malformed.                       */
/* -------------------------------------------------------------------- */

#define TPM2_HEADER_SIZE            10   /* tag(2) + size(4) + code(4) */
#define TPM_MIN_COMMAND_BUFFER      1024
#define TPM_MIN_RESPONSE_BUFFER     1024
#define TPM_MAX_REASONABLE_BUFFER   (128u * 1024u)

/* -------------------------------------------------------------------- */
/* Utility: constant-time zeroization.                                   */
/* -------------------------------------------------------------------- */

static void secure_zero(void *p, bytes n)
{
    volatile u8 *b = (volatile u8 *)p;
    while (n--)
        *b++ = 0;
}

/* -------------------------------------------------------------------- */
/* Register-access thin wrappers over the abstract ops table.           */
/* -------------------------------------------------------------------- */

static inline u32 reg32(nanos_tpm tpm, u64 off)
{
    return tpm->mmio_ops->read32(tpm->mmio_ops->cookie, off);
}

static inline void set32(nanos_tpm tpm, u64 off, u32 v)
{
    tpm->mmio_ops->write32(tpm->mmio_ops->cookie, off, v);
}

static inline u64 reg64(nanos_tpm tpm, u64 off)
{
    return tpm->mmio_ops->read64(tpm->mmio_ops->cookie, off);
}

static inline void mmio_mb(nanos_tpm tpm)
{
    tpm->mmio_ops->mb(tpm->mmio_ops->cookie);
}

/* -------------------------------------------------------------------- */
/* Interface validation (design doc §4.4).                               */
/* -------------------------------------------------------------------- */

static boolean crb_interface_plausible(nanos_tpm tpm)
{
    u32 lo = reg32(tpm, CRB_REG_INTF_ID_LO);
    u32 type = lo & CRB_INTF_ID_TYPE_MASK;

    if (type != CRB_INTF_ID_TYPE_CRB)
        return false;

    /* A device that reports zero for both command and response buffer
     * size is either uninitialized or masquerading; refuse it. */
    u32 cmd_sz = reg32(tpm, CRB_REG_CMD_SIZE);
    u32 rsp_sz = reg32(tpm, CRB_REG_RSP_SIZE);

    if (cmd_sz < TPM_MIN_COMMAND_BUFFER || cmd_sz > TPM_MAX_REASONABLE_BUFFER)
        return false;
    if (rsp_sz < TPM_MIN_RESPONSE_BUFFER || rsp_sz > TPM_MAX_REASONABLE_BUFFER)
        return false;

    tpm->maximum_command_size  = cmd_sz;
    tpm->maximum_response_size = rsp_sz;
    tpm->interface_type        = TPM_INTERFACE_CRB;
    return true;
}

/* -------------------------------------------------------------------- */
/* Discovery (design doc §4.4).                                          */
/* -------------------------------------------------------------------- */

static status try_discover_acpi(nanos_tpm tpm)
{
    /* TODO(nanos-integration): resolve ACPI TPM2 table -> mmio_base +
     * mmio_length via the target Nanos SHA's ACPI parser.  For now
     * this returns NO_DEVICE, prompting fallback. */
    (void)tpm;
    return TPM_ERR_NO_DEVICE;
}

static status try_discover_platform(nanos_tpm tpm)
{
    /* TODO(nanos-integration): consult the platform device description
     * table produced by the boot loader; hook depends on the target
     * Nanos SHA. */
    (void)tpm;
    return TPM_ERR_NO_DEVICE;
}

static status try_discover_manifest(nanos_tpm tpm)
{
    /* TODO(nanos-integration): consult the Nanos boot manifest for an
     * explicit tpm.crb.base / tpm.crb.length entry. */
    (void)tpm;
    return TPM_ERR_NO_DEVICE;
}

static status try_discover_qemu_fixed(nanos_tpm tpm)
{
    /* Final fallback per §4.4.  Map the standard x86 QEMU CRB base and
     * only accept it if crb_interface_plausible() succeeds. */
    void *mapped = map_mmio_region(CRB_QEMU_DEFAULT_MMIO_BASE,
                                   CRB_QEMU_DEFAULT_MMIO_LEN);
    if (!mapped)
        return TPM_ERR_NO_DEVICE;

    tpm->mmio_base   = mapped;
    tpm->mmio_length = CRB_QEMU_DEFAULT_MMIO_LEN;
    tpm->mmio_ops    = crb_mmio_ops_real(mapped, CRB_QEMU_DEFAULT_MMIO_LEN);

    if (!tpm->mmio_ops || !crb_interface_plausible(tpm)) {
        unmap_mmio_region(mapped, CRB_QEMU_DEFAULT_MMIO_LEN);
        tpm->mmio_base = 0;
        tpm->mmio_ops  = 0;
        return TPM_ERR_NO_DEVICE;
    }

    tpm->discovery_source = TPM_DISCOVERY_QEMU_FIXED;
    return TPM_ERR_OK;
}

status nanos_tpm_discover(nanos_tpm *out, const crb_mmio_ops *ops)
{
    if (!out)
        return TPM_ERR_INVAL;

    nanos_tpm tpm = allocate_zero(sizeof(*tpm));
    if (!tpm)
        return TPM_ERR_INTERNAL;

    tpm->state    = TPM_STATE_UNINITIALIZED;
    tpm->locality = 0;
    tpm->timeouts.locality_ns   = NANOS_TPM_DEFAULT_LOCALITY_NS;
    tpm->timeouts.readiness_ns  = NANOS_TPM_DEFAULT_READINESS_NS;
    tpm->timeouts.execution_ns  = NANOS_TPM_DEFAULT_EXECUTION_NS;
    tpm->timeouts.cancel_ns     = NANOS_TPM_DEFAULT_CANCEL_NS;
    tpm->timeouts.recovery_ns   = NANOS_TPM_DEFAULT_RECOVERY_NS;
    tpm->command_lock = mutex_new();

    /* Test-injected ops override the discovery pipeline entirely. */
    if (ops) {
        tpm->mmio_ops = ops;
        if (!crb_interface_plausible(tpm)) {
            mutex_free(tpm->command_lock);
            deallocate(tpm, sizeof(*tpm));
            return TPM_ERR_NO_DEVICE;
        }
        tpm->discovery_source = TPM_DISCOVERY_PLATFORM;
        tpm->state = TPM_STATE_DISCOVERED;
        *out = tpm;
        return TPM_ERR_OK;
    }

    /* Ordered discovery per §4.4. */
    status s = try_discover_acpi(tpm);
    if (s == TPM_ERR_NO_DEVICE)
        s = try_discover_platform(tpm);
    if (s == TPM_ERR_NO_DEVICE)
        s = try_discover_manifest(tpm);
    if (s == TPM_ERR_NO_DEVICE)
        s = try_discover_qemu_fixed(tpm);

    if (s != TPM_ERR_OK) {
        mutex_free(tpm->command_lock);
        deallocate(tpm, sizeof(*tpm));
        return s;
    }

    tpm->state = TPM_STATE_DISCOVERED;
    *out = tpm;
    return TPM_ERR_OK;
}

status nanos_tpm_configure(nanos_tpm tpm, const nanos_tpm_timeouts *t)
{
    if (!tpm || !t)
        return TPM_ERR_INVAL;
    /* Zero timeouts would freeze the driver; refuse. */
    if (!t->locality_ns || !t->readiness_ns || !t->execution_ns ||
        !t->cancel_ns || !t->recovery_ns)
        return TPM_ERR_INVAL;
    tpm->timeouts = *t;
    return TPM_ERR_OK;
}

void nanos_tpm_destroy(nanos_tpm tpm)
{
    if (!tpm)
        return;
    if (tpm->mmio_base && tpm->mmio_length)
        unmap_mmio_region(tpm->mmio_base, tpm->mmio_length);
    if (tpm->command_lock)
        mutex_free(tpm->command_lock);
    secure_zero(tpm, sizeof(*tpm));
    deallocate(tpm, sizeof(*tpm));
}

/* -------------------------------------------------------------------- */
/* Locality management.                                                  */
/* -------------------------------------------------------------------- */

static status crb_acquire_locality(nanos_tpm tpm, timestamp deadline)
{
    set32(tpm, CRB_REG_LOC_CTRL, CRB_LOC_CTRL_REQ_ACCESS);
    mmio_mb(tpm);

    timestamp t_end = deadline_min(deadline,
                                   now() + tpm->timeouts.locality_ns);
    while (now() < t_end) {
        u32 sts = reg32(tpm, CRB_REG_LOC_STS);
        if (sts & CRB_LOC_STS_GRANTED)
            return TPM_ERR_OK;
        kernel_yield();
    }
    return TPM_ERR_TIMEDOUT;
}

static void crb_release_locality(nanos_tpm tpm)
{
    set32(tpm, CRB_REG_LOC_CTRL, CRB_LOC_CTRL_RELINQUISH);
    mmio_mb(tpm);
}

/* -------------------------------------------------------------------- */
/* Command readiness.                                                    */
/* -------------------------------------------------------------------- */

static status crb_wait_ready(nanos_tpm tpm, timestamp deadline)
{
    set32(tpm, CRB_REG_CTRL_REQ, CRB_CTRL_REQ_CMD_READY);
    mmio_mb(tpm);

    timestamp t_end = deadline_min(deadline,
                                   now() + tpm->timeouts.readiness_ns);
    while (now() < t_end) {
        u32 sts = reg32(tpm, CRB_REG_CTRL_STS);
        if (sts & CRB_CTRL_STS_ERROR)
            return TPM_ERR_TRANSPORT;
        if (!(sts & CRB_CTRL_STS_IDLE))
            return TPM_ERR_OK;
        kernel_yield();
    }
    return TPM_ERR_TIMEDOUT;
}

/* -------------------------------------------------------------------- */
/* Command execution wait.                                               */
/* -------------------------------------------------------------------- */

static status crb_wait_completion(nanos_tpm tpm, timestamp deadline)
{
    while (now() < deadline) {
        u32 sts = reg32(tpm, CRB_REG_CTRL_STS);
        if (sts & CRB_CTRL_STS_ERROR)
            return TPM_ERR_TRANSPORT;
        u32 start = reg32(tpm, CRB_REG_CTRL_START);
        if ((start & CRB_CTRL_START) == 0)
            return TPM_ERR_OK;
        kernel_yield();
    }
    return TPM_ERR_TIMEDOUT;
}

/* -------------------------------------------------------------------- */
/* Response length extraction — bounds-checked against caller capacity. */
/* -------------------------------------------------------------------- */

static status crb_extract_response_length(nanos_tpm tpm,
                                          bytes response_capacity,
                                          bytes *out_len)
{
    /* TPM 2.0 response header layout:
     *   [0..1] tag (u16 BE)
     *   [2..5] responseSize (u32 BE) — total including header
     *   [6..9] responseCode (u32 BE)
     */
    u8 hdr[TPM2_HEADER_SIZE];
    tpm->mmio_ops->read_bytes(tpm->mmio_ops->cookie,
                              CRB_REG_RSP_LOW, hdr, sizeof(hdr));
    bytes len = ((bytes)hdr[2] << 24) | ((bytes)hdr[3] << 16) |
                ((bytes)hdr[4] <<  8) | ((bytes)hdr[5]);
    if (len < TPM2_HEADER_SIZE || len > tpm->maximum_response_size)
        return TPM_ERR_TRANSPORT;
    if (len > response_capacity)
        return TPM_ERR_INVAL;
    *out_len = len;
    return TPM_ERR_OK;
}

/* -------------------------------------------------------------------- */
/* Transmit (design doc §4.3).                                           */
/* -------------------------------------------------------------------- */

status nanos_tpm_transmit(
    nanos_tpm tpm,
    const void *command,
    bytes command_length,
    void *response,
    bytes response_capacity,
    bytes *response_length,
    timestamp deadline)
{
    if (!tpm || !command || !response || !response_length)
        return TPM_ERR_INVAL;
    if (command_length < TPM2_HEADER_SIZE)
        return TPM_ERR_INVAL;
    if (command_length > tpm->maximum_command_size)
        return TPM_ERR_INVAL;
    if (response_capacity < TPM2_HEADER_SIZE)
        return TPM_ERR_INVAL;
    if (response_capacity > TPM_MAX_REASONABLE_BUFFER)
        return TPM_ERR_INVAL;

    if (tpm->state == TPM_STATE_FAILED)
        return TPM_ERR_UNHEALTHY;
    if (tpm->state == TPM_STATE_UNINITIALIZED ||
        tpm->state == TPM_STATE_DISCOVERED  ||
        tpm->state == TPM_STATE_SHUTDOWN)
        return TPM_ERR_NO_DEVICE;

    /* Single-in-flight enforcement per §4.3. */
    if (!mutex_try_lock(tpm->command_lock))
        return TPM_ERR_BUSY;

    status s;
    tpm->state = TPM_STATE_BUSY;

    /* Effective deadline is the tighter of (caller deadline,
     * per-instance execution timeout). */
    timestamp effective_deadline =
        deadline_min(deadline, now() + tpm->timeouts.execution_ns);

    s = crb_acquire_locality(tpm, effective_deadline);
    if (s != TPM_ERR_OK)
        goto out;

    s = crb_wait_ready(tpm, effective_deadline);
    if (s != TPM_ERR_OK)
        goto release_loc;

    /* Write the command into the CRB command buffer. */
    tpm->mmio_ops->write_bytes(tpm->mmio_ops->cookie,
                               CRB_REG_CMD_LOW, command, command_length);
    mmio_mb(tpm);

    /* Kick off execution. */
    set32(tpm, CRB_REG_CTRL_START, CRB_CTRL_START);
    mmio_mb(tpm);

    s = crb_wait_completion(tpm, effective_deadline);
    if (s != TPM_ERR_OK)
        goto release_loc;

    /* Extract length with bounds check BEFORE copying bytes out. */
    s = crb_extract_response_length(tpm, response_capacity, response_length);
    if (s != TPM_ERR_OK)
        goto release_loc;

    tpm->mmio_ops->read_bytes(tpm->mmio_ops->cookie,
                              CRB_REG_RSP_LOW, response, *response_length);

    tpm->last_success = now();

release_loc:
    crb_release_locality(tpm);

out:
    if (s == TPM_ERR_OK)
        tpm->state = TPM_STATE_READY;
    else if (s == TPM_ERR_TIMEDOUT || s == TPM_ERR_TRANSPORT)
        tpm->state = TPM_STATE_FAILED; /* caller may invoke recover() */
    else
        tpm->state = TPM_STATE_READY;

    tpm->last_error = s;
    mutex_unlock(tpm->command_lock);
    return s;
}

/* -------------------------------------------------------------------- */
/* Recovery (design doc §4.5).                                           */
/* -------------------------------------------------------------------- */

static status crb_cancel(nanos_tpm tpm)
{
    set32(tpm, CRB_REG_CTRL_CANCEL, CRB_CTRL_CANCEL_YES);
    mmio_mb(tpm);

    timestamp t_end = now() + tpm->timeouts.cancel_ns;
    while (now() < t_end) {
        u32 start = reg32(tpm, CRB_REG_CTRL_START);
        if ((start & CRB_CTRL_START) == 0) {
            set32(tpm, CRB_REG_CTRL_CANCEL, CRB_CTRL_CANCEL_NO);
            mmio_mb(tpm);
            return TPM_ERR_OK;
        }
        kernel_yield();
    }
    set32(tpm, CRB_REG_CTRL_CANCEL, CRB_CTRL_CANCEL_NO);
    mmio_mb(tpm);
    return TPM_ERR_TIMEDOUT;
}

status nanos_tpm_recover(nanos_tpm tpm)
{
    if (!tpm)
        return TPM_ERR_INVAL;

    mutex_lock(tpm->command_lock);

    timestamp end = now() + tpm->timeouts.recovery_ns;
    status s;

    /* Step 1 — Attempt CRB cancellation. */
    s = crb_cancel(tpm);
    if (s != TPM_ERR_OK && now() >= end)
        goto fail;

    /* Step 2 — Reset driver-local state. */
    tpm->locality      = 0;
    tpm->last_error    = TPM_ERR_OK;

    /* Step 3 — Revalidate interface registers. */
    if (!crb_interface_plausible(tpm))
        goto fail;

    tpm->state = TPM_STATE_READY;
    mutex_unlock(tpm->command_lock);
    return TPM_ERR_OK;

fail:
    /* Step 4 — Mark unhealthy; further calls will be rejected. */
    tpm->state      = TPM_STATE_FAILED;
    tpm->last_error = TPM_ERR_UNHEALTHY;
    mutex_unlock(tpm->command_lock);
    return TPM_ERR_UNHEALTHY;
}

status nanos_tpm_reinitialize(nanos_tpm tpm)
{
    if (!tpm)
        return TPM_ERR_INVAL;

    mutex_lock(tpm->command_lock);

    /* Reset state; caller is responsible for evaluating deployment
     * policy before invoking this — see §4.5. */
    tpm->state      = TPM_STATE_UNINITIALIZED;
    tpm->locality   = 0;
    tpm->last_error = TPM_ERR_OK;

    if (!crb_interface_plausible(tpm)) {
        tpm->state      = TPM_STATE_FAILED;
        tpm->last_error = TPM_ERR_UNHEALTHY;
        mutex_unlock(tpm->command_lock);
        return TPM_ERR_UNHEALTHY;
    }

    tpm->state = TPM_STATE_READY;
    mutex_unlock(tpm->command_lock);
    return TPM_ERR_OK;
}

/* -------------------------------------------------------------------- */
/* Health snapshot (design doc §5.3).                                    */
/* -------------------------------------------------------------------- */

status nanos_tpm_get_health(nanos_tpm tpm, nanos_tpm_health *out)
{
    if (!tpm || !out)
        return TPM_ERR_INVAL;

    out->state                 = tpm->state;
    out->interface_type        = tpm->interface_type;
    out->last_success          = tpm->last_success;
    out->last_error            = tpm->last_error;
    out->maximum_command_size  = tpm->maximum_command_size;
    out->maximum_response_size = tpm->maximum_response_size;
    return TPM_ERR_OK;
}

/* -------------------------------------------------------------------- */
/* Global default instance — used by the syscall shim in patch 0002.    */
/* Kernel init (integration commit) is expected to:                     */
/*   1. call nanos_tpm_discover(&tpm, NULL)                              */
/*   2. call nanos_tpm_set_default(tpm)                                  */
/* Failure to discover leaves the default at NULL, in which case the    */
/* syscall returns -ENOTSUP.                                             */
/* -------------------------------------------------------------------- */

static nanos_tpm the_default_tpm = 0;

nanos_tpm nanos_tpm_default(void)
{
    return the_default_tpm;
}

void nanos_tpm_set_default(nanos_tpm tpm)
{
    the_default_tpm = tpm;
}

/* -------------------------------------------------------------------- */
/* Real MMIO ops table (production).                                    */
/* -------------------------------------------------------------------- */

static u32  real_read32 (void *c, u64 off)               { return *(volatile u32 *)((u8 *)c + off); }
static void real_write32(void *c, u64 off, u32 v)        { *(volatile u32 *)((u8 *)c + off) = v; }
static u64  real_read64 (void *c, u64 off)               { return *(volatile u64 *)((u8 *)c + off); }
static void real_write64(void *c, u64 off, u64 v)        { *(volatile u64 *)((u8 *)c + off) = v; }
static void real_readbs (void *c, u64 off, void *d, bytes n) { runtime_memcpy(d, (u8 *)c + off, n); }
static void real_writebs(void *c, u64 off, const void *s, bytes n) { runtime_memcpy((u8 *)c + off, s, n); }
static void real_mb     (void *c)                         { (void)c; memory_barrier(); }

static crb_mmio_ops g_real_ops;

const crb_mmio_ops *crb_mmio_ops_real(void *virt_base, u64 length)
{
    (void)length;
    if (!virt_base)
        return 0;
    g_real_ops.read32      = real_read32;
    g_real_ops.write32     = real_write32;
    g_real_ops.read64      = real_read64;
    g_real_ops.write64     = real_write64;
    g_real_ops.read_bytes  = real_readbs;
    g_real_ops.write_bytes = real_writebs;
    g_real_ops.mb          = real_mb;
    g_real_ops.cookie      = virt_base;
    return &g_real_ops;
}
