/*
 * tpm_crb_fake_mmio.c - table-driven fake CRB register-access shim
 *
 * NANOS PATH: test/unit/tpm_crb_fake_mmio.c
 *
 * Backs a `struct crb_mmio_ops` (see src/tpm/tpm_crb_mmio.h) with an
 * in-memory register table and a transcript of every access.  See the
 * header for the shim's design intent and modes.
 */

#include <runtime.h>
#include <tpm/tpm_crb_mmio.h>
#include "tpm_crb_fake_mmio.h"

/* -------------------------------------------------------------------- */
/* Transcript recording.                                                 */
/* -------------------------------------------------------------------- */

static void record(tpm_crb_fake_state *s, u64 offset, u32 value, boolean is_write)
{
    if (s->transcript_len < TPM_CRB_FAKE_MMIO_TRANSCRIPT_ENTRIES) {
        tpm_crb_fake_transcript_entry *e = &s->transcript[s->transcript_len++];
        e->offset   = offset;
        e->value    = value;
        e->is_write = is_write;
    }
}

/* -------------------------------------------------------------------- */
/* Register-space helpers (little-endian, matching the CRB spec).        */
/* -------------------------------------------------------------------- */

static u32 rd32(tpm_crb_fake_state *s, u64 off)
{
    if (off + 4 > TPM_CRB_FAKE_MMIO_REG_TABLE_BYTES)
        return 0;
    return  ((u32)s->regs[off + 0]      ) |
            ((u32)s->regs[off + 1] <<  8) |
            ((u32)s->regs[off + 2] << 16) |
            ((u32)s->regs[off + 3] << 24);
}

static void wr32(tpm_crb_fake_state *s, u64 off, u32 v)
{
    if (off + 4 > TPM_CRB_FAKE_MMIO_REG_TABLE_BYTES)
        return;
    s->regs[off + 0] = (u8)(v      );
    s->regs[off + 1] = (u8)(v >>  8);
    s->regs[off + 2] = (u8)(v >> 16);
    s->regs[off + 3] = (u8)(v >> 24);
}

/* -------------------------------------------------------------------- */
/* Ops-table callbacks.                                                  */
/* -------------------------------------------------------------------- */

static u32 op_read32(void *cookie, u64 off)
{
    tpm_crb_fake_state *s = (tpm_crb_fake_state *)cookie;
    u32 v = rd32(s, off);

    /* Mode-specific dynamic overrides. */
    if (off == CRB_REG_CTRL_STS) {
        switch (s->mode) {
        case TPM_CRB_FAKE_MODE_STUCK_BUSY:
            v |= CRB_CTRL_STS_IDLE; /* never leaves idle */
            break;
        case TPM_CRB_FAKE_MODE_ERROR_LATCHED:
            v |= CRB_CTRL_STS_ERROR;
            break;
        default:
            break;
        }
    }
    if (off == CRB_REG_CTRL_START) {
        if (s->mode == TPM_CRB_FAKE_MODE_STUCK_EXECUTING) {
            v |= CRB_CTRL_START;
        } else if (s->execution_ticks_remaining > 0) {
            s->execution_ticks_remaining--;
            v |= CRB_CTRL_START;
        } else {
            v &= ~CRB_CTRL_START;
        }
    }
    record(s, off, v, false);
    return v;
}

static void op_write32(void *cookie, u64 off, u32 v)
{
    tpm_crb_fake_state *s = (tpm_crb_fake_state *)cookie;
    wr32(s, off, v);
    record(s, off, v, true);

    /* Cross-register side effects. */
    if (off == CRB_REG_LOC_CTRL && (v & CRB_LOC_CTRL_REQ_ACCESS))
        wr32(s, CRB_REG_LOC_STS, CRB_LOC_STS_GRANTED);
    if (off == CRB_REG_CTRL_START && (v & CRB_CTRL_START))
        s->execution_ticks_remaining = 2; /* 2 poll ticks -> complete */
}

static u64 op_read64(void *cookie, u64 off)
{
    u32 lo = op_read32(cookie, off);
    u32 hi = op_read32(cookie, off + 4);
    return ((u64)hi << 32) | lo;
}

static void op_write64(void *cookie, u64 off, u64 v)
{
    op_write32(cookie, off,     (u32)(v      ));
    op_write32(cookie, off + 4, (u32)(v >> 32));
}

static void op_read_bytes(void *cookie, u64 off, void *dst, bytes n)
{
    tpm_crb_fake_state *s = (tpm_crb_fake_state *)cookie;
    if (off + n > TPM_CRB_FAKE_MMIO_BUF_BYTES)
        return;
    for (bytes i = 0; i < n; ++i)
        ((u8 *)dst)[i] = s->buf[off + i];
}

static void op_write_bytes(void *cookie, u64 off, const void *src, bytes n)
{
    tpm_crb_fake_state *s = (tpm_crb_fake_state *)cookie;
    if (off + n > TPM_CRB_FAKE_MMIO_BUF_BYTES)
        return;
    for (bytes i = 0; i < n; ++i)
        s->buf[off + i] = ((const u8 *)src)[i];
}

static void op_mb(void *cookie) { (void)cookie; }

/* -------------------------------------------------------------------- */
/* Public API.                                                           */
/* -------------------------------------------------------------------- */

static crb_mmio_ops fake_ops_singleton;

const crb_mmio_ops *tpm_crb_fake_ops(tpm_crb_fake_state *state)
{
    fake_ops_singleton.read32      = op_read32;
    fake_ops_singleton.write32     = op_write32;
    fake_ops_singleton.read64      = op_read64;
    fake_ops_singleton.write64     = op_write64;
    fake_ops_singleton.read_bytes  = op_read_bytes;
    fake_ops_singleton.write_bytes = op_write_bytes;
    fake_ops_singleton.mb          = op_mb;
    fake_ops_singleton.cookie      = state;
    return &fake_ops_singleton;
}

void tpm_crb_fake_reset(tpm_crb_fake_state *state, tpm_crb_fake_mode mode)
{
    for (u32 i = 0; i < TPM_CRB_FAKE_MMIO_REG_TABLE_BYTES; ++i) state->regs[i] = 0;
    for (u32 i = 0; i < TPM_CRB_FAKE_MMIO_BUF_BYTES;       ++i) state->buf [i] = 0;
    state->transcript_len            = 0;
    state->execution_ticks_remaining = 0;
    state->mode = mode;

    /* Plausible ready-to-use CRB device. */
    wr32(state, CRB_REG_INTF_ID_LO,
         CRB_INTF_ID_TYPE_CRB | CRB_INTF_ID_CAP_LOCALITY);
    wr32(state, CRB_REG_CMD_SIZE, 4096);
    wr32(state, CRB_REG_RSP_SIZE, 4096);
    wr32(state, CRB_REG_CTRL_STS, 0);
}

boolean tpm_crb_fake_seed_response(tpm_crb_fake_state *state,
                                   const void *bytes_in, u64 n)
{
    if (n > (TPM_CRB_FAKE_MMIO_BUF_BYTES - (u64)CRB_REG_RSP_LOW))
        return false;
    for (u64 i = 0; i < n; ++i)
        state->buf[CRB_REG_RSP_LOW + i] = ((const u8 *)bytes_in)[i];
    return true;
}
