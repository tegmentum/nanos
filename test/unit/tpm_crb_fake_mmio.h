/*
 * tpm_crb_fake_mmio.h - table-driven fake CRB register-access shim
 *
 * NANOS PATH: test/unit/tpm_crb_fake_mmio.h
 *
 * Design doc (wasmos): docs/design/nanos-tpm-crb-transport.md sec 8.1 -
 * "The CRB register layer MUST be abstracted so tests can substitute a
 * fake MMIO implementation - real hardware in unit tests is a
 * non-starter."
 *
 * This shim backs a `struct crb_mmio_ops` (see src/tpm/tpm_crb_mmio.h)
 * with an in-memory register table and a transcript of every access, so
 * tests can:
 *   - Assert on the exact sequence of writes issued by the driver.
 *   - Simulate a device that never asserts CTRL_STS_IDLE (to test
 *     timeouts).
 *   - Simulate a device that returns a truncated response header (to
 *     test bounds checking).
 *   - Simulate CRB_CTRL_STS_ERROR to exercise the recovery path.
 *
 * Nanos header convention: no include guards; the .c that includes this
 * header MUST also have already brought in <runtime.h> and
 * <tpm/tpm_crb_mmio.h>.
 */

#define TPM_CRB_FAKE_MMIO_REG_TABLE_BYTES   0x1000
#define TPM_CRB_FAKE_MMIO_BUF_BYTES         0x4000
#define TPM_CRB_FAKE_MMIO_TRANSCRIPT_ENTRIES  1024

typedef enum {
    TPM_CRB_FAKE_MODE_NORMAL           = 0,
    TPM_CRB_FAKE_MODE_STUCK_BUSY       = 1,  /* CTRL_STS_IDLE never clears  */
    TPM_CRB_FAKE_MODE_STUCK_EXECUTING  = 2,  /* CTRL_START never clears     */
    TPM_CRB_FAKE_MODE_ERROR_LATCHED    = 3,  /* CTRL_STS_ERROR always set   */
} tpm_crb_fake_mode;

typedef struct tpm_crb_fake_transcript_entry {
    u64  offset;
    u32  value;
    boolean is_write;
} tpm_crb_fake_transcript_entry;

typedef struct tpm_crb_fake_state {
    u8  regs[TPM_CRB_FAKE_MMIO_REG_TABLE_BYTES];
    u8  buf [TPM_CRB_FAKE_MMIO_BUF_BYTES];
    tpm_crb_fake_mode mode;
    u32 execution_ticks_remaining;

    /* Transcript ring - grows monotonically until reset. */
    tpm_crb_fake_transcript_entry transcript[TPM_CRB_FAKE_MMIO_TRANSCRIPT_ENTRIES];
    u32 transcript_len;
} tpm_crb_fake_state;

/* Reset to a plausible ready-to-transmit CRB device:
 *   - INTF_ID_LO reports CRB with locality supported.
 *   - CMD_SIZE / RSP_SIZE = 4096.
 *   - LOC_STS = granted on any LOC_CTRL request-access write.
 *   - CTRL_STS = idle-cleared (i.e. ready to accept commands).
 * Then applies the given mode. */
void tpm_crb_fake_reset(tpm_crb_fake_state *state, tpm_crb_fake_mode mode);

/* Construct a fake ops table backed by `state`. The returned pointer is
 * valid for the lifetime of `state`. */
const crb_mmio_ops *tpm_crb_fake_ops(tpm_crb_fake_state *state);

/* Seed response bytes into the command/response buffer region so the
 * driver's read-response path finds them. Returns false on out-of-range
 * writes so tests can assert the shim rejects malformed inputs. */
boolean tpm_crb_fake_seed_response(tpm_crb_fake_state *state,
                                   const void *bytes_in, u64 n);
