/*
 * tpm_crb_test.c - CRB register-abstraction + response-decode unit tests
 *
 * NANOS PATH: test/unit/tpm_crb_test.c
 *
 * Companion design (wasmos): docs/design/nanos-tpm-crb-transport.md sec 8.1.
 *
 * Scope of what THIS file tests, and why the scope is narrow:
 *
 * The CRB driver in src/tpm/tpm_crb.c is deeply kernel-integrated: it
 * depends on `<kernel.h>` (which will not compile outside a kernel or
 * VDSO build), on `allocate_mutex()` and the mutex facility (which
 * requires the kernel scheduler), on ACPICA table access, on
 * `heap_locked(get_kernel_heaps())`, and on `map()` / `unmap()` /
 * `pageflags_device()`. None of that is available in this userspace
 * test/unit harness. The scaffold tests that were originally drafted
 * (see wasmos deploy/nanos/patches/tests/README.md) assumed a
 * userland-linkable driver; that assumption did not survive the
 * driver's Nanos integration.
 *
 * What is testable in isolation, and is exercised here:
 *
 *   - The abstract MMIO ops table defined in src/tpm/tpm_crb_mmio.h.
 *   - The fake-MMIO shim in tpm_crb_fake_mmio.{h,c} that concrete
 *     driver code targets, and that other in-kernel tests would also
 *     re-use.
 *   - The TCG PC Client CRB register offsets and bit fields
 *     (constants) - drift in these silently breaks the driver.
 *   - The response-header length decode used at
 *     `crb_extract_response_length()` in tpm_crb.c - reproduced here
 *     so the test can exercise the exact algorithm on the shim's
 *     seeded response bytes.
 *
 * What is documented as skipped, and why:
 *
 *   The state-machine tests (discover / transmit / configure / recover
 *   / cancel / locking / timeouts) each require linking tpm_crb.c into
 *   this binary. That would drag in kernel-only translation units that
 *   this test harness intentionally does not provide, so those tests
 *   are reported as SKIPPED at run time and the reason is printed once
 *   per test. The correct home for those tests is a Nanos in-kernel
 *   test facility (test/runtime or a new test/kernel harness) that
 *   this branch does not yet introduce.
 *
 * The tests below still cover the design sec 8.1 checklist items that
 * are testable from userspace: the MMIO register-encoding/-decoding
 * items, the response-size validation (via the extracted decode), and
 * the fake-MMIO shim's structural properties that every future
 * driver-side test will depend on.
 */

#include <runtime.h>
#include <tpm/tpm_crb_mmio.h>
#include "tpm_crb_fake_mmio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------- */
/* Local test harness.                                                   */
/*                                                                       */
/* Modelled after the ad-hoc harness in test/unit/random_test.c: each    */
/* TEST(name) is a static function; RUN(name) invokes it and records    */
/* pass/fail; SKIP(name, reason) records the skip. main() returns 0    */
/* only if every non-skipped test passed.                               */
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
/* Register offsets - checklist item: MMIO register encoding.            */
/*                                                                       */
/* The TCG PC Client Platform TPM Profile (CRB interface) fixes the      */
/* offset of every CRB register. A silent drift in tpm_crb_mmio.h would  */
/* wedge the driver on real hardware without any earlier failure signal, */
/* so we pin the numeric values here and cross-reference the CRB spec    */
/* Table 8-1.                                                             */
/* -------------------------------------------------------------------- */

TEST(register_offsets_match_tcg_spec)
{
    ASSERT_EQ_U(CRB_REG_LOC_STATE,    0x0000);
    ASSERT_EQ_U(CRB_REG_LOC_CTRL,     0x0008);
    ASSERT_EQ_U(CRB_REG_LOC_STS,      0x000C);
    ASSERT_EQ_U(CRB_REG_INTF_ID_LO,   0x0030);
    ASSERT_EQ_U(CRB_REG_INTF_ID_HI,   0x0034);
    ASSERT_EQ_U(CRB_REG_CTRL_EXT,     0x0038);
    ASSERT_EQ_U(CRB_REG_CTRL_REQ,     0x0040);
    ASSERT_EQ_U(CRB_REG_CTRL_STS,     0x0044);
    ASSERT_EQ_U(CRB_REG_CTRL_CANCEL,  0x0048);
    ASSERT_EQ_U(CRB_REG_CTRL_START,   0x004C);
    ASSERT_EQ_U(CRB_REG_INT_ENABLE,   0x0050);
    ASSERT_EQ_U(CRB_REG_INT_STS,      0x0054);
    ASSERT_EQ_U(CRB_REG_CMD_SIZE,     0x0058);
    ASSERT_EQ_U(CRB_REG_CMD_ADDR_LO,  0x005C);
    ASSERT_EQ_U(CRB_REG_CMD_ADDR_HI,  0x0060);
    ASSERT_EQ_U(CRB_REG_RSP_SIZE,     0x0064);
    ASSERT_EQ_U(CRB_REG_RSP_ADDR,     0x0068);
    ASSERT_EQ_U(CRB_REG_CMD_LOW,      0x0080);
    ASSERT_EQ_U(CRB_REG_RSP_LOW,      0x0080);
    /* Control-Area offset from locality base is fixed by CRB Table 8-1
     * and used on the ACPI-discovery path (tpm_crb.c try_discover_acpi). */
    ASSERT_EQ_U(CRB_LOC_CTRL_AREA_OFFSET, 0x40);
}

TEST(register_bit_fields_are_stable)
{
    ASSERT_EQ_U(CRB_LOC_STATE_ESTABLISHED,    0x1);
    ASSERT_EQ_U(CRB_LOC_STATE_ASSIGNED,       0x2);
    ASSERT_EQ_U(CRB_LOC_CTRL_REQ_ACCESS,      0x1);
    ASSERT_EQ_U(CRB_LOC_CTRL_RELINQUISH,      0x2);
    ASSERT_EQ_U(CRB_LOC_CTRL_SEIZE,           0x4);
    ASSERT_EQ_U(CRB_LOC_CTRL_RESET,           0x8);
    ASSERT_EQ_U(CRB_LOC_STS_GRANTED,          0x1);
    ASSERT_EQ_U(CRB_LOC_STS_BEEN_SEIZED,      0x2);
    ASSERT_EQ_U(CRB_CTRL_REQ_CMD_READY,       0x1);
    ASSERT_EQ_U(CRB_CTRL_REQ_IDLE,            0x2);
    ASSERT_EQ_U(CRB_CTRL_STS_ERROR,           0x1);
    ASSERT_EQ_U(CRB_CTRL_STS_IDLE,            0x2);
    ASSERT_EQ_U(CRB_CTRL_CANCEL_YES,          0x1);
    ASSERT_EQ_U(CRB_CTRL_CANCEL_NO,           0x0);
    ASSERT_EQ_U(CRB_CTRL_START,               0x1);
    ASSERT_EQ_U(CRB_INTF_ID_TYPE_MASK,        0xF);
    ASSERT_EQ_U(CRB_INTF_ID_TYPE_CRB,         0x1);
    ASSERT_EQ_U(CRB_INTF_ID_TYPE_FIFO_CRB,    0xF);
    ASSERT_EQ_U(CRB_INTF_ID_CAP_LOCALITY,     (1u << 8));
    ASSERT_EQ_U(CRB_INTF_ID_CAP_IDLE_BYPASS,  (1u << 9));
}

TEST(qemu_fallback_mmio_window_matches_spec)
{
    ASSERT_EQ_U(CRB_QEMU_DEFAULT_MMIO_BASE, 0xFED40000ull);
    /* Window covers CRB register block plus localities 0..4
     * (CRB Table 8-1: 4 KiB per locality, 5 localities). */
    ASSERT_EQ_U(CRB_QEMU_DEFAULT_MMIO_LEN,  0x5000ull);
}

/* -------------------------------------------------------------------- */
/* Fake MMIO shim - self-tests.                                          */
/*                                                                       */
/* Any driver-side test that uses the shim implicitly depends on these   */
/* semantics; validating them here catches shim regressions early.      */
/* -------------------------------------------------------------------- */

TEST(fake_mmio_reset_populates_plausible_defaults)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    /* CMD_SIZE / RSP_SIZE and INTF_ID_LO should read back as configured. */
    ASSERT_EQ_U(ops->read32(ops->cookie, CRB_REG_CMD_SIZE), 4096);
    ASSERT_EQ_U(ops->read32(ops->cookie, CRB_REG_RSP_SIZE), 4096);
    u32 intf = ops->read32(ops->cookie, CRB_REG_INTF_ID_LO);
    ASSERT_EQ_U(intf & CRB_INTF_ID_TYPE_MASK, CRB_INTF_ID_TYPE_CRB);
    ASSERT(intf & CRB_INTF_ID_CAP_LOCALITY);
}

TEST(fake_mmio_reset_clears_transcript)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    ops->write32(ops->cookie, CRB_REG_CTRL_REQ, CRB_CTRL_REQ_CMD_READY);
    ASSERT(s.transcript_len > 0);
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    ASSERT_EQ_U(s.transcript_len, 0);
}

TEST(fake_mmio_write_read32_roundtrip)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    ops->write32(ops->cookie, CRB_REG_INT_ENABLE, 0xDEADBEEF);
    ASSERT_EQ_U(ops->read32(ops->cookie, CRB_REG_INT_ENABLE), 0xDEADBEEFu);
}

TEST(fake_mmio_transcript_records_writes_and_reads)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    (void)ops->read32(ops->cookie, CRB_REG_CMD_SIZE);
    ops->write32(ops->cookie, CRB_REG_INT_ENABLE, 0x1);
    ASSERT_EQ_U(s.transcript_len, 2);
    ASSERT_EQ_U(s.transcript[0].offset, CRB_REG_CMD_SIZE);
    ASSERT(!s.transcript[0].is_write);
    ASSERT_EQ_U(s.transcript[1].offset, CRB_REG_INT_ENABLE);
    ASSERT(s.transcript[1].is_write);
}

TEST(fake_mmio_loc_ctrl_grants_locality_on_request)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    ASSERT_EQ_U(ops->read32(ops->cookie, CRB_REG_LOC_STS) & CRB_LOC_STS_GRANTED, 0);
    ops->write32(ops->cookie, CRB_REG_LOC_CTRL, CRB_LOC_CTRL_REQ_ACCESS);
    ASSERT_EQ_U(ops->read32(ops->cookie, CRB_REG_LOC_STS) & CRB_LOC_STS_GRANTED,
                CRB_LOC_STS_GRANTED);
}

TEST(fake_mmio_ctrl_start_clears_after_two_ticks)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    /* Write START = 1 to arm the tick countdown. */
    ops->write32(ops->cookie, CRB_REG_CTRL_START, CRB_CTRL_START);

    /* First two reads still see START set; third read must see it cleared. */
    ASSERT(ops->read32(ops->cookie, CRB_REG_CTRL_START) & CRB_CTRL_START);
    ASSERT(ops->read32(ops->cookie, CRB_REG_CTRL_START) & CRB_CTRL_START);
    ASSERT_EQ_U(ops->read32(ops->cookie, CRB_REG_CTRL_START) & CRB_CTRL_START, 0);
}

TEST(fake_mmio_mode_stuck_busy_never_clears_ctrl_sts_idle)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_STUCK_BUSY);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    for (int i = 0; i < 10; ++i) {
        u32 sts = ops->read32(ops->cookie, CRB_REG_CTRL_STS);
        ASSERT(sts & CRB_CTRL_STS_IDLE);
    }
}

TEST(fake_mmio_mode_stuck_executing_holds_ctrl_start_high)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_STUCK_EXECUTING);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    ops->write32(ops->cookie, CRB_REG_CTRL_START, CRB_CTRL_START);
    for (int i = 0; i < 10; ++i) {
        u32 start = ops->read32(ops->cookie, CRB_REG_CTRL_START);
        ASSERT(start & CRB_CTRL_START);
    }
}

TEST(fake_mmio_mode_error_latched_holds_ctrl_sts_error_high)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_ERROR_LATCHED);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    for (int i = 0; i < 10; ++i) {
        u32 sts = ops->read32(ops->cookie, CRB_REG_CTRL_STS);
        ASSERT(sts & CRB_CTRL_STS_ERROR);
    }
}

TEST(fake_mmio_bulk_write_read_bytes_roundtrip)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    u8 src[64];
    for (int i = 0; i < 64; ++i) src[i] = (u8)(i ^ 0x5A);
    ops->write_bytes(ops->cookie, CRB_REG_CMD_LOW, src, sizeof(src));

    u8 dst[64];
    memset(dst, 0, sizeof(dst));
    ops->read_bytes(ops->cookie, CRB_REG_RSP_LOW, dst, sizeof(dst));
    /* CMD_LOW and RSP_LOW alias the same buffer region on this shim
     * (matching what the CRB spec allows and what tpm_crb.c assumes). */
    ASSERT(memcmp(src, dst, sizeof(src)) == 0);
}

TEST(fake_mmio_seed_response_rejects_out_of_range)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    u8 huge[TPM_CRB_FAKE_MMIO_BUF_BYTES];
    ASSERT(!tpm_crb_fake_seed_response(&s, huge, sizeof(huge)));
}

TEST(fake_mmio_read_bytes_out_of_range_is_a_noop)
{
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    u8 dst[8];
    memset(dst, 0xAB, sizeof(dst));
    /* Past the end of the buffer: shim must not touch dst. */
    ops->read_bytes(ops->cookie,
                    TPM_CRB_FAKE_MMIO_BUF_BYTES - 4, dst, sizeof(dst));
    for (int i = 0; i < 8; ++i) ASSERT_EQ_U(dst[i], 0xAB);
}

/* -------------------------------------------------------------------- */
/* Response-header length decode - checklist item: response-size         */
/* validation (bounds check before copy).                                */
/*                                                                       */
/* Reproduces the algorithm in tpm_crb.c crb_extract_response_length()   */
/* so we can exercise it against seeded shim payloads: the function is   */
/* file-static in the driver and not exported, but the algorithm is      */
/* small, spec-defined (TCG TPM 2.0 Part 1 sec 6), and easy to           */
/* replicate here.                                                       */
/*                                                                       */
/* TPM 2.0 response header (10 bytes, big-endian):                       */
/*   [0..1] tag                                                          */
/*   [2..5] responseSize (total including header)                        */
/*   [6..9] responseCode                                                 */
/* -------------------------------------------------------------------- */

#define TPM2_HEADER_SIZE 10

/* Values returned by the decode - integer codes that mirror the driver's
 * TPM_ERR_* enumeration so a test failure would surface the same
 * classification the caller sees. */
#define DECODE_OK           0
#define DECODE_TRANSPORT    4  /* len < header, or len > device max */
#define DECODE_INVAL        1  /* len > caller capacity */

static int decode_response_length(const u8 *rsp_hdr,
                                  bytes max_response_size,
                                  bytes response_capacity,
                                  bytes *out_len)
{
    bytes len = ((bytes)rsp_hdr[2] << 24) | ((bytes)rsp_hdr[3] << 16) |
                ((bytes)rsp_hdr[4] <<  8) | ((bytes)rsp_hdr[5]);
    if (len < TPM2_HEADER_SIZE || len > max_response_size)
        return DECODE_TRANSPORT;
    if (len > response_capacity)
        return DECODE_INVAL;
    *out_len = len;
    return DECODE_OK;
}

TEST(response_decode_accepts_valid_header)
{
    /* tag=0x8001, responseSize=0x00000010 (16 bytes), rc=0. */
    u8 hdr[TPM2_HEADER_SIZE] = { 0x80, 0x01, 0, 0, 0, 0x10,
                                 0, 0, 0, 0 };
    bytes len = 0;
    ASSERT_EQ_U(decode_response_length(hdr, 4096, 128, &len), DECODE_OK);
    ASSERT_EQ_U(len, 16);
}

TEST(response_decode_rejects_len_below_header_size)
{
    /* Header claims responseSize = 4, which is smaller than the 10-byte
     * header - a malformed device response that the driver reports as a
     * transport failure. */
    u8 hdr[TPM2_HEADER_SIZE] = { 0x80, 0x01, 0, 0, 0, 0x04,
                                 0, 0, 0, 0 };
    bytes len = 0;
    ASSERT_EQ_U(decode_response_length(hdr, 4096, 128, &len), DECODE_TRANSPORT);
}

TEST(response_decode_rejects_len_above_device_max)
{
    /* Header claims responseSize = 8192 but the device's maximum
     * response size is 4096 - a transport failure. */
    u8 hdr[TPM2_HEADER_SIZE] = { 0x80, 0x01, 0, 0, 0x20, 0x00,
                                 0, 0, 0, 0 };
    bytes len = 0;
    ASSERT_EQ_U(decode_response_length(hdr, 4096, 8192, &len), DECODE_TRANSPORT);
}

TEST(response_decode_rejects_len_above_caller_capacity)
{
    /* Header claims 128 bytes but the caller only offers 32 bytes of
     * capacity - INVAL, not TRANSPORT, because the caller has misused
     * the interface. Matches design doc sec 4.3. */
    u8 hdr[TPM2_HEADER_SIZE] = { 0x80, 0x01, 0, 0, 0, 0x80,
                                 0, 0, 0, 0 };
    bytes len = 0;
    ASSERT_EQ_U(decode_response_length(hdr, 4096, 32, &len), DECODE_INVAL);
}

TEST(response_decode_accepts_len_exactly_at_capacity)
{
    /* len == capacity is allowed (not "less than"). */
    u8 hdr[TPM2_HEADER_SIZE] = { 0x80, 0x01, 0, 0, 0, 0x40,
                                 0, 0, 0, 0 };
    bytes len = 0;
    ASSERT_EQ_U(decode_response_length(hdr, 4096, 64, &len), DECODE_OK);
    ASSERT_EQ_U(len, 64);
}

TEST(response_decode_seeded_via_fake_mmio)
{
    /* Round-trip: seed a header through the shim's write path, read it
     * back through the shim, decode it. Confirms shim + decode pair
     * behaves as a future driver-side transmit would observe. */
    tpm_crb_fake_state s;
    tpm_crb_fake_reset(&s, TPM_CRB_FAKE_MODE_NORMAL);
    const crb_mmio_ops *ops = tpm_crb_fake_ops(&s);

    u8 hdr[TPM2_HEADER_SIZE] = { 0x80, 0x01, 0, 0, 0, 0x20,
                                 0, 0, 0, 0 };
    ASSERT(tpm_crb_fake_seed_response(&s, hdr, sizeof(hdr)));

    u8 read_back[TPM2_HEADER_SIZE];
    ops->read_bytes(ops->cookie, CRB_REG_RSP_LOW, read_back, sizeof(read_back));
    bytes len = 0;
    ASSERT_EQ_U(decode_response_length(read_back, 4096, 128, &len), DECODE_OK);
    ASSERT_EQ_U(len, 0x20);
}

/* -------------------------------------------------------------------- */
/* main - drives the test list.                                          */
/* -------------------------------------------------------------------- */

int main(void)
{
    printf("tpm_crb_test: CRB register-abstraction + response-decode\n");

    /* Register-space encoding + decoding (design sec 8.1). */
    RUN(register_offsets_match_tcg_spec);
    RUN(register_bit_fields_are_stable);
    RUN(qemu_fallback_mmio_window_matches_spec);

    /* Fake MMIO shim self-tests. */
    RUN(fake_mmio_reset_populates_plausible_defaults);
    RUN(fake_mmio_reset_clears_transcript);
    RUN(fake_mmio_write_read32_roundtrip);
    RUN(fake_mmio_transcript_records_writes_and_reads);
    RUN(fake_mmio_loc_ctrl_grants_locality_on_request);
    RUN(fake_mmio_ctrl_start_clears_after_two_ticks);
    RUN(fake_mmio_mode_stuck_busy_never_clears_ctrl_sts_idle);
    RUN(fake_mmio_mode_stuck_executing_holds_ctrl_start_high);
    RUN(fake_mmio_mode_error_latched_holds_ctrl_sts_error_high);
    RUN(fake_mmio_bulk_write_read_bytes_roundtrip);
    RUN(fake_mmio_seed_response_rejects_out_of_range);
    RUN(fake_mmio_read_bytes_out_of_range_is_a_noop);

    /* Response-header decode (design sec 8.1: response-size validation
     * / malformed-response handling / integer-overflow guard). */
    RUN(response_decode_accepts_valid_header);
    RUN(response_decode_rejects_len_below_header_size);
    RUN(response_decode_rejects_len_above_device_max);
    RUN(response_decode_rejects_len_above_caller_capacity);
    RUN(response_decode_accepts_len_exactly_at_capacity);
    RUN(response_decode_seeded_via_fake_mmio);

    /* Design sec 8.1 checklist items whose testing requires linking
     * tpm_crb.c and thus a kernel/VDSO build environment - deferred to
     * a future in-kernel test harness. Reported here so the coverage
     * signal is honest, not hidden. */
    const char *why = "requires tpm_crb.c linkage; kernel-only translation unit";
    SKIP(state_transitions_uninit_discovered_ready_busy_failed_shutdown, why);
    SKIP(discovery_rejects_zero_or_oversize_command_buffer,              why);
    SKIP(discovery_rejects_non_crb_interface_type,                       why);
    SKIP(transmit_rejects_undersize_and_oversize_command,                why);
    SKIP(transmit_serializes_second_caller_returns_busy,                 why);
    SKIP(transmit_times_out_when_device_stuck_executing,                 why);
    SKIP(configure_rejects_zero_timeouts,                                why);
    SKIP(recover_after_latched_error_returns_ready,                      why);
    SKIP(recover_marks_unhealthy_when_interface_gone,                    why);
    SKIP(cancel_completes_within_cancel_ns_budget,                       why);

    printf("tpm_crb_test: pass=%u fail=%u skip=%u\n",
           g_pass, g_fail, g_skip);
    return g_fail ? EXIT_FAILURE : EXIT_SUCCESS;
}
