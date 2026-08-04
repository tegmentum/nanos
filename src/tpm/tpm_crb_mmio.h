/*
 * WasmOS TPM 2.0 CRB - MMIO register-access seam
 *
 * NANOS PATH: src/tpm/tpm_crb_mmio.h
 *
 * Design doc sec 8.1: "The CRB register layer MUST be abstracted so tests
 * can substitute a fake MMIO implementation - real hardware in unit
 * tests is a non-starter."
 *
 * This header defines the abstract ops table. The production
 * implementation (crb_mmio_ops_real) uses the platform's memory-mapped
 * I/O primitives; the test implementation (crb_mmio_ops_fake, defined
 * in the tests/ tree) records reads/writes to a backing map so the
 * unit test can assert on register-access sequences.
 */

/* Nanos headers use no include guards - each header is expected to be
 * included exactly once from a .c file that has already pulled in
 * <runtime.h> / <kernel.h>.  Do NOT #include <kernel.h> here. */

/* -------------------------------------------------------------------- */
/* CRB register offsets (TCG PC Client Platform TPM Profile — CRB       */
/* interface). Values are stable across TPM 2.0 CRB implementations;    */
/* see the CRB specification Table 8-1 for authoritative offsets.        */
/* -------------------------------------------------------------------- */

#define CRB_REG_LOC_STATE       0x0000  /* Locality State */
#define CRB_REG_LOC_CTRL        0x0008  /* Locality Control */
#define CRB_REG_LOC_STS         0x000C  /* Locality Status */
#define CRB_REG_INTF_ID_LO      0x0030  /* Interface Id (low 32 bits) */
#define CRB_REG_INTF_ID_HI      0x0034  /* Interface Id (high 32 bits) */
#define CRB_REG_CTRL_EXT        0x0038  /* Control Extension */
#define CRB_REG_CTRL_REQ        0x0040  /* Control Request */
#define CRB_REG_CTRL_STS        0x0044  /* Control Status */
#define CRB_REG_CTRL_CANCEL     0x0048  /* Control Cancel */
#define CRB_REG_CTRL_START      0x004C  /* Control Start */
#define CRB_REG_INT_ENABLE      0x0050  /* Interrupt Enable */
#define CRB_REG_INT_STS         0x0054  /* Interrupt Status */
#define CRB_REG_CMD_SIZE        0x0058  /* Command Buffer Size */
#define CRB_REG_CMD_ADDR_LO     0x005C  /* Command Buffer Addr (low) */
#define CRB_REG_CMD_ADDR_HI     0x0060  /* Command Buffer Addr (high) */
#define CRB_REG_RSP_SIZE        0x0064  /* Response Buffer Size */
#define CRB_REG_RSP_ADDR        0x0068  /* Response Buffer Addr (64-bit) */

/* Command Buffer / Response Buffer (I/O region — the driver reads and
 * writes command/response bytes through these offsets). Some devices
 * expose the buffers at the addresses in the CMD_ADDR / RSP_ADDR
 * registers instead — see design doc §4.4 for the discovery
 * validation the driver MUST perform. */
#define CRB_REG_CMD_LOW         0x0080
#define CRB_REG_RSP_LOW         0x0080

/* -------------------------------------------------------------------- */
/* Register bit fields                                                   */
/* -------------------------------------------------------------------- */

#define CRB_LOC_STATE_ESTABLISHED   (1u << 0)
#define CRB_LOC_STATE_ASSIGNED      (1u << 1)
#define CRB_LOC_STATE_ACTIVE_MASK   (7u << 2)
#define CRB_LOC_STATE_ACTIVE_SHIFT  2
#define CRB_LOC_STATE_TPM_REG_VALID (1u << 7)

#define CRB_LOC_CTRL_REQ_ACCESS     (1u << 0)
#define CRB_LOC_CTRL_RELINQUISH     (1u << 1)
#define CRB_LOC_CTRL_SEIZE          (1u << 2)
#define CRB_LOC_CTRL_RESET          (1u << 3)

#define CRB_LOC_STS_GRANTED         (1u << 0)
#define CRB_LOC_STS_BEEN_SEIZED     (1u << 1)

#define CRB_CTRL_REQ_CMD_READY      (1u << 0)
#define CRB_CTRL_REQ_IDLE           (1u << 1)

#define CRB_CTRL_STS_ERROR          (1u << 0)
#define CRB_CTRL_STS_IDLE           (1u << 1)

#define CRB_CTRL_CANCEL_YES         0x00000001u
#define CRB_CTRL_CANCEL_NO          0x00000000u

#define CRB_CTRL_START              0x00000001u

/* Interface Id (low) — bits 0..3 identify interface family:
 *   0x1 = pure CRB (rare in practice)
 *   0xF = FIFO-over-TIS / CRB combined device, CRB is one of several
 *         selectable interface modes. QEMU's tpm-crb device and most
 *         real-hardware Intel PTT / Infineon parts report 0xF: the
 *         "interface type" field advertises the device family, while
 *         the "capabilities" field indicates which sub-modes are
 *         actually supported. Accepting 0xF here matches the TPM2
 *         reference implementation and the Linux tpm_crb driver.
 * The driver treats both values as CRB-capable and relies on the
 * CRB-specific register offsets below being valid for either.
 */
#define CRB_INTF_ID_TYPE_MASK       0xFu
#define CRB_INTF_ID_TYPE_CRB        0x1u
#define CRB_INTF_ID_TYPE_FIFO_CRB   0xFu
#define CRB_INTF_ID_VERSION_MASK    0xF0u
#define CRB_INTF_ID_VERSION_SHIFT   4
#define CRB_INTF_ID_CAP_LOCALITY    (1u << 8)
#define CRB_INTF_ID_CAP_IDLE_BYPASS (1u << 9)

/* Offset of the CRB Control Area within a locality register block.
 * Per TCG PC Client Platform TPM Profile (CRB Interface) Table 8-1,
 * each locality's register block starts with the Locality State /
 * Control / Status registers (0x00 .. 0x3F) followed by the CRB
 * Control Area beginning at offset 0x40 (CTRL_REQ, CTRL_STS,
 * CTRL_CANCEL, CTRL_START, ...). The ACPI TPM2 table's
 * ControlAddress field points at the Control Area itself; the
 * driver indexes from the locality base and therefore subtracts
 * this offset when it consumes ControlAddress. */
#define CRB_LOC_CTRL_AREA_OFFSET    0x40u

/* Standard x86 QEMU CRB MMIO base — used only as a final-fallback in
 * discovery per design doc §4.4. Production images MUST prefer ACPI
 * TPM2 / platform / manifest sources first. */
#define CRB_QEMU_DEFAULT_MMIO_BASE  0xFED40000ULL
#define CRB_QEMU_DEFAULT_MMIO_LEN   0x00005000ULL

/* -------------------------------------------------------------------- */
/* Abstract MMIO ops table                                               */
/* -------------------------------------------------------------------- */

typedef struct crb_mmio_ops {
    /* Register reads/writes — 32-bit little-endian. */
    u32  (*read32) (void *cookie, u64 offset);
    void (*write32)(void *cookie, u64 offset, u32 value);
    u64  (*read64) (void *cookie, u64 offset);
    void (*write64)(void *cookie, u64 offset, u64 value);

    /* Bulk byte transfer for command / response buffer regions. */
    void (*read_bytes) (void *cookie, u64 offset, void *dst, bytes n);
    void (*write_bytes)(void *cookie, u64 offset, const void *src, bytes n);

    /* Memory barrier for ordering register writes vs buffer writes.   */
    void (*mb)(void *cookie);

    /* Ops-specific cookie passed to every callback; opaque to the
     * driver.  For real MMIO this is the virtual base address. */
    void *cookie;
} crb_mmio_ops;

/* Construct the production real-MMIO ops table over a virtual address
 * range that has already been mapped by the platform. Returns NULL on
 * mapping failure. */
const crb_mmio_ops *crb_mmio_ops_real(void *virt_base, u64 length);
