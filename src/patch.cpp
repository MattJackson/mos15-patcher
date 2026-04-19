//
// patch.cpp — Function prologue patching with trampolines.
//
// On x86_64, the simplest reliable hook is an absolute indirect jump:
//
//     ff 25 00 00 00 00          jmpq *(%rip)
//     <8-byte target>
//
// 14 bytes total. We disassemble the original prologue with a tiny built-in
// length disassembler (just enough to know how many bytes to displace),
// copy the displaced bytes into a trampoline buffer, append our own
// 14-byte absolute jump back to (target + N), then overwrite the prologue
// with the absolute jump to our replacement.
//

#include "patch.hpp"
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <libkern/libkern.h>
#include <IOKit/IOLib.h>

extern "C" {
    /* Kernel-internal vm_protect via map. Used for trampoline pages
     * (allocated via IOMallocAligned) — works fine. */
    extern vm_map_t kernel_map;
    extern kern_return_t vm_protect(vm_map_t, vm_offset_t, vm_size_t, boolean_t, vm_prot_t);
}

/*
 * Kernel-text writes: the kernel marks its __TEXT pages read-only and
 * vm_protect can't override that on Sequoia. Standard trick: temporarily
 * clear the WP (Write Protect) bit in CR0 — that disables supervisor-mode
 * read-only enforcement, letting us write. Restore CR0 afterward.
 *
 * Disable interrupts during the window so a context switch / preempt won't
 * leave us with WP=0.
 */
static inline uintptr_t cr0_read() {
    uintptr_t v;
    __asm__ volatile ("movq %%cr0, %0" : "=r"(v));
    return v;
}
static inline void cr0_write(uintptr_t v) {
    __asm__ volatile ("movq %0, %%cr0" :: "r"(v) : "memory");
}
#define CR0_WP_BIT (1ULL << 16)

/* Exposed under a stable C name for vtable.cpp etc. */
extern "C" void wp_write_kernel_bytes(uint8_t *dst, const uint8_t *src, size_t n) {
    boolean_t intr = ml_set_interrupts_enabled(FALSE);
    uintptr_t cr0 = cr0_read();
    cr0_write(cr0 & ~CR0_WP_BIT);
    memcpy(dst, src, n);
    cr0_write(cr0);
    ml_set_interrupts_enabled(intr);
}

#define write_kernel_bytes wp_write_kernel_bytes

/*
 * Rewrite RIP-relative offsets in a displaced instruction copied to the
 * trampoline. x86_64 RIP-relative addressing: ModR/M byte with mod=00,
 * rm=101. The 32-bit displacement that follows is relative to RIP =
 * address of next instruction.
 *
 *   src   = original instruction bytes (at original address)
 *   dst   = copy at new (trampoline) address
 *   len   = instruction length
 *   delta = original_addr - trampoline_addr (signed)
 *
 * For an instruction at original_addr with disp32 D referencing target
 * T = original_addr + insn_len + D, the same instruction at trampoline_addr
 * needs disp32 D' such that trampoline_addr + insn_len + D' == T.
 * Solving: D' = D + (original_addr - trampoline_addr) = D + delta.
 *
 * If D + delta overflows int32_t, we have a problem — trampoline is too
 * far from original. Caller should detect and fail.
 */
static int rip_rel_offset_index(const uint8_t *insn, int insn_len, int *disp_off);
extern "C" int patch_relocate_insn(uint8_t *dst, const uint8_t *src,
                                   int insn_len, int64_t delta);
int patch_relocate_insn(uint8_t *dst, const uint8_t *src, int insn_len, int64_t delta)
{
    int disp_off = 0;
    int idx = rip_rel_offset_index(src, insn_len, &disp_off);
    memcpy(dst, src, insn_len);
    if (idx < 0) return 0;  /* not RIP-relative — straight copy is fine */

    int32_t orig_disp = *(int32_t *)(src + disp_off);
    int64_t new_disp64 = (int64_t)orig_disp + delta;
    if (new_disp64 > INT32_MAX || new_disp64 < INT32_MIN) {
        return -1;  /* trampoline too far from original */
    }
    *(int32_t *)(dst + disp_off) = (int32_t)new_disp64;
    return 1;
}

/* Locate the disp32 inside an instruction if it's RIP-relative.
 * Returns 1 + sets *disp_off to byte offset within instruction; -1 if not RIP-rel. */
static int rip_rel_offset_index(const uint8_t *insn, int insn_len, int *disp_off)
{
    int p = 0;

    /* Skip legacy prefixes */
    while (p < 4) {
        uint8_t b = insn[p];
        if (b == 0x66 || b == 0x67 || b == 0xf0 || b == 0xf2 || b == 0xf3 ||
            b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e || b == 0x64 ||
            b == 0x65) { p++; continue; }
        break;
    }

    /* REX prefix */
    if ((insn[p] & 0xf0) == 0x40) p++;

    uint8_t op = insn[p++];

    /* Opcodes with no ModR/M: nothing to relocate */
    if ((op >= 0x50 && op <= 0x5f) ||  /* push/pop reg */
        op == 0xc3 || op == 0xc9 ||    /* ret / leave */
        (op >= 0xb8 && op <= 0xbf)) {  /* mov r64, imm64 */
        return -1;
    }

    /* 0F escape — handle 0F 1F (multibyte nop) — has ModR/M but rare to be RIP-rel */
    if (op == 0x0f) {
        op = insn[p++];
        /* fall through to ModR/M handling */
    }

    /* All remaining ops here have a ModR/M byte at insn[p]. */
    if (p >= insn_len) return -1;
    uint8_t modrm = insn[p++];
    uint8_t mod = modrm >> 6;
    uint8_t rm  = modrm & 7;

    /* RIP-relative is mod==00 && rm==101 (no SIB; disp32 follows directly) */
    if (mod == 0 && rm == 5) {
        /* disp32 starts at p */
        if (p + 4 > insn_len) return -1;
        *disp_off = p;
        return 1;
    }

    return -1;
}

static const char *kLog = "mp:patch";

#define ABS_JMP_LEN 14

/* Length-disassembler for x86_64. Returns instruction length, or 0 on error.
 * Handles only the common prologue patterns we care about (push, mov, sub,
 * lea, etc.) — not a complete disassembler. */
static int x86_insn_length(const uint8_t *p)
{
    int len = 0;

    /* Legacy prefixes */
    while (len < 4) {
        uint8_t b = p[len];
        if (b == 0x66 || b == 0x67 || b == 0xf0 || b == 0xf2 || b == 0xf3 ||
            b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e || b == 0x64 ||
            b == 0x65) { len++; continue; }
        break;
    }

    /* REX prefix */
    if ((p[len] & 0xf0) == 0x40) len++;

    uint8_t op = p[len++];

    /* Common single-byte ops */
    switch (op) {
        case 0x50 ... 0x57:  /* push reg (incl. push %rbp = 0x55) */
        case 0x58 ... 0x5f:  /* pop reg */
        case 0xc3:           /* ret */
        case 0xc9:           /* leave */
            return len;
    }

    /* Two-byte 0F escape */
    if (op == 0x0f) {
        op = p[len++];
        if (op == 0x1f) {
            /* nopw / multibyte nop */
            uint8_t modrm = p[len++];
            if ((modrm & 0xc0) != 0xc0) {
                /* memory operand: handle ModR/M */
                uint8_t mod = modrm >> 6;
                uint8_t rm  = modrm & 7;
                if (rm == 4) len++; /* SIB */
                if (mod == 1) len++;
                else if (mod == 2) len += 4;
                else if (mod == 0 && rm == 5) len += 4; /* RIP+disp32 */
            }
            return len;
        }
    }

    /* mov r64, imm64: 0xB8+rd */
    if (op >= 0xb8 && op <= 0xbf) {
        return len + 8;
    }

    /* mov, sub, add, lea, xor with ModR/M and optional disp/imm.
     * Handle: 89 C0 (mov r/m64,r64), 8B C0 (mov r64,r/m64), 83 EC NN (sub r/m64,imm8),
     *         48 81 EC NN NN NN NN (sub r/m64,imm32), 8D ... (lea), etc. */
    if (op == 0x89 || op == 0x8b || op == 0x8d || op == 0x31 || op == 0x33 ||
        op == 0x39 || op == 0x3b || op == 0x21 || op == 0x29 || op == 0x01 ||
        op == 0x09 || op == 0x29 || op == 0x85 || op == 0x83 || op == 0x81 ||
        op == 0xc7 || op == 0xff) {
        /* ModR/M */
        uint8_t modrm = p[len++];
        uint8_t mod = modrm >> 6;
        uint8_t rm  = modrm & 7;
        if (mod != 3 && rm == 4) len++; /* SIB */
        if (mod == 1) len++;
        else if (mod == 2) len += 4;
        else if (mod == 0 && rm == 5) len += 4; /* RIP+disp32 */

        /* Imm for ops with immediates */
        if (op == 0x83) len += 1;
        else if (op == 0x81 || op == 0xc7) len += 4;
        return len;
    }

    return 0; /* unsupported — caller will fail safely */
}

/*
 * Determine how many original bytes to displace. We need at least
 * ABS_JMP_LEN (14) bytes of clean instruction starts, no fallthrough into
 * the middle of an instruction.
 */
static int compute_displacement(const uint8_t *prologue)
{
    int total = 0;
    while (total < ABS_JMP_LEN) {
        int n = x86_insn_length(prologue + total);
        if (n == 0) return 0;
        total += n;
    }
    return total;
}

/* Write a 14-byte absolute jump at `dst` jumping to `target`. */
static void write_abs_jmp(uint8_t *dst, uint64_t target)
{
    dst[0] = 0xff; dst[1] = 0x25;
    dst[2] = 0x00; dst[3] = 0x00; dst[4] = 0x00; dst[5] = 0x00;
    *(uint64_t *)(dst + 6) = target;
}

/*
 * Trampoline allocator: hand out slots from a pre-allocated buffer that
 * lives in our kext's __TEXT segment. __TEXT is mapped RX by the kext
 * loader, which is exactly what we need. Writing to it requires the
 * WP-toggle trick (same as patching kernel text).
 *
 * 64 slots * 48 bytes each — plenty for 18+ routes. Each trampoline needs
 * room for displaced bytes (max 32) + a 14-byte JMP back = 46 bytes.
 *
 * The `used` attribute keeps the linker from stripping the buffer; the
 * `section("__TEXT,__cstring")` placement puts it in __TEXT so the page is RX
 * (we can't easily declare a custom subsection without xcodebuild setup).
 */
#define TRAMP_SLOTS 64
#define TRAMP_SIZE  48

__attribute__((used, section("__TEXT,__cstring")))
static uint8_t gTrampPool[TRAMP_SLOTS * TRAMP_SIZE] = { 0xcc };  /* int3 fill */

static int gNextTramp = 0;

static uint8_t *
alloc_tramp_slot()
{
    if (gNextTramp >= TRAMP_SLOTS) {
        IOLog("%s: trampoline pool exhausted (%d slots)\n", kLog, TRAMP_SLOTS);
        return nullptr;
    }
    return &gTrampPool[gNextTramp++ * TRAMP_SIZE];
}

int
patch_route(uint64_t target_addr, void *replacement, void **org)
{
    if (!target_addr || !replacement) return -1;

    uint8_t *target = (uint8_t *)target_addr;

    /* 1. Figure out how much of the prologue to displace. */
    int displ = compute_displacement(target);
    if (displ == 0 || displ > 32) {
        IOLog("%s: bad displacement %d at 0x%llx\n", kLog, displ, target_addr);
        return -2;
    }

    /* 2. Allocate trampoline slot from our __TEXT pool (RX). Build the
     *    trampoline contents in a stack buffer, then WP-toggle-write to the
     *    slot (since __TEXT is read-only from the supervisor's normal view). */
    uint8_t *tramp = alloc_tramp_slot();
    if (!tramp) return -3;

    /* Build trampoline contents in scratch, with RIP-rel offsets rewritten
     * for the new (trampoline) address. */
    uint8_t scratch[TRAMP_SIZE];
    int64_t delta = (int64_t)target_addr - (int64_t)tramp;
    int p = 0;
    while (p < displ) {
        int n = x86_insn_length(target + p);
        if (n == 0) {
            IOLog("%s: bad insn at offset %d while relocating\n", kLog, p);
            return -5;
        }
        if (patch_relocate_insn(scratch + p, target + p, n, delta) < 0) {
            IOLog("%s: RIP-rel offset overflow at offset %d (delta=0x%llx)\n",
                  kLog, p, (long long)delta);
            return -6;
        }
        p += n;
    }
    write_abs_jmp(scratch + displ, target_addr + displ);
    write_kernel_bytes(tramp, scratch, displ + ABS_JMP_LEN);

    if (org) *org = tramp;

    /* 3. Build the JMP into a local buffer, then write it to the target via
     *    the WP-bit-toggle trick (vm_protect is unreliable on kernel __TEXT). */
    uint8_t jmp_bytes[ABS_JMP_LEN];
    write_abs_jmp(jmp_bytes, (uint64_t)replacement);
    write_kernel_bytes(target, jmp_bytes, ABS_JMP_LEN);

    IOLog("%s: routed 0x%llx -> %p (trampoline %p, displaced %d bytes)\n",
          kLog, target_addr, replacement, tramp, displ);
    return 0;
}
