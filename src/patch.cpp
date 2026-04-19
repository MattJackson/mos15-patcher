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
    /* Kernel-internal vm_protect via map. We need read-write access to the
     * code page during patching. */
    extern vm_map_t kernel_map;
    extern kern_return_t vm_protect(vm_map_t, vm_offset_t, vm_size_t, boolean_t, vm_prot_t);
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

/* Allocate executable kernel memory big enough for one trampoline.
 * Returns a kernel virtual address with R+W+X. */
static uint8_t *
alloc_trampoline_page()
{
    /* IOMallocAligned gives us page-aligned RW memory. We then bump to RX. */
    void *mem = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
    if (!mem) return nullptr;
    bzero(mem, PAGE_SIZE);

    /* Make it executable. Default IOMalloc memory is RW only. */
    kern_return_t kr = vm_protect(kernel_map, (vm_offset_t)mem, PAGE_SIZE,
                                  FALSE, VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        IOLog("%s: vm_protect(RX) failed kr=%d\n", kLog, kr);
        IOFreeAligned(mem, PAGE_SIZE);
        return nullptr;
    }
    return (uint8_t *)mem;
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

    /* 2. Allocate trampoline: displaced bytes + 14-byte JMP back. */
    uint8_t *tramp = alloc_trampoline_page();
    if (!tramp) return -3;

    memcpy(tramp, target, displ);
    write_abs_jmp(tramp + displ, target_addr + displ);

    if (org) *org = tramp;

    /* 3. Make the target page writable, install our JMP, restore. */
    vm_offset_t page = (vm_offset_t)target & ~(PAGE_SIZE - 1);
    /* The target may straddle two pages (rare for prologues, but possible). */
    vm_size_t span = PAGE_SIZE * 2;

    kern_return_t kr = vm_protect(kernel_map, page, span, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        IOLog("%s: vm_protect(RWX) failed kr=%d\n", kLog, kr);
        return -4;
    }

    write_abs_jmp(target, (uint64_t)replacement);

    /* Restore RX (no W). */
    vm_protect(kernel_map, page, span, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);

    IOLog("%s: routed 0x%llx -> %p (trampoline %p, displaced %d bytes)\n",
          kLog, target_addr, replacement, tramp, displ);
    return 0;
}
