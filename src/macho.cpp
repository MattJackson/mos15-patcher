//
// macho.cpp — Mach-O symbol lookup.
//
// The kmod_info_t.address points at a mach_header_64. We walk LC_SEGMENT_64
// and LC_SYMTAB load commands to find the symbol table, then linearly scan
// it comparing names.
//
// On x86_64 with PIE / KASLR, all addresses in the in-memory Mach-O image
// have already been relocated by the loader. nlist_64.n_value is the
// runtime kernel address.
//
// One subtlety: in Apple's kernel collection format (Boot KC / System KC),
// individual kexts share a symbol table in the parent KC's __LINKEDIT
// segment. The kext's mach_header has LC_SYMTAB pointing at file offsets
// that are RELATIVE TO THE KC, not relative to the kext's own load address.
//
// We handle both cases: try the standalone interpretation first; if that
// gives garbage (n_strx out of range, or symbol names look invalid), fall
// back to interpreting offsets as KC-relative by looking for the parent KC.
//

#include "macho.hpp"
#include <mach/mach_types.h>
#include <mach/kmod.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <libkern/libkern.h>
#include <IOKit/IOLib.h>

static const char *kLog = "mp:macho";

/* Walk load commands looking for a load command of `cmd_type`. */
static load_command *
find_load_command(mach_header_64 *hdr, uint32_t cmd_type)
{
    load_command *lc = (load_command *)((uint8_t *)hdr + sizeof(mach_header_64));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == cmd_type)
            return lc;
        lc = (load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return nullptr;
}

/* Walk load commands and call `fn` on each LC_SEGMENT_64 segment. */
template <typename F>
static void
for_each_segment(mach_header_64 *hdr, F fn)
{
    load_command *lc = (load_command *)((uint8_t *)hdr + sizeof(mach_header_64));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            fn((segment_command_64 *)lc);
        }
        lc = (load_command *)((uint8_t *)lc + lc->cmdsize);
    }
}

uint64_t
macho_find_symbol(kmod_info_t *kmod, const char *symbol)
{
    if (!kmod || !symbol) return 0;

    mach_header_64 *hdr = (mach_header_64 *)kmod->address;
    if (!hdr || hdr->magic != MH_MAGIC_64) return 0;

    symtab_command *symtab = (symtab_command *)find_load_command(hdr, LC_SYMTAB);
    if (!symtab) return 0;

    /*
     * The kernel and any runtime-loaded mach-o image can be interpreted two
     * ways for symtab access:
     *   (A) Standalone: symoff/stroff are byte offsets from the mach header
     *       itself. Works when the file was loaded contiguously into memory
     *       (typical for the kernel and individual kexts).
     *   (B) KC-embedded: symoff/stroff are file offsets from the parent
     *       collection's start; the actual runtime addresses are reached via
     *       __LINKEDIT's vmaddr/fileoff delta. (System KC kexts.)
     *
     * Earlier we tried to PICK between (A) and (B) using a heuristic on the
     * first symbol's name. That mis-classified the kernel. New approach: try
     * BOTH and return whichever actually finds the symbol.
     */

    /*
     * Unified interpretation via __LINKEDIT:
     *   symbols = linkedit.vmaddr + (symtab.symoff - linkedit.fileoff)
     *   strings = linkedit.vmaddr + (symtab.stroff - linkedit.fileoff)
     *
     * This works for BOTH standalone mach-o (where hdr = linkedit.vmaddr -
     * linkedit.fileoff makes it algebraically equivalent to hdr+symoff)
     * AND KC-embedded kexts (where hdr has no direct relationship to symtab
     * offsets because those are KC-relative). No heuristic needed — dropping
     * the previous "standalone vs KC" split. The __LINKEDIT segment is
     * guaranteed to exist in every valid mach-o image.
     */
    uint64_t linkedit_vmaddr = 0;
    uint64_t linkedit_fileoff = 0;
    uint64_t linkedit_vmsize = 0;
    bool found_linkedit = false;
    for_each_segment(hdr, [&](segment_command_64 *seg) {
        if (!strcmp(seg->segname, "__LINKEDIT")) {
            linkedit_vmaddr = seg->vmaddr;
            linkedit_fileoff = seg->fileoff;
            linkedit_vmsize = seg->vmsize;
            found_linkedit = true;
        }
    });
    if (!found_linkedit) return 0;
    if (symtab->symoff < linkedit_fileoff ||
        symtab->stroff < linkedit_fileoff ||
        symtab->symoff - linkedit_fileoff > linkedit_vmsize ||
        symtab->stroff - linkedit_fileoff > linkedit_vmsize) {
        return 0;
    }

    nlist_64 *symbols = (nlist_64 *)(linkedit_vmaddr + (symtab->symoff - linkedit_fileoff));
    const char *strings = (const char *)(linkedit_vmaddr + (symtab->stroff - linkedit_fileoff));
    uint32_t strsize = symtab->strsize;

    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        uint32_t strx = symbols[i].n_un.n_strx;
        if (strx >= strsize) continue;
        const char *name = strings + strx;
        if (!strcmp(name, symbol)) return symbols[i].n_value;
    }

    /* Silent miss — callers scan many kexts and log once at the top level. */
    return 0;
}

uint64_t
macho_find_symbol_by_prefix(kmod_info_t *kmod, const char *prefix)
{
    if (!kmod || !prefix) return 0;

    mach_header_64 *hdr = (mach_header_64 *)kmod->address;
    if (!hdr || hdr->magic != MH_MAGIC_64) return 0;

    symtab_command *symtab = (symtab_command *)find_load_command(hdr, LC_SYMTAB);
    if (!symtab) return 0;

    uint64_t linkedit_vmaddr = 0, linkedit_fileoff = 0, linkedit_vmsize = 0;
    bool found_linkedit = false;
    for_each_segment(hdr, [&](segment_command_64 *seg) {
        if (!strcmp(seg->segname, "__LINKEDIT")) {
            linkedit_vmaddr = seg->vmaddr;
            linkedit_fileoff = seg->fileoff;
            linkedit_vmsize = seg->vmsize;
            found_linkedit = true;
        }
    });
    if (!found_linkedit) return 0;
    if (symtab->symoff < linkedit_fileoff ||
        symtab->stroff < linkedit_fileoff ||
        symtab->symoff - linkedit_fileoff > linkedit_vmsize ||
        symtab->stroff - linkedit_fileoff > linkedit_vmsize) {
        return 0;
    }

    nlist_64 *symbols = (nlist_64 *)(linkedit_vmaddr + (symtab->symoff - linkedit_fileoff));
    const char *strings = (const char *)(linkedit_vmaddr + (symtab->stroff - linkedit_fileoff));
    uint32_t strsize = symtab->strsize;
    size_t prefix_len = strlen(prefix);

    uint64_t first_match = 0;
    const char *first_name = nullptr;
    int match_count = 0;

    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        uint32_t strx = symbols[i].n_un.n_strx;
        if (strx >= strsize) continue;
        const char *name = strings + strx;
        if (strncmp(name, prefix, prefix_len) != 0) continue;
        match_count++;
        if (match_count == 1) {
            first_match = symbols[i].n_value;
            first_name = name;
        } else if (match_count == 2) {
            IOLog("%s: prefix '%s' is ambiguous: '%s' + '%s' (pass full mangled name)\n",
                  kLog, prefix, first_name, name);
            return 0;
        }
    }

    return (match_count == 1) ? first_match : 0;
}
