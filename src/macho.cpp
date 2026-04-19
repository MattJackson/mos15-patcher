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
    if (hdr->magic != MH_MAGIC_64) {
        IOLog("%s: bad magic 0x%x at kmod %s\n", kLog, hdr->magic, kmod->name);
        return 0;
    }

    symtab_command *symtab = (symtab_command *)find_load_command(hdr, LC_SYMTAB);
    if (!symtab) {
        IOLog("%s: no LC_SYMTAB in %s\n", kLog, kmod->name);
        return 0;
    }

    /*
     * Standalone Mach-O interpretation: symoff and stroff are file offsets
     * from hdr. In a runtime-loaded kext, the file == in-memory image, so
     * these offsets are valid as-is.
     *
     * KC-embedded kext interpretation: symoff is a file offset from the
     * parent KC's start. We need to find __LINKEDIT and compute the runtime
     * pointer differently. For now, we try the standalone interpretation
     * and validate by checking that the first symbol's name string is
     * within reasonable bounds.
     */
    nlist_64 *symbols = (nlist_64 *)((uint8_t *)hdr + symtab->symoff);
    const char *strings = (const char *)((uint8_t *)hdr + symtab->stroff);

    /* Validate: first non-empty string should look like a symbol name (start with _) */
    bool standalone_valid = false;
    if (symtab->nsyms > 0) {
        uint32_t strx = symbols[0].n_un.n_strx;
        if (strx < symtab->strsize && strings[strx] != '\0') {
            const char *first_name = strings + strx;
            standalone_valid = (first_name[0] == '_' || first_name[0] == '.' ||
                               (first_name[0] >= 'a' && first_name[0] <= 'z') ||
                               (first_name[0] >= 'A' && first_name[0] <= 'Z'));
        }
    }

    if (!standalone_valid) {
        /*
         * Fall back to KC-embedded interpretation: walk segments to find
         * __LINKEDIT, use its (vmaddr - fileoff) as the file→VA delta, then
         * read symtab from (vmaddr_of_LINKEDIT + symoff - fileoff_of_LINKEDIT).
         *
         * In Apple's KC format, the kext's __LINKEDIT vmaddr points into
         * the parent KC's combined __LINKEDIT segment.
         */
        uint64_t linkedit_vmaddr = 0;
        uint64_t linkedit_fileoff = 0;
        bool found_linkedit = false;
        for_each_segment(hdr, [&](segment_command_64 *seg) {
            if (!strcmp(seg->segname, "__LINKEDIT")) {
                linkedit_vmaddr = seg->vmaddr;
                linkedit_fileoff = seg->fileoff;
                found_linkedit = true;
            }
        });

        if (!found_linkedit) {
            IOLog("%s: %s: standalone symtab invalid AND no __LINKEDIT — bailing\n",
                  kLog, kmod->name);
            return 0;
        }

        symbols = (nlist_64 *)(linkedit_vmaddr + (symtab->symoff - linkedit_fileoff));
        strings = (const char *)(linkedit_vmaddr + (symtab->stroff - linkedit_fileoff));
    }

    /* Linear scan. No hash table — simple for now. */
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        uint32_t strx = symbols[i].n_un.n_strx;
        if (strx >= symtab->strsize) continue;
        const char *name = strings + strx;
        if (!strcmp(name, symbol)) {
            return symbols[i].n_value;
        }
    }

    return 0;
}
