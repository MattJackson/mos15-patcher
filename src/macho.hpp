//
// macho.hpp — Mach-O symbol lookup for kernel-loaded kexts.
//
// Given a runtime-loaded kext (its kmod_info_t.address points at a
// mach_header_64), find the address of a symbol by name.
//
// For Boot KC kexts the symbol table is local to the kext (LC_SYMTAB).
// For System KC kexts the symbol table lives in the parent System KC's
// __LINKEDIT and we have to follow the offsets carefully — see the
// implementation for the gory bits.
//

#pragma once

#include <stdint.h>
#include <mach/kmod.h>

/*
 * Find a symbol's address in a loaded kext.
 *
 *  kmod    — the kmod_info_t (gives the kext's load address + size)
 *  symbol  — mangled symbol name (e.g. "__ZN17IONDRVFramebuffer16enableControllerEv")
 *
 * Returns the symbol's runtime kernel address, or 0 if not found.
 */
uint64_t macho_find_symbol(kmod_info_t *kmod, const char *symbol);
