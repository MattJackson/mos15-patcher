//
// vtable.hpp — C++ vtable patching.
//
// For virtual methods on a class, the vtable holds function pointers we
// can swap directly. No prologue patching, no trampoline, no RIP-relative
// rewriting. The original is just the saved old pointer.
//
// Itanium C++ ABI:
//   - Vtable symbol: __ZTV<class-name>  (e.g. __ZTV17IONDRVFramebuffer)
//   - Layout: [16-byte header (typeinfo + offset-to-top)] [function ptrs...]
//   - One slot per virtual method, in declaration + inheritance order.
//

#pragma once

#include <stdint.h>
#include <mach/kmod.h>

/*
 * Patch a virtual method. Looks up the method's address in `kmod`, finds
 * the class's vtable, locates the slot containing that address, swaps it
 * for `replacement`, fills *org with the previous pointer.
 *
 *   kmod          : kmod_info_t for the kext containing both vtable and method
 *   class_mangled : e.g. "17IONDRVFramebuffer" (length-prefixed C++ name)
 *   method_mangled: e.g. "__ZN17IONDRVFramebuffer16enableControllerEv"
 *   replacement   : your hook (same signature as method)
 *   org           : filled with previous function pointer (call to invoke original)
 *
 * Returns 0 on success, negative on error.
 */
int vtable_patch_method(kmod_info_t *kmod,
                        const char *class_mangled,
                        const char *method_mangled,
                        void *replacement,
                        void **org);

/*
 * Patch a virtual method directly via an INSTANCE pointer. Used when you
 * receive an IOService instance from an IOService notification and want
 * to patch its vtable. Reads the vtable from the instance's first 8 bytes.
 *
 * Returns 0 on success, negative on error.
 */
int vtable_patch_method_via_instance(void *instance,
                                     uint64_t method_addr,  /* target's runtime addr */
                                     void *replacement,
                                     void **org);
