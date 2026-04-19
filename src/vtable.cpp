//
// vtable.cpp — C++ vtable patching.
//

#include "vtable.hpp"
#include "macho.hpp"
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <IOKit/IOLib.h>

extern "C" void wp_write_kernel_bytes(uint8_t *dst, const uint8_t *src, size_t n);
/* Defined in patch.cpp — re-uses the WP-bit-toggle write trick. We declare
 * it extern here so vtable.cpp can write to vtables in __DATA_CONST. */

static const char *kLog = "mp:vtable";

/* Vtable scan limit — arbitrary safety cap. Real vtables for IONDRVFramebuffer
 * have ~80 entries. 256 is generous. */
#define VTABLE_MAX_SLOTS 256

int
vtable_patch_method_via_instance(void *instance,
                                 uint64_t method_addr,
                                 void *replacement,
                                 void **org)
{
    if (!instance || !method_addr || !replacement) return -1;

    /* First 8 bytes of any C++ instance is its vtable pointer. */
    void **vtable = *(void ***)instance;
    if (!vtable) return -2;

    /* Itanium ABI: vtable starts with 16 bytes of (offset-to-top, typeinfo).
     * Function pointers begin at offset +16 bytes (= 2 slots on x86_64). */
    void **slots = vtable;  /* we just scan from the start; pointer matches will
                               only happen at function-pointer slots anyway */

    for (int i = 0; i < VTABLE_MAX_SLOTS; i++) {
        if (slots[i] == (void *)method_addr) {
            *org = slots[i];
            wp_write_kernel_bytes((uint8_t *)&slots[i],
                                  (const uint8_t *)&replacement,
                                  sizeof(void *));
            IOLog("%s: patched slot %d (vtable %p) — old=%p new=%p\n",
                  kLog, i, vtable, *org, replacement);
            return 0;
        }
    }

    IOLog("%s: method addr 0x%llx not found in vtable %p (scanned %d slots)\n",
          kLog, method_addr, vtable, VTABLE_MAX_SLOTS);
    return -3;
}

int
vtable_patch_method(kmod_info_t *kmod,
                    const char *class_mangled,
                    const char *method_mangled,
                    void *replacement,
                    void **org)
{
    /* Build vtable symbol name: __ZTV<class_mangled> */
    char vt_sym[160];
    snprintf(vt_sym, sizeof(vt_sym), "__ZTV%s", class_mangled);

    uint64_t vt_addr = macho_find_symbol(kmod, vt_sym);
    if (!vt_addr) {
        IOLog("%s: vtable symbol %s not found\n", kLog, vt_sym);
        return -10;
    }

    uint64_t method_addr = macho_find_symbol(kmod, method_mangled);
    if (!method_addr) {
        IOLog("%s: method symbol %s not found\n", kLog, method_mangled);
        return -11;
    }

    /* The vtable symbol address is the start of the typeinfo header, NOT the
     * first function pointer slot. But we scan from the start anyway and
     * matches only happen at function-pointer slots. */
    void **slots = (void **)vt_addr;
    for (int i = 0; i < VTABLE_MAX_SLOTS; i++) {
        if (slots[i] == (void *)method_addr) {
            *org = slots[i];
            wp_write_kernel_bytes((uint8_t *)&slots[i],
                                  (const uint8_t *)&replacement,
                                  sizeof(void *));
            IOLog("%s: patched %s slot %d — old=%p new=%p\n",
                  kLog, method_mangled, i, *org, replacement);
            return 0;
        }
    }

    IOLog("%s: %s addr 0x%llx not found in %s (scanned %d slots)\n",
          kLog, method_mangled, method_addr, vt_sym, VTABLE_MAX_SLOTS);
    return -12;
}
