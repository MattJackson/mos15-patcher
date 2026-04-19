/*
 * mos15-patcher — public API.
 *
 * Two patching strategies:
 *
 *   A. VTABLE PATCHING (preferred for C++ virtual methods)
 *      Find the class vtable, scan for the method address, swap with your
 *      replacement. No prologue rewrite, no trampoline, no RIP-rel issues.
 *      "Original" is just the saved old vtable pointer.
 *
 *   B. PROLOGUE PATCHING (for static functions / non-virtual methods)
 *      Overwrite the function's first ~14 bytes with an absolute JMP to
 *      your replacement. Displaced bytes go in a trampoline that ends with
 *      a JMP back to (target + N). RIP-relative instructions in the
 *      displaced bytes are auto-rewritten for the new address.
 *
 * Two delivery mechanisms:
 *
 *   1. mp_route_kext — auto-pick A or B based on whether the symbol is
 *      found in any class's vtable. If the kext isn't loaded yet, requests
 *      are queued and applied when it loads.
 *
 *   2. mp_route_on_publish — register an IOService publish notification.
 *      When macOS creates an instance of the named class, we patch its
 *      vtable. Apple's blessed kext-arrival API; no kernel-text writes.
 *      Always uses strategy A (vtable patching).
 */
#ifndef MOS15_PATCHER_H
#define MOS15_PATCHER_H

#include <mach/mach_types.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mp_route_request {
    const char *symbol;       /* mangled symbol name */
    void       *replacement;  /* your hook */
    void      **org;          /* set to original (vtable ptr or trampoline addr) */
} mp_route_request_t;

/*
 * Preferred path for patching IOService classes.
 *
 *   class_name   : C++ class name (UNMANGLED, e.g. "IONDRVFramebuffer")
 *   reqs         : array of routes; reqs[i].symbol is the mangled method name
 *
 * Registers an IOService publish notification. When a matching instance is
 * created, walks its vtable and patches the slots for each route. Always
 * vtable patching — no trampolines.
 *
 * Returns 0 on success (notifier registered), negative on error.
 */
int mp_route_on_publish(const char *class_name,
                        const char *kext_bundle_id,
                        mp_route_request_t *reqs,
                        size_t count);

/*
 * Auto-dispatch route registration on a kext.
 *
 *   kext_bundle_id : e.g. "com.apple.iokit.IONDRVSupport"
 *
 * For each route: look up the symbol's address in the kext, check if it's
 * a vtable slot in any class — if yes, vtable patch; if no, prologue patch.
 * If the kext isn't loaded, requests are queued for when it loads.
 *
 * Returns 0 on immediate success, 1 on queued, negative on error.
 */
int mp_route_kext(const char *kext_bundle_id,
                  mp_route_request_t *reqs,
                  size_t count);

/*
 * Lower-level: prologue-patch a function at a known runtime address.
 * For when you've already done your own symbol lookup. Builds a trampoline,
 * rewrites RIP-relative offsets, installs an absolute JMP at the target.
 */
int mp_route_addr(uint64_t target_addr, void *replacement, void **org);

#ifdef __cplusplus
}
#endif

#endif /* MOS15_PATCHER_H */
