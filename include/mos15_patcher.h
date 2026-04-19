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

/*
 * === Route-construction helpers (C++ only) ==================================
 *
 * Write a route table without hand-mangling Itanium C++ ABI parameter
 * signatures. The symbol you hand to the patcher is just the PREFIX up to
 * (but including) the 'E' nested-name delimiter:
 *
 *      __ZN<N><class><M><method>E
 *
 * mos15-patcher's resolver tries exact-match first, then falls back to
 * prefix-match — so the first symbol starting with that prefix wins. This
 * kills the whole class of typedef-mangling bugs (e.g. IOPixelAperture being
 * a typedef for int mangles as 'i', not '15IOPixelAperture').
 *
 * Disambiguation: if two overloads share the same prefix the patcher logs
 * the ambiguity and refuses to resolve — pass the full mangled name via
 * MP_ROUTE_EXACT() in that case.
 *
 * Usage:
 *
 *   mp_route_request_t reqs[] = {
 *       MP_ROUTE_PAIR("IONDRVFramebuffer", "IOFramebuffer",
 *                     "enableController", patchedEnable, orgEnable),
 *       MP_ROUTE_PAIR("IONDRVFramebuffer", "IOFramebuffer",
 *                     "getApertureRange", patchedAperture, orgAperture),
 *       MP_ROUTE_EXACT("__ZN17IONDRVFramebuffer3fooEii", patchedFoo, orgFoo),
 *   };
 */
#ifdef __cplusplus

#include <libkern/libkern.h>  /* strlen, snprintf */

namespace mp {
    /* Build "__ZN<len><cls><len><method>E" at compile-ish time.
     * We do it with a static buffer per call site via a lambda so each
     * macro expansion gets its own storage. Not thread-safe, but route
     * tables are built once at kext start. */
    inline const char *build_prefix(char *buf, size_t sz, const char *cls, const char *method) {
        /* snprintf exists in the kernel via libkern.h. */
        snprintf(buf, sz, "__ZN%u%s%u%sE",
                 (unsigned)strlen(cls), cls,
                 (unsigned)strlen(method), method);
        return buf;
    }
}

/* Build a single-class route from a class+method name (prefix match). */
#define MP_ROUTE(cls, method, replacement, org)                                 \
    []() -> mp_route_request_t {                                                \
        static char _buf[128];                                                  \
        return { mp::build_prefix(_buf, sizeof(_buf), (cls), (method)),         \
                 (void *)(replacement), (void **)&(org) };                      \
    }()

/* Disambiguated variant — supply an explicit Itanium C++ ABI paramSig
 * (e.g. "jjjPv", "i", "P24IODisplayModeInformation"). Required when the
 * method is overloaded; the patcher logs an ambiguity warning if you try
 * prefix-match on such a symbol. */
#define MP_ROUTE_SIG(cls, method, sig, replacement, org)                        \
    []() -> mp_route_request_t {                                                \
        static char _buf[192];                                                  \
        snprintf(_buf, sizeof(_buf), "__ZN%u%s%u%sE%s",                         \
                 (unsigned)strlen(cls), (cls),                                  \
                 (unsigned)strlen(method), (method), (sig));                    \
        return { _buf, (void *)(replacement), (void **)&(org) };                \
    }()

/* Build TWO routes in one entry (derived class + base class), sharing the
 * same replacement+org. The derived route wins when the derived class
 * overrides the method; the base route catches methods inherited without
 * override. Emits as a C99 initializer, so must appear inside an
 * aggregate-initializer list. */
#define MP_ROUTE_PAIR(derived_cls, base_cls, method, replacement, org)          \
    MP_ROUTE((derived_cls), (method), (replacement), (org)),                    \
    MP_ROUTE((base_cls),    (method), (replacement), (org))

/* Disambiguated pair — for overloaded methods. */
#define MP_ROUTE_PAIR_SIG(derived_cls, base_cls, method, sig, replacement, org) \
    MP_ROUTE_SIG((derived_cls), (method), (sig), (replacement), (org)),         \
    MP_ROUTE_SIG((base_cls),    (method), (sig), (replacement), (org))

/* Full mangled-name escape hatch for when neither of the above fits. */
#define MP_ROUTE_EXACT(mangled_symbol, replacement, org)                        \
    mp_route_request_t{ (mangled_symbol), (void *)(replacement), (void **)&(org) }

#endif /* __cplusplus */

#endif /* MOS15_PATCHER_H */
