/*
 * mos15-patcher — public API
 *
 * Minimal kernel-function-hook framework for macOS. Lilu replacement for
 * the mos15 project. Three jobs: detect kext loads, look up Mach-O symbols
 * by mangled name, patch function prologues with trampolines.
 *
 * Usage from a consumer kext (e.g. QEMUDisplayPatcher):
 *
 *   1. Add com.docker-macos.kext.mos15Patcher to OSBundleLibraries in
 *      your Info.plist.
 *   2. From your IOService::start() (or earlier), register routes:
 *
 *        static IOReturn (*orgEnableController)(void *) = nullptr;
 *        static IOReturn patchedEnableController(void *that) {
 *            IOReturn r = orgEnableController(that);
 *            // ... your code ...
 *            return r;
 *        }
 *
 *        mp_route_request_t reqs[] = {
 *            { "__ZN17IONDRVFramebuffer16enableControllerEv",
 *              (void *)patchedEnableController,
 *              (void **)&orgEnableController },
 *        };
 *        mp_route_kext("com.apple.iokit.IONDRVSupport", reqs, 1);
 *
 *   3. mp_route_kext returns immediately. If the target kext is already
 *      loaded, it patches synchronously. If not, it queues the routes for
 *      patching when the kext loads later.
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
    const char *symbol;       /* mangled symbol name, e.g. "__ZN17IONDRVFramebuffer..." */
    void       *replacement;  /* your patched function — same signature as target */
    void      **org;          /* set by mp_route to a trampoline that calls the original */
} mp_route_request_t;

/*
 * Register routes on a target kext.
 *  - kext_bundle_id: e.g. "com.apple.iokit.IONDRVSupport"
 *  - reqs / count: array of routes to apply
 *
 * If the target kext is already loaded, patches are applied immediately and
 * *req->org is filled before this function returns.
 *
 * If the target kext is not yet loaded, the request is queued. When the kext
 * loads later, patches are applied and *req->org is filled at that time.
 *
 * Returns 0 on success (immediate patch), 1 on queued, negative on error.
 */
int mp_route_kext(const char *kext_bundle_id,
                  mp_route_request_t *reqs,
                  size_t count);

/*
 * Patch a single function at a known kernel address. Lower-level than
 * mp_route_kext — useful when you've already found the address yourself.
 */
int mp_route_addr(uint64_t target_addr,
                  void     *replacement,
                  void    **org);

#ifdef __cplusplus
}
#endif

#endif /* MOS15_PATCHER_H */
