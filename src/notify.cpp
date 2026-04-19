//
// notify.cpp — IOService publish notification + kmod enumeration.
//

#include "notify.hpp"
#include "macho.hpp"
#include "vtable.hpp"
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSArray.h>

extern "C" kmod_info_t *kmod;

static const char *kLog = "mp:notify";

/* Track which kexts we've already reported to avoid double-firing. */
static const int  MAX_SEEN = 512;
static uintptr_t  seen[MAX_SEEN];
static int        seen_count = 0;

static bool seen_kext(uintptr_t addr) {
    for (int i = 0; i < seen_count; i++) if (seen[i] == addr) return true;
    if (seen_count < MAX_SEEN) seen[seen_count++] = addr;
    return false;
}

void
enumerate_loaded_kexts(mp_kext_load_callback cb)
{
    int total = 0;
    for (kmod_info_t *km = kmod; km; km = (kmod_info_t *)km->next) {
        if (!seen_kext((uintptr_t)km->address)) cb(km);
        if (++total > 4096) {
            IOLog("%s: kmod chain too long, bailing\n", kLog);
            break;
        }
    }
}

/* === IOService publish notification ===================================== */

/* Per-notifier state — arrays of routes to apply when the named IOService
 * publishes. We can serve up to MAX_NOTIFIERS distinct classes. */
struct notifier_state {
    const char                  *class_name;       /* e.g. "IONDRVFramebuffer" */
    const char                  *kext_bundle_id;   /* e.g. "com.apple.iokit.IONDRVSupport" */
    mp_pending_publish_route_t  *routes;
    int                          route_count;
    int                          instances_patched;
    IONotifier                  *notifier;
};
static const int MAX_NOTIFIERS = 8;
static notifier_state g_notifiers[MAX_NOTIFIERS];
static int            g_notifier_count = 0;

/* Find a kmod by bundle ID — exact name match. */
static kmod_info_t *
find_kmod(const char *bundle_id)
{
    for (kmod_info_t *km = kmod; km; km = (kmod_info_t *)km->next) {
        if (!strncmp(km->name, bundle_id, sizeof(km->name))) return km;
    }
    return nullptr;
}

static bool
on_publish(void *target, void *refCon, IOService *newService, IONotifier *notifier)
{
    notifier_state *st = (notifier_state *)refCon;
    if (!st) return true;

    IOLog("%s: %s instance %d published — patching vtable\n",
          kLog, st->class_name, st->instances_patched);

    /* Find the kext by exact bundle ID — no scan-all-kmods (which crashed
     * macho_find_symbol on some kexts with weird mach-o layout). */
    kmod_info_t *km = find_kmod(st->kext_bundle_id);
    if (!km) {
        IOLog("%s: kext %s not loaded — can't resolve symbols\n",
              kLog, st->kext_bundle_id);
        return true;
    }

    /*
     * Per-instance vtable swap: allocate a NEW vtable buffer in regular RW
     * kernel memory, copy the original vtable's contents, patch our slots
     * in the copy, then atomically install the copy by writing its address
     * to the instance's vtable pointer (instance+0).
     *
     * Why: writing to the original vtable in __DATA_CONST hits page
     * protection that survives the CR0.WP toggle on Sequoia. The instance
     * itself is on the C++ heap (RW), so writing the 8-byte pointer there
     * is trivial. Only THIS instance is affected — fine for our case
     * (single VMware-SVGA → single IONDRVFramebuffer).
     */
    /* Per-instance vtable swap. COPY_BYTES must be ≥ the real vtable length
     * of the instance's class — any slot we don't copy reads past our
     * allocation and is almost certain to crash when invoked. 8192 bytes =
     * 1024 slots, comfortably larger than any IOKit class's virtual surface.
     * Still lands within a page-sized __DATA_CONST region in practice. */
    const size_t COPY_BYTES = 8192;
    void **orig_vtable = *(void ***)newService;
    IOLog("%s: instance %p, vtable %p\n", kLog, newService, orig_vtable);

    void **new_vtable = (void **)IOMallocAligned(COPY_BYTES, sizeof(void *));
    if (!new_vtable) { IOLog("%s: alloc failed\n", kLog); return true; }
    bzero(new_vtable, COPY_BYTES);
    memcpy(new_vtable, orig_vtable, COPY_BYTES);

    /* Resolve a mangled name: try the caller-specified kext (overrides live
     * there), then IOGraphicsFamily (IOFramebuffer base-class methods for
     * anyone hooking an IONDRVFramebuffer/AppleGraphicsDevicePolicy-style
     * class). Targeted lookup avoids scanning all 60+ kmods on every
     * publish, which was flooding IOLog and panicking mid-callback. */
    kmod_info_t *km_fallback = find_kmod("com.apple.iokit.IOGraphicsFamily");
    IOLog("%s: primary kext %p (%s), fallback %p (IOGraphicsFamily)\n",
          kLog, km, km ? km->name : "nil", km_fallback);
    /* Diagnostic encoding: one char per route into a fixed buffer, then ONE
     * line summarizing all routes, plus up to 3 lines naming the unpatched
     * symbols. The earlier 40-line burst appeared to overflow the kernel
     * message buffer during the publish callback — even the pre-existing
     * on_publish IOLogs got dropped. Keep this quiet. */
    /* Resolver tries EXACT match first, then falls back to PREFIX match.
     * Prefix match accepts names that end with 'E' (Itanium C++ ABI nested-name
     * delimiter) so consumers can pass just "class::method" without paramSig.
     * The typedef-vs-underlying-type footgun goes away. */
    enum class ResolveWhere { Unresolved, Primary, Fallback };
    auto resolve = [&](const char *sym, ResolveWhere &where) -> uint64_t {
        uint64_t a = macho_find_symbol(km, sym);
        if (a) { where = ResolveWhere::Primary; return a; }
        if (km_fallback && km_fallback != km) {
            a = macho_find_symbol(km_fallback, sym);
            if (a) { where = ResolveWhere::Fallback; return a; }
        }
        size_t len = strlen(sym);
        if (len > 0 && sym[len - 1] == 'E') {
            a = macho_find_symbol_by_prefix(km, sym);
            if (a) { where = ResolveWhere::Primary; return a; }
            if (km_fallback && km_fallback != km) {
                a = macho_find_symbol_by_prefix(km_fallback, sym);
                if (a) { where = ResolveWhere::Fallback; return a; }
            }
        }
        where = ResolveWhere::Unresolved;
        return 0;
    };

    /* per-route status chars: P=primary+patched, F=fallback+patched,
     * u=primary+no-slot, f=fallback+no-slot, X=unresolved. */
    char status[64];
    bzero(status, sizeof(status));
    int n = st->route_count;
    if (n > 60) n = 60;

    int patched = 0;
    for (int i = 0; i < n; i++) {
        auto &r = st->routes[i];
        ResolveWhere where = ResolveWhere::Unresolved;
        uint64_t method_addr = resolve(r.method_mangled, where);
        if (!method_addr) { status[i] = 'X'; continue; }
        bool slot_found = false;
        for (size_t s = 0; s < COPY_BYTES / sizeof(void *); s++) {
            if (new_vtable[s] == (void *)method_addr) {
                *r.org = new_vtable[s];
                new_vtable[s] = r.replacement;
                patched++;
                slot_found = true;
                break;
            }
        }
        status[i] = slot_found
            ? (where == ResolveWhere::Primary ? 'P' : 'F')
            : (where == ResolveWhere::Primary ? 'u' : 'f');
    }

    *(void ***)newService = new_vtable;

    /* Real stats: routes are registered in derived/base pairs by the caller
     * (QDP's ROUTE() macro). For each pair, only ONE route should actually
     * patch a vtable slot — the derived class's override wins; the base
     * entry is a fallback for methods NOT overridden. So the true method
     * coverage is: "how many pairs had at least one P/F?" */
    int methods_total    = st->route_count / 2;
    int methods_hooked   = 0;
    int routes_redundant = 0;  /* resolved but slot already taken */
    int routes_unresolved = 0; /* symbol not found anywhere */

    /* Pretty status: "Pf Pf Pf XX Pf..." — space between pairs. */
    char pretty[128];
    int po = 0;
    for (int i = 0; i < n; i++) {
        if (status[i] == 'u' || status[i] == 'f') routes_redundant++;
        if (status[i] == 'X') routes_unresolved++;
        if (po < (int)sizeof(pretty) - 3) {
            pretty[po++] = status[i];
            if (i % 2 == 1) pretty[po++] = ' ';
        }
    }
    pretty[po] = 0;

    for (int m = 0; m < methods_total && m * 2 + 1 < n; m++) {
        char a = status[m * 2], b = status[m * 2 + 1];
        if (a == 'P' || a == 'F' || b == 'P' || b == 'F') methods_hooked++;
    }
    int methods_missing = methods_total - methods_hooked;

    IOLog("%s: methods %d/%d hooked, %d gap, routes P=%d f=%d X=%d [%s]\n",
          kLog, methods_hooked, methods_total, methods_missing,
          patched, routes_redundant, routes_unresolved, pretty);

    /* Durable diagnostic via IOService properties — readable from userspace
     * with `ioreg -c IONDRVFramebuffer -l`. Bypasses the kernel log stream
     * which has been silently dropping on_publish IOLog output. */
    newService->setProperty("MPStatus",          pretty);
    newService->setProperty("MPMethodsHooked",   (unsigned long long)methods_hooked,    32);
    newService->setProperty("MPMethodsTotal",    (unsigned long long)methods_total,     32);
    newService->setProperty("MPMethodsMissing",  (unsigned long long)methods_missing,   32);
    newService->setProperty("MPRoutesPatched",   (unsigned long long)patched,           32);
    newService->setProperty("MPRoutesRedundant", (unsigned long long)routes_redundant,  32);
    newService->setProperty("MPRoutesUnresolved",(unsigned long long)routes_unresolved, 32);

    /* Emit only the TRULY unhooked methods — pairs where neither P nor F. */
    OSArray *gaps = OSArray::withCapacity(8);
    if (gaps) {
        for (int m = 0; m < methods_total && m * 2 + 1 < n; m++) {
            char a = status[m * 2], b = status[m * 2 + 1];
            if (a == 'P' || a == 'F' || b == 'P' || b == 'F') continue;
            char buf[256];
            snprintf(buf, sizeof(buf), "%s | %s",
                     st->routes[m * 2].method_mangled,
                     st->routes[m * 2 + 1].method_mangled);
            OSString *s = OSString::withCString(buf);
            if (s) { gaps->setObject(s); s->release(); }
        }
        newService->setProperty("MPMethodGaps", gaps);
        gaps->release();
    }

    st->instances_patched++;
    return true;  /* keep notifier active — patch every future instance too */
}

int
notify_register_publish(const char *class_name,
                        const char *kext_bundle_id,
                        mp_pending_publish_route_t *routes,
                        int route_count)
{
    if (g_notifier_count >= MAX_NOTIFIERS) {
        IOLog("%s: too many notifiers (max %d)\n", kLog, MAX_NOTIFIERS);
        return -1;
    }

    notifier_state *st = &g_notifiers[g_notifier_count];
    st->class_name = class_name;
    st->kext_bundle_id = kext_bundle_id;
    st->routes = routes;
    st->route_count = route_count;
    st->instances_patched = 0;

    OSDictionary *match = IOService::serviceMatching(class_name);
    if (!match) {
        IOLog("%s: serviceMatching(%s) returned null\n", kLog, class_name);
        return -2;
    }

    st->notifier = IOService::addMatchingNotification(
        gIOPublishNotification, match, on_publish,  /* fires for every instance, current + future */
        /* target */ nullptr, /* refCon */ st);

    match->release();

    if (!st->notifier) {
        IOLog("%s: addMatchingNotification(%s) returned null\n", kLog, class_name);
        return -3;
    }

    g_notifier_count++;
    IOLog("%s: registered publish notification for %s (%d routes pending)\n",
          kLog, class_name, route_count);
    return 0;
}
