//
// start.cpp — mos15-patcher kext entry + public API implementation.
//

#include "../include/mos15_patcher.h"
#include "macho.hpp"
#include "patch.hpp"
#include "vtable.hpp"
#include "notify.hpp"

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <IOKit/IOLib.h>

extern "C" kmod_info_t *kmod;

static const char *kLog = "mp:start";

/* Cache: bundle id → kmod_info_t for already-loaded kexts at our start. */
struct loaded_kext_entry {
    char         bundle_id[64];
    kmod_info_t *kmod;
};
static const int       MAX_LOADED = 512;
static loaded_kext_entry loaded[MAX_LOADED];
static int             loaded_count = 0;

static void cache_kext(kmod_info_t *km) {
    if (loaded_count >= MAX_LOADED) return;
    for (int i = 0; i < loaded_count; i++) if (loaded[i].kmod == km) return;
    auto &e = loaded[loaded_count++];
    strlcpy(e.bundle_id, km->name, sizeof(e.bundle_id));
    e.kmod = km;
}

static kmod_info_t *find_loaded_kext(const char *bundle_id) {
    for (int i = 0; i < loaded_count; i++) {
        if (!strncmp(loaded[i].bundle_id, bundle_id, sizeof(loaded[i].bundle_id)))
            return loaded[i].kmod;
    }
    return nullptr;
}

/*
 * Pending kext-arrival routes — for mp_route_kext when the kext isn't
 * loaded yet. These are NOT applied via IOService notifications (callers
 * use mp_route_on_publish for that path); they wait for kext-load events
 * via the kmod chain delta.
 *
 * For now we only catch already-loaded kexts at our start. Future: add an
 * IOService::addMatchingNotification on a generic class to wake up periodic
 * re-enumeration if needed.
 */
struct pending_route {
    char        bundle_id[64];
    const char *symbol;
    void       *replacement;
    void      **org;
};
static const int    MAX_PENDING = 128;
static pending_route pending[MAX_PENDING];
static int          pending_count = 0;

/*
 * Apply a single route to a loaded kext. Auto-pick: try to find the symbol
 * in any vtable in the kext; if found, vtable-patch. Else, prologue-patch.
 *
 * (Vtable scan is by symbol equality — much like vtable_patch_method does
 * internally. We skip a separate "is this in a vtable" probe for now and
 * always try vtable_patch_method first; if it returns "not found" we fall
 * to prologue patching.)
 */
static int apply_route(kmod_info_t *km, const char *symbol,
                       void *replacement, void **org)
{
    /* TODO: smarter dispatch. For now: try prologue patch via mp_route_addr.
     * mp_route_kext is only used today for kexts whose virtual methods are
     * better patched via mp_route_on_publish, so this path is mostly
     * fallback / static-function support. */
    uint64_t addr = macho_find_symbol(km, symbol);
    if (!addr) {
        IOLog("%s: symbol %s not found in %s\n", kLog, symbol, km->name);
        return -10;
    }
    return mp_route_addr(addr, replacement, org);
}

extern "C"
int mp_route_kext(const char *kext_bundle_id,
                  mp_route_request_t *reqs,
                  size_t count)
{
    if (!kext_bundle_id || !reqs || count == 0) return -1;

    kmod_info_t *km = find_loaded_kext(kext_bundle_id);
    if (km) {
        int err = 0;
        for (size_t i = 0; i < count; i++) {
            if (apply_route(km, reqs[i].symbol, reqs[i].replacement, reqs[i].org) != 0)
                err++;
        }
        return err == 0 ? 0 : -2;
    }

    if (pending_count + (int)count > MAX_PENDING) return -3;
    for (size_t i = 0; i < count; i++) {
        auto &p = pending[pending_count++];
        strlcpy(p.bundle_id, kext_bundle_id, sizeof(p.bundle_id));
        p.symbol = reqs[i].symbol;
        p.replacement = reqs[i].replacement;
        p.org = reqs[i].org;
    }
    IOLog("%s: queued %zu route(s) for %s (kext not yet loaded)\n",
          kLog, count, kext_bundle_id);
    return 1;
}

extern "C"
int mp_route_on_publish(const char *class_name,
                        const char *kext_bundle_id,
                        mp_route_request_t *reqs,
                        size_t count)
{
    if (!class_name || !kext_bundle_id || !reqs || count == 0) return -1;

    /* Convert mp_route_request_t (caller-friendly) to mp_pending_publish_route_t
     * (notify.cpp's internal format). The caller's reqs lifetime must outlive
     * the notifier — we just take a pointer. For our use case, reqs is a
     * static array in the consumer kext, so this is fine. */
    static mp_pending_publish_route_t storage[64];  /* shared storage */
    static int storage_used = 0;
    if (storage_used + (int)count > 64) {
        IOLog("%s: publish-route storage exhausted\n", kLog);
        return -2;
    }
    mp_pending_publish_route_t *base = &storage[storage_used];
    for (size_t i = 0; i < count; i++) {
        storage[storage_used++] = (mp_pending_publish_route_t){
            .kext_bundle_id = nullptr,  /* found via vtable scan */
            .method_mangled = reqs[i].symbol,
            .replacement    = reqs[i].replacement,
            .org            = reqs[i].org,
        };
    }
    return notify_register_publish(class_name, kext_bundle_id, base, (int)count);
}

extern "C"
int mp_route_addr(uint64_t target_addr, void *replacement, void **org)
{
    return patch_route(target_addr, replacement, org);
}

extern "C"
kern_return_t mp_start(kmod_info_t *ki, void *d)
{
    IOLog("%s: mos15-patcher starting\n", kLog);
    enumerate_loaded_kexts(cache_kext);
    IOLog("%s: cached %d already-loaded kexts\n", kLog, loaded_count);
    return KERN_SUCCESS;
}

extern "C"
kern_return_t mp_stop(kmod_info_t *ki, void *d)
{
    return KERN_FAILURE;  /* don't allow unload — patches are permanent */
}
