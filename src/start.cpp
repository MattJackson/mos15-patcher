//
// start.cpp — mos15-patcher kext entry, public API.
//
// This kext exports mp_route_kext / mp_route_addr for consumer kexts (e.g.
// QEMUDisplayPatcher) to call from their _start.
//
// Lifecycle:
//   1. _start (kmod_info entry): enumerate all already-loaded kexts so we
//      can serve mp_route_kext requests immediately, AND install the
//      future-load hook.
//   2. Consumer kext loads after us, calls mp_route_kext("...", reqs, n).
//   3. If target kext is in our cache → patch synchronously, fill *org.
//      Else → queue for later, fire when target loads.
//

#include "../include/mos15_patcher.h"
#include "macho.hpp"
#include "patch.hpp"
#include "notify.hpp"

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <IOKit/IOLib.h>

extern "C" kmod_info_t *kmod;

static const char *kLog = "mp:start";

/* Cache: bundle id -> kmod_info_t pointer for every loaded kext. */
struct loaded_kext_entry {
    char           bundle_id[64];
    kmod_info_t   *kmod;
};

static const int       MAX_LOADED = 512;
static loaded_kext_entry loaded[MAX_LOADED];
static int             loaded_count = 0;

static void cache_kext(kmod_info_t *km) {
    if (loaded_count >= MAX_LOADED) return;
    /* Already cached? */
    for (int i = 0; i < loaded_count; i++) {
        if (loaded[i].kmod == km) return;
    }
    loaded_count++;
    auto &e = loaded[loaded_count - 1];
    strlcpy(e.bundle_id, km->name, sizeof(e.bundle_id));
    e.kmod = km;
}

static kmod_info_t *find_loaded_kext(const char *bundle_id) {
    for (int i = 0; i < loaded_count; i++) {
        if (!strncmp(loaded[i].bundle_id, bundle_id, sizeof(loaded[i].bundle_id))) {
            return loaded[i].kmod;
        }
    }
    return nullptr;
}

/* Pending route requests waiting on a kext that hasn't loaded yet. */
struct pending_route {
    char            bundle_id[64];
    const char     *symbol;       /* must be string-literal-stable */
    void           *replacement;
    void          **org;
};

static const int    MAX_PENDING = 128;
static pending_route pending[MAX_PENDING];
static int          pending_count = 0;

static int apply_route_now(kmod_info_t *km, const char *symbol,
                           void *replacement, void **org)
{
    uint64_t addr = macho_find_symbol(km, symbol);
    if (!addr) {
        IOLog("%s: symbol %s not found in %s\n", kLog, symbol, km->name);
        return -10;
    }
    int rc = patch_route(addr, replacement, org);
    if (rc != 0) {
        IOLog("%s: patch_route failed rc=%d for %s in %s\n",
              kLog, rc, symbol, km->name);
        return rc;
    }
    return 0;
}

static void on_kext_seen(kmod_info_t *km)
{
    cache_kext(km);

    /* Drain any pending routes for this kext. */
    int i = 0;
    while (i < pending_count) {
        if (!strncmp(pending[i].bundle_id, km->name,
                     sizeof(pending[i].bundle_id))) {
            apply_route_now(km, pending[i].symbol,
                            pending[i].replacement, pending[i].org);
            /* Remove by swapping last in. */
            pending[i] = pending[pending_count - 1];
            pending_count--;
        } else {
            i++;
        }
    }
}

extern "C"
int mp_route_kext(const char *kext_bundle_id,
                  mp_route_request_t *reqs,
                  size_t count)
{
    if (!kext_bundle_id || !reqs || count == 0) return -1;

    kmod_info_t *km = find_loaded_kext(kext_bundle_id);
    if (km) {
        /* Apply all routes immediately. */
        int errors = 0;
        for (size_t i = 0; i < count; i++) {
            int rc = apply_route_now(km, reqs[i].symbol,
                                     reqs[i].replacement, reqs[i].org);
            if (rc != 0) errors++;
        }
        return errors == 0 ? 0 : -2;
    }

    /* Queue for later. */
    if (pending_count + (int)count > MAX_PENDING) {
        IOLog("%s: pending queue full\n", kLog);
        return -3;
    }
    for (size_t i = 0; i < count; i++) {
        auto &p = pending[pending_count++];
        strlcpy(p.bundle_id, kext_bundle_id, sizeof(p.bundle_id));
        p.symbol = reqs[i].symbol;
        p.replacement = reqs[i].replacement;
        p.org = reqs[i].org;
    }
    IOLog("%s: queued %zu route(s) for %s (not yet loaded)\n",
          kLog, count, kext_bundle_id);
    return 1;
}

extern "C"
int mp_route_addr(uint64_t target_addr, void *replacement, void **org)
{
    return patch_route(target_addr, replacement, org);
}

/* Kext start: enumerate loaded kexts + install future-load hook. */
extern "C"
kern_return_t mp_start(kmod_info_t *ki, void *d)
{
    IOLog("%s: mos15-patcher starting\n", kLog);
    enumerate_loaded_kexts(on_kext_seen);
    IOLog("%s: cached %d already-loaded kexts\n", kLog, loaded_count);

    int rc = install_kext_load_hook(on_kext_seen);
    if (rc < 0) {
        IOLog("%s: install_kext_load_hook failed rc=%d (consumers may miss late kext loads)\n",
              kLog, rc);
    }

    return KERN_SUCCESS;
}

extern "C"
kern_return_t mp_stop(kmod_info_t *ki, void *d)
{
    /* We deliberately don't support unload — our patches modify shared
     * kernel pages and ripping them out is risky. Returning failure tells
     * the kernel "do not unload me." */
    return KERN_FAILURE;
}
