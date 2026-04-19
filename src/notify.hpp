//
// notify.hpp — Two coverage paths for "patch when target is available":
//
// (a) IOService notification: register for class published events. When
//     macOS publishes an instance, we read its vtable from the instance
//     pointer and patch slots. NO kernel-text patching, NO polling, NO
//     RIP-rel rewriting. Apple's blessed API. The cleanest path.
//
// (b) kmod chain enumeration at start: walk the existing kmod list at
//     mp_start so callers can issue mp_route_kext for already-loaded
//     kexts and have them patch synchronously.
//

#pragma once

#include <stdint.h>
#include <mach/kmod.h>

/* Walk the kernel's kmod chain calling cb for each loaded kext. */
typedef void (*mp_kext_load_callback)(kmod_info_t *kmod);
void enumerate_loaded_kexts(mp_kext_load_callback cb);

/* Per-route info passed through the IOService notification path. */
typedef struct mp_pending_publish_route {
    const char *kext_bundle_id;
    const char *method_mangled;
    void       *replacement;
    void      **org;
} mp_pending_publish_route_t;

/* Register an IOService publish notification on `class_name`. When the
 * matching IOService is created, walk its vtable and patch the slots for
 * each pending route whose kext we can find via macho_find_symbol.
 *
 * Returns 0 on success (notifier registered), negative on error. */
int notify_register_publish(const char *class_name,
                            const char *kext_bundle_id,
                            mp_pending_publish_route_t *routes,
                            int route_count);
