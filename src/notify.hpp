//
// notify.hpp — Hook OSKext::saveLoadedKextPanicList for future kext loads.
//

#pragma once

#include <stdint.h>
#include <mach/kmod.h>

/* Called for every kmod when iterating already-loaded kexts at start, AND
 * for every newly-loaded kext after install_kext_load_hook(). */
typedef void (*mp_kext_load_callback)(kmod_info_t *kmod);

/* Walk the existing kmod chain, calling cb for each. */
void enumerate_loaded_kexts(mp_kext_load_callback cb);

/* Install a hook that fires cb for each NEWLY loaded kext from now on.
 * Idempotent. Returns 0 on success. */
int install_kext_load_hook(mp_kext_load_callback cb);
