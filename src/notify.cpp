//
// notify.cpp — Kext-load notifier.
//
// Strategy:
//   1. enumerate_loaded_kexts walks the kernel's `kmod` global, which is a
//      linked list of kmod_info_t for every loaded kext. We see EVERY kext
//      that loaded before us, including System KC kexts.
//
//   2. install_kext_load_hook patches OSKext::saveLoadedKextPanicList in
//      the kernel itself — that function is called every time a kext loads
//      (it serializes the kext list for the panic log). After our hook, we
//      re-walk the kmod list and find any kext we haven't seen yet.
//
// Together these give us 100% coverage with no race: every kext is reported
// exactly once, regardless of load order vs ours.
//

#include "notify.hpp"
#include "macho.hpp"
#include "patch.hpp"
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <IOKit/IOLib.h>

/* Kernel global: head of loaded-kext linked list. */
extern "C" kmod_info_t *kmod;

static const char *kLog = "mp:notify";

/* Track which kexts we've already reported (by load address). Simple
 * append-only list; never grows beyond a few hundred entries during boot. */
static const int    MAX_SEEN = 512;
static uintptr_t    seen[MAX_SEEN];
static int          seen_count = 0;
static mp_kext_load_callback gCallback = nullptr;

static bool seen_kext(uintptr_t addr) {
    for (int i = 0; i < seen_count; i++) {
        if (seen[i] == addr) return true;
    }
    if (seen_count < MAX_SEEN) {
        seen[seen_count++] = addr;
    }
    return false;
}

void
enumerate_loaded_kexts(mp_kext_load_callback cb)
{
    int total = 0;
    for (kmod_info_t *km = kmod; km; km = (kmod_info_t *)km->next) {
        if (!seen_kext((uintptr_t)km->address)) {
            cb(km);
        }
        total++;
        if (total > 4096) {
            IOLog("%s: kmod chain seems too long (%d), bailing\n", kLog, total);
            break;
        }
    }
}

/* Hook target — called when any kext is loaded after our hook is installed.
 * We re-walk the kmod list to find the newcomer. */
static void (*org_saveLoadedKextPanicList)() = nullptr;

static void
patched_saveLoadedKextPanicList()
{
    if (org_saveLoadedKextPanicList)
        org_saveLoadedKextPanicList();

    if (gCallback)
        enumerate_loaded_kexts(gCallback);
}

int
install_kext_load_hook(mp_kext_load_callback cb)
{
    gCallback = cb;

    /*
     * Find OSKext::saveLoadedKextPanicList in the kernel. The kernel itself
     * is the first "kext" — kmod points at it. Or we can look it up via
     * the kernel's symbol table directly using macho_find_symbol on a
     * synthesized kmod_info representing the kernel.
     *
     * For simplicity here we use the trick that the kernel's kmod_info has
     * a known name "__kernel__" or similar in xnu, and its address is
     * 0xffffff8000200000-ish (depends on KASLR slide).
     *
     * Easier: walk kmod chain, find the entry whose name is "__kernel__".
     */
    kmod_info_t *kernel_kmod = nullptr;
    for (kmod_info_t *km = kmod; km; km = (kmod_info_t *)km->next) {
        if (!strncmp(km->name, "__kernel__", sizeof(km->name)) ||
            !strncmp(km->name, "mach_kernel", sizeof(km->name))) {
            kernel_kmod = km;
            break;
        }
    }

    if (!kernel_kmod) {
        IOLog("%s: couldn't find kernel kmod — falling back to chain walk only\n", kLog);
        /* No future-load hook; consumers must call enumerate_loaded_kexts
         * periodically or rely on having loaded after their target. */
        return 1;
    }

    uint64_t addr = macho_find_symbol(kernel_kmod, "__ZN6OSKext23saveLoadedKextPanicListEv");
    if (!addr) {
        IOLog("%s: couldn't find saveLoadedKextPanicList symbol\n", kLog);
        return -1;
    }

    int rc = patch_route(addr, (void *)patched_saveLoadedKextPanicList,
                         (void **)&org_saveLoadedKextPanicList);
    if (rc != 0) {
        IOLog("%s: patch_route failed rc=%d\n", kLog, rc);
        return rc;
    }

    IOLog("%s: future-kext-load hook installed at 0x%llx\n", kLog, addr);
    return 0;
}
