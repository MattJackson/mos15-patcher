# mos15-patcher

Minimal kernel-function-hook framework for macOS — Lilu replacement built for the **mos15** project.

## Why exist

Lilu is a great general-purpose patcher (~10–15k lines, 20+ files) but for our needs (mos15) it does too much, and we hit reliability issues with kext-load detection on Sequoia in our VM. mos15-patcher does only the three things we need, in ~600 lines we own:

1. **Detect kext loads** — both already-loaded (kmod chain walk at our `_start`) and future loads (hook `OSKext::saveLoadedKextPanicList`). No queue races, no "loaded 5th, missed first 4" — every kext seen exactly once.
2. **Look up Mach-O symbols** by mangled name in any loaded kext (Boot KC, System KC, Aux KC).
3. **Patch function prologues** with absolute jumps to your replacement, allocate trampolines so you can call the original.

## Public API

```c
#include <mos15_patcher.h>

// Your replacement — same signature as target.
static IOReturn (*orgEnableController)(void *) = nullptr;
static IOReturn patchedEnableController(void *that) {
    IOReturn r = orgEnableController(that);
    // ... your code ...
    return r;
}

// Register routes. Synchronous if target kext is already loaded; queued
// otherwise. *org is filled with a trampoline pointer when patching applies.
mp_route_request_t reqs[] = {
    { "__ZN17IONDRVFramebuffer16enableControllerEv",
      (void *)patchedEnableController,
      (void **)&orgEnableController },
};
mp_route_kext("com.apple.iokit.IONDRVSupport", reqs, 1);
```

That's it. No plugin framework, no boot-args, no version checks. If your kext needs those, build them yourself — it's not our job.

## How it works

### Kext-load detection (notify.cpp)

At `mp_start`, walk the kernel's `kmod` global (linked list of `kmod_info_t`) — this contains every kext loaded so far, including System KC ones. Cache them.

Then patch `__ZN6OSKext23saveLoadedKextPanicListEv` (called every time a kext loads after us) — its hook re-walks the chain looking for new entries.

Net effect: **100% kext-load coverage**, no race, no order dependency.

### Symbol lookup (macho.cpp)

Given a `kmod_info_t.address`, parse the `mach_header_64` there. Walk load commands to find `LC_SYMTAB`. Linear scan the symbol+string tables comparing names.

Two interpretations needed for Apple kernel collections:
- **Standalone Mach-O**: `symoff`/`stroff` are file offsets from the kext's header (Boot KC and Aux KC).
- **Embedded in KC**: `symoff` is relative to the parent KC's `__LINKEDIT` segment (System KC).

We try standalone first; if the first symbol's string isn't a plausible C identifier, fall back to the `__LINKEDIT`-relative interpretation.

### Function patching (patch.cpp)

On x86_64, write a 14-byte absolute indirect jump (`ff 25 00 00 00 00 <8-byte addr>`) at the target's prologue.

Use a tiny built-in length disassembler to compute how many original bytes to displace (must be ≥14). Copy displaced bytes to a trampoline, append a 14-byte jump back to (target+N). Set `*org` to the trampoline.

`vm_protect` flips the target page to writable, write JMP, restore RX. Trampolines come from `IOMallocAligned` + `vm_protect` to RWX.

## Build

```bash
KERN_SDK=/path/to/MacKernelSDK ./build.sh
# Output: build/mos15-patcher.kext
```

Default looks for MacKernelSDK at `../docker-macos/kexts/deps/MacKernelSDK`.

## Compatibility with Lilu plugins

**No.** Lilu's API is a rich C++ class hierarchy (`KernelPatcher`, `KextInfo`, `PluginConfiguration`, etc.). We don't reimplement any of it. Plugins must port to `mp_route_kext` (a few-line change per route, plus dropping the `PluginConfiguration` boilerplate — boot-arg handling becomes the plugin's own concern).

## Status

Initial implementation. Builds cleanly. Not yet runtime-verified end-to-end. Target consumer: [QEMUDisplayPatcher](https://github.com/MattJackson/docker-macos/tree/main/kexts/QEMUDisplayPatcher) once its Lilu dependencies are stripped.

## Part of mos15

- [docker-macos](https://github.com/MattJackson/docker-macos) — Docker image, build pipeline
- [qemu-mos15](https://github.com/MattJackson/qemu-mos15) — QEMU patches
- [opencore-mos15](https://github.com/MattJackson/opencore-mos15) — OpenCore patches
- [lilu-mos15](https://github.com/MattJackson/lilu-mos15) — patched Lilu (will be deprecated once mos15-patcher proves out)
- [mos15-patcher](https://github.com/MattJackson/mos15-patcher) — this repo

## License

GPL-3.0, same as the rest of mos15.
