# mos15-patcher

Minimal kernel-function-hook framework for macOS — Lilu replacement built for the **mos15** project.

## Why exist

Lilu is a great general-purpose patcher (~10–15k lines, 20+ files) but for our needs (mos15) it does too much, and we hit reliability issues with kext-load detection on Sequoia in our VM. mos15-patcher does only the three things we need, in ~600 lines we own:

1. **Detect IOService class instantiation** — register `IOService::addMatchingNotification` on the class name; every current and future instance is delivered to our callback.
2. **Look up Mach-O symbols** by mangled name in any loaded kext — Boot KC, System KC, Aux KC — with unified `__LINKEDIT`-relative resolution (no standalone vs KC-embedded split).
3. **Swap per-instance vtables** (for IOService classes) or patch function prologues with 14-byte absolute JMPs (for static / non-virtual functions).

Plus kmod-chain enumeration at our `_start` so callers can synchronously patch
already-loaded kexts via prologue JMP.

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

mp_route_request_t reqs[] = {
    { "__ZN17IONDRVFramebuffer16enableControllerEv",
      (void *)patchedEnableController,
      (void **)&orgEnableController },
};

// For IOService classes — installs a vtable swap on every current and
// future instance. Preferred for virtual method hooking.
mp_route_on_publish("IONDRVFramebuffer",
                    "com.apple.iokit.IONDRVSupport",
                    reqs, 1);

// For static or non-virtual functions in a specific kext — prologue JMP.
// Synchronous if the kext is already loaded; queued otherwise.
// *org is filled with a trampoline pointer.
mp_route_kext("com.apple.iokit.IONDRVSupport", reqs, 1);

// For a function whose address you already have.
mp_route_addr(0xffffff8012345678ULL, (void *)replacement, (void **)&org);
```

No plugin framework, no boot-args, no version checks. If your kext needs those, build them yourself.

## How it works

### IOService publish notifications (notify.cpp)

`IOService::addMatchingNotification(gIOPublishNotification, ...)` fires the
instant macOS creates an instance of a matched class, for every current and
future instance. Our callback:

1. Reads the instance's first 8 bytes — the vtable pointer.
2. Allocates a RW copy of the vtable in heap (bzero + memcpy from the original).
3. Resolves each routed method by mangled name via `macho_find_symbol`, first
   in the specified kext, then falling back to every loaded kmod (for methods
   inherited from a base class in a different kext).
4. Scans the copied vtable for slots matching the resolved method addresses;
   stores the original in `*org`, writes the replacement into the slot.
5. Writes the copy's address back to instance+0. Only that instance is
   affected — other instances keep the OEM vtable.

This is the only path that works on Sequoia for classes whose vtables live in
`__DATA_CONST`. In-place patches crash because page protection now survives
the traditional CR0.WP toggle.

### Symbol lookup (macho.cpp)

Given a `kmod_info_t.address`, parse the `mach_header_64`. Walk load commands
to `LC_SYMTAB` and `LC_SEGMENT_64`. Read the `__LINKEDIT` segment command.
Compute:

```
symbols = linkedit.vmaddr + (symtab.symoff - linkedit.fileoff)
strings = linkedit.vmaddr + (symtab.stroff - linkedit.fileoff)
```

This formula works universally — standalone mach-o (where the image is
contiguous from file offset 0, so `hdr = linkedit.vmaddr - linkedit.fileoff`
by algebraic identity) AND KC-embedded kexts (where the kext's mach header
has no direct relation to the KC-relative symtab offsets). No heuristic,
no "try both" fallback; one formula.

### Function patching (patch.cpp)

On x86_64, write a 14-byte absolute indirect JMP
(`ff 25 00 00 00 00 <8-byte addr>`) at the target's prologue. Use a tiny
length disassembler to compute how many original bytes to displace
(must be ≥14). Copy displaced bytes to a slot in an in-kext `__TEXT`
trampoline pool (RX from the kext loader). Rewrite any RIP-relative
displacement in the copied bytes by `delta = original_addr - tramp_addr`.
Append a 14-byte JMP back to `target+N`. Set `*org` to the trampoline.

Writes to kernel `__TEXT` use a CR0 WP-bit toggle (interrupts disabled,
`CR0 &= ~WP`, memcpy, restore). The trampoline pool is allocated inside
our own kext's `__TEXT,__cstring` section so it comes up executable from
the kext loader — we don't need `vm_protect` to upgrade it (which fails
kr=2 on recent kernels anyway).

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
