# mos15-patcher

Minimal kernel-function-hook framework for macOS — a Lilu replacement built for the **mos** project.

> **Status: v0.5 — usable but barebones.** Runtime-verified on macOS 15 (Sequoia) inside a QEMU/KVM VM. Production hardening is incomplete; APIs may change. See [Status](#status) below.

## Why this exists

[Lilu](https://github.com/acidanthera/Lilu) is the de facto kernel-patching framework for hackintosh-adjacent work (10–15k LOC, 20+ files, rich C++ class hierarchy). For our use case (the [mos](https://github.com/MattJackson/docker-macos) macOS-in-Docker stack on Sequoia) we hit a Lilu reliability bug at early boot — `onKextLoad` only fires on ~60% of boots for System KC kexts loaded before Lilu's `activate()`. Rather than patch around it, we wrote a smaller framework (~700 LOC across 4 files we own) that solves three things and nothing else:

1. **Detect IOService class instantiation.** Register `IOService::addMatchingNotification` on the class name. Every current and future instance is delivered to our callback.
2. **Look up Mach-O symbols** by mangled name in any loaded kext (Boot KC, System KC, Aux KC) with one universal `__LINKEDIT`-relative resolution formula — no standalone-vs-KC heuristic.
3. **Swap per-instance vtables** for IOService classes (Sequoia-safe — no `__DATA_CONST` writes), or patch function prologues with 14-byte absolute JMPs for static functions.

Plus prefix-based symbol matching so consumers don't hand-mangle Itanium C++ ABI parameter signatures.

## Quick start

```c
#include <mos15_patcher.h>

static IOReturn (*orgEnableController)(void *) = nullptr;

static IOReturn patchedEnableController(void *that) {
    IOReturn r = orgEnableController(that);
    // ... your code ...
    return r;
}

extern "C" kern_return_t my_start(kmod_info_t *ki, void *d) {
    mp_route_request_t reqs[] = {
        // Apple's blessed path — vtable swap on every IONDRVFramebuffer
        // instance, current and future. Prefix-match: pass class+method,
        // patcher resolves the mangled symbol with the ABI param sig.
        MP_ROUTE_PAIR("IONDRVFramebuffer", "IOFramebuffer",
                      "enableController",
                      patchedEnableController, orgEnableController),
    };
    return mp_route_on_publish("IONDRVFramebuffer",
                               "com.apple.iokit.IONDRVSupport",
                               reqs, sizeof(reqs)/sizeof(*reqs));
}
```

That's the whole framework surface area for the IOService path. See [`include/mos15_patcher.h`](include/mos15_patcher.h) for the full API.

## Public API

```c
// IOService publish — preferred for virtual methods.
int mp_route_on_publish(const char *class_name,
                        const char *kext_bundle_id,
                        mp_route_request_t *reqs, size_t count);

// Auto-dispatch for static / non-virtual functions in a specific kext.
// Synchronous if loaded; queued if not.
int mp_route_kext(const char *kext_bundle_id,
                  mp_route_request_t *reqs, size_t count);

// Lower-level: prologue patch at a known address.
int mp_route_addr(uint64_t target_addr, void *replacement, void **org);
```

### Route-construction macros (C++ only)

These remove the need to spell out Itanium C++ ABI parameter signatures:

```cpp
// Most common — class+method only, patcher prefix-matches.
MP_ROUTE("IONDRVFramebuffer", "enableController", patched, org)

// Two routes (derived class + base class) sharing the same replacement.
MP_ROUTE_PAIR("IONDRVFramebuffer", "IOFramebuffer", "enableController",
              patched, org)

// When prefix is ambiguous (overloaded methods) — supply explicit ABI sig.
MP_ROUTE_PAIR_SIG("IONDRVFramebuffer", "IOFramebuffer",
                  "setGammaTable", "jjjPv",
                  patched, org)

// Full mangled-name escape hatch.
MP_ROUTE_EXACT("__ZN17IONDRVFramebuffer3fooEii", patched, org)
```

The ambiguity-detection logic in the symbol resolver logs ambiguous prefix matches at kext load time, so consumers see the problem immediately instead of mysteriously.

## How it works

### IOService publish notifications (`src/notify.cpp`)

`addMatchingNotification(gIOPublishNotification, ...)` fires the instant macOS creates an instance of a matched class — for every current and future instance. Our callback:

1. Reads instance+0 — the vtable pointer.
2. Allocates a RW vtable copy in heap (8KB / 1024 slots — bigger than any IOKit class's virtual surface).
3. For each routed method: resolve via `macho_find_symbol` (exact) or `macho_find_symbol_by_prefix` (E-delimited prefix match), first in the consumer-specified kext, then in IOGraphicsFamily as fallback for inherited base methods.
4. Scan the copy's slots for the resolved address. Save the original to `*org`, write the replacement.
5. Atomic write of the copy's address to instance+0. Only that instance is affected — other instances keep the OEM vtable.

Why per-instance: in-place writes to `__DATA_CONST` (where vtables live on Sequoia) crash even with `CR0.WP` toggled. The instance itself is on the C++ heap (RW). Writing 8 bytes there is trivial and safe.

### Symbol lookup (`src/macho.cpp`)

Given a `kmod_info_t.address`, parse the `mach_header_64`. Walk load commands to `LC_SYMTAB` and `LC_SEGMENT_64`. Read `__LINKEDIT`'s `vmaddr` and `fileoff`. Compute:

```
symbols = linkedit.vmaddr + (symtab.symoff - linkedit.fileoff)
strings = linkedit.vmaddr + (symtab.stroff - linkedit.fileoff)
```

This formula works universally — standalone Mach-O (where `hdr = linkedit.vmaddr - linkedit.fileoff` by algebraic identity) AND KC-embedded kexts (where the kext's mach header has no relation to KC-relative symtab offsets). One formula, no heuristics.

Prefix match (`macho_find_symbol_by_prefix`): scan the symbol table for names starting with a given prefix. Returns the unique match, or 0 with a kernel log line on ambiguity (caller should disambiguate via `MP_ROUTE_*_SIG` or `MP_ROUTE_EXACT`).

### Function patching (`src/patch.cpp`)

On x86_64, write a 14-byte absolute indirect JMP (`ff 25 00 00 00 00 <8-byte addr>`) at the target's prologue. A small length disassembler computes how many original bytes to displace (must be ≥14). Displaced bytes go to a slot in an in-kext `__TEXT` trampoline pool. RIP-relative displacements in the displaced bytes are rewritten by `delta = original_addr - tramp_addr`. A 14-byte JMP back to `target+N` is appended. `*org` becomes the trampoline.

Writes to kernel `__TEXT` use a CR0 WP-bit toggle (interrupts disabled, `CR0 &= ~WP`, memcpy, restore). The trampoline pool sits inside our own kext's `__TEXT,__cstring` section — it comes up executable from the kext loader with no `vm_protect` upgrade needed (`vm_protect` returns `kr=2` on recent kernels for kernel pages anyway).

### Diagnostics

Per-class status is published as ioreg properties on the matched IOService instance:

- `MPMethodsHooked`, `MPMethodsTotal`, `MPMethodsMissing`
- `MPMethodGaps` — array of mangled symbol pairs that didn't resolve
- `MPStatus` — compact per-route status string (`P` = primary patched, `F` = fallback patched, `u/f` = resolved-but-slot-taken, `X` = unresolved)
- `MPRoutesPatched`, `MPRoutesRedundant`, `MPRoutesUnresolved`

Read with `ioreg -l | grep MP` from userspace. Bypasses kernel log buffer drops during the publish callback (which we hit early on).

## Build

```bash
KERN_SDK=/path/to/MacKernelSDK ./build.sh
# Output: build/mos15-patcher.kext
```

The default looks for MacKernelSDK at `../docker-macos/kexts/deps/MacKernelSDK`.

Built artifact bundle ID: `com.pq.kext.mos15-patcher`. Place under `EFI/OC/Kexts/` and reference it in OpenCore `config.plist` to load at boot.

## Compatibility with Lilu plugins

**No compatibility layer.** Lilu's API is a rich C++ hierarchy (`KernelPatcher`, `KextInfo`, `PluginConfiguration`, `IOSubclasser`...). We don't reimplement any of it. Plugins must port to the much smaller `mp_route_*` surface — usually a few-line change per route, plus dropping `PluginConfiguration` boilerplate (boot-arg handling becomes the plugin's own concern).

## Status

**v0.5 — usable but barebones.** The framework is **runtime-proven** end-to-end on Sequoia in our VM environment:

- 24/24 IOFramebuffer methods hooked across `IONDRVFramebuffer` + `IOFramebuffer` base, 0 gaps, in [QEMUDisplayPatcher](https://github.com/MattJackson/docker-macos/tree/main/kexts/QEMUDisplayPatcher)
- iMac20,1 EDID injection delivered intact through 2-block `getDDCBlock`
- 7/8 advertised display modes surface in CoreGraphics (the 8th is blocked by an upstream qemu-mos15 limit, not us)
- Vtable swap fires on every `IONDRVFramebuffer` instance via the publish-notification path; persistent across container restarts
- Ioreg diagnostic properties expose per-route status for fast debugging

**Not yet:**

- Hardened against multiple consumers — no consumer-isolation if two kexts both call `mp_route_on_publish` on the same class
- Tested across macOS versions — only Sequoia 15.7.5 (build 24G624)
- ARM64 / Apple Silicon support — x86_64 only (the prologue patcher is x86 ISA-specific)
- API frozen — `MP_ROUTE_*` macros and `mp_route_*` signatures may change in v1.0 once we have a second consumer to validate the API shape

## Part of the mos suite

- [docker-macos](https://github.com/MattJackson/docker-macos) — the orchestration repo. Docker image, build pipeline, OpenCore config, the `QEMUDisplayPatcher` kext that consumes this framework
- [qemu-mos15](https://github.com/MattJackson/qemu-mos15) — patches to QEMU 10.2.2 (`applesmc`, `vmware_vga`, `dev-hid`)
- [opencore-mos15](https://github.com/MattJackson/opencore-mos15) — OpenCore config + patches

## License

[GNU AGPL-3.0](LICENSE). Network use counts as distribution — anyone who runs this code as part of a service must offer the source to its users.
