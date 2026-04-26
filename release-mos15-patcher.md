# v0.5 — first usable cut

A minimal kernel-function-hook framework for macOS. Built as a Lilu replacement for the [mos suite](https://github.com/MattJackson/docker-macos).

## What this release provides

- **24/24 IOFramebuffer methods hooked** end-to-end, runtime-proven on Sequoia 15.7.5 inside QEMU/KVM
- **MP_ROUTE_PAIR API** — consumers don't hand-mangle Itanium C++ ABI parameter signatures
- **Per-instance vtable swap** via `IOService::addMatchingNotification` — Sequoia-safe (no `__DATA_CONST` writes)
- **Universal `__LINKEDIT`-relative symbol resolution** — works across Boot KC, System KC, Aux KC with one formula
- **Ioreg diagnostic properties** — per-route status, hook coverage, gaps; bypass kernel log buffer drops

## Status

**Usable but barebones.** Production hardening incomplete — see README for known limitations and what's not yet (multi-consumer isolation, multiple macOS versions, ARM64).

## License

AGPL-3.0. Network use counts as distribution.
