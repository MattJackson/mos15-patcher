//
// patch.hpp — Function prologue patching with trampolines.
//

#pragma once

#include <stdint.h>

/*
 * Patch the function at `target_addr` to jump to `replacement`. Allocate
 * a trampoline that executes the displaced original instructions and then
 * jumps back to (target_addr + N) so callers can still invoke the original
 * function. Stores the trampoline address in *org.
 *
 * Returns 0 on success, negative on error.
 */
int patch_route(uint64_t target_addr, void *replacement, void **org);
