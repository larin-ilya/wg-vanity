/* Minimal <stdlib.h> stand-in for the libc-less zig build.
 *
 * ed25519-donna's portability header includes <stdlib.h> for the uint128_t
 * detection only; it never calls malloc/free/abort from the code paths we
 * compile. No allocation happens in this DLL at all - every buffer is a
 * static/global.
 */
#ifndef WG_ONION_SHIM_STDLIB_H
#define WG_ONION_SHIM_STDLIB_H

#include <stddef.h>

/* ed25519-donna's modm code calls abs(); provide it inline so we do not need a
 * runtime symbol for it. */
static inline int abs(int x)
{
	return x < 0 ? -x : x;
}

#endif /* WG_ONION_SHIM_STDLIB_H */
