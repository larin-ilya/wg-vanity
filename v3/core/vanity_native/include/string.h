/* Minimal <string.h> stand-in for the libc-less zig build.
 *
 * The DLL is linked without any C runtime (see build.ps1), so we cannot use
 * the system <string.h>. Only the prototypes that the vendored ed25519-donna
 * headers and our own bridge actually reference are declared here. The
 * definitions come from zig's compiler_rt (memcpy/memset/memmove/memcmp),
 * which the linker pulls in on demand.
 */
#ifndef VANITY_SHIM_STRING_H
#define VANITY_SHIM_STRING_H

#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

#endif /* VANITY_SHIM_STRING_H */
