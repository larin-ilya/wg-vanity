/* Minimal <wchar.h> stand-in for the libc-less zig build.
 *
 * Only the GDNative build needs this: godot_headers' gdnative/string.h includes
 * <wchar.h> to get wchar_t (for the wide-string API), and there is no libc
 * header set on the build machines. In C, wchar_t is a compiler builtin type,
 * so clang's own <stddef.h> is all that is actually required - the rest of
 * wchar.h (wcs* functions, mbstate_t) is never referenced by anything we
 * compile. The engine-only targets (windows/linux/linux-*) never include this
 * file, so their byte-for-byte output is unaffected.
 */
#ifndef VANITY_SHIM_WCHAR_H
#define VANITY_SHIM_WCHAR_H

#include <stddef.h>   /* defines wchar_t (clang builtin header) */

#endif /* VANITY_SHIM_WCHAR_H */
