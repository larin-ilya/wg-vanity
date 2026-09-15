/* Minimal <sys/param.h> stand-in for the libc-less zig build.
 *
 * ed25519-donna-portable.h includes this on every non-MSVC compiler (we are
 * clang/zig, so that is us) to pick up BSD detection macros. We target
 * x86_64-windows-gnu, so nothing from it is needed.
 */
#ifndef WG_ONION_SHIM_SYS_PARAM_H
#define WG_ONION_SHIM_SYS_PARAM_H

#endif /* WG_ONION_SHIM_SYS_PARAM_H */
