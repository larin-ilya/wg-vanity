/* vanity_dllentry.c - the two symbols a PE DLL normally gets from the C runtime.
 *
 * build.ps1 deliberately links this module with NO libc at all (zig's libc
 * setup is broken on this machine: `zig cc ... -lc` dies with CacheCheckFailed,
 * and there is no MSVC/gcc/mingw toolchain available). Without libc the PE
 * loader still needs an entry point and a TLS index slot, so we define them
 * ourselves. Nothing here does any initialisation: the DRBG is seeded lazily by
 * vanity_init() and the ed25519 constants by ge_initeightpoint().
 *
 * The whole file is Windows-only: _tls_index and _DllMainCRTStartup are PE
 * loader concepts with no ELF counterpart. On Linux/ARM the very same sources
 * are built into a plain shared object, which needs no entry point and takes
 * its TLS index from the dynamic loader, so this file becomes an empty
 * translation unit there. Keeping it in the source list for every target keeps
 * build.ps1's file list identical across platforms.
 */
#ifdef _WIN32

unsigned long _tls_index = 0;

__declspec(dllexport) int _DllMainCRTStartup(void *hinstDLL,
                                            unsigned long fdwReason,
                                            void *lpvReserved)
{
	(void)hinstDLL;
	(void)fdwReason;
	(void)lpvReserved;
	return 1;
}

#endif /* _WIN32 */
