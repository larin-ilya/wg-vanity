/* vanity_dllentry.c - the two symbols a DLL normally gets from the C runtime.
 *
 * build.ps1 deliberately links this module with NO libc at all (zig's libc
 * setup is broken on this machine: `zig cc ... -lc` dies with CacheCheckFailed,
 * and there is no MSVC/gcc/mingw toolchain available). Without libc the PE
 * loader still needs an entry point and a TLS index slot, so we define them
 * ourselves. Nothing here does any initialisation: the DRBG is seeded lazily by
 * vanity_init() and the ed25519 constants by ge_initeightpoint().
 */

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
