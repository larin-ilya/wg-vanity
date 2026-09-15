/* libsodium <sodium/randombytes.h> stand-in.
 *
 * Upstream mkp224o takes its 32-byte batch seeds from libsodium's randombytes,
 * i.e. from the OS CSPRNG. Here the entropy enters the DLL exactly once, via
 * wg_onion_init(seed) from Python's os.urandom(); randombytes() below is the
 * ChaCha20 DRBG that is fed by that seed.
 */
#ifndef WG_ONION_SHIM_SODIUM_RANDOMBYTES_H
#define WG_ONION_SHIM_SODIUM_RANDOMBYTES_H

#include <stddef.h>
#include "wg_onion_crypto.h"

static inline void randombytes(void *buf, size_t len)
{
	wg_drbg_bytes(buf, len);
}

#endif /* WG_ONION_SHIM_SODIUM_RANDOMBYTES_H */
