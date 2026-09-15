/* libsodium <sodium/randombytes.h> stand-in.
 *
 * Upstream mkp224o takes its 32-byte batch seeds from libsodium's randombytes,
 * i.e. from the OS CSPRNG. Here the entropy enters the DLL exactly once, via
 * vanity_init(seed) from Python's os.urandom(); randombytes() below is the
 * ChaCha20 DRBG that is fed by that seed.
 */
#ifndef VANITY_SHIM_SODIUM_RANDOMBYTES_H
#define VANITY_SHIM_SODIUM_RANDOMBYTES_H

#include <stddef.h>
#include "vanity_crypto.h"

static inline void randombytes(void *buf, size_t len)
{
	vn_drbg_bytes(buf, len);
}

#endif /* VANITY_SHIM_SODIUM_RANDOMBYTES_H */
