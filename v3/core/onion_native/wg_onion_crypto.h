/* wg_onion_crypto.h - self-contained crypto for the libc-less native module.
 *
 * The DLL is deliberately linked WITHOUT any C runtime (see build.ps1), so it
 * cannot use malloc/free/printf/time and cannot pull in libsodium. Everything
 * the vendored ed25519-donna glue and our bridge need is implemented here:
 *
 *   - SHA-512 (FIPS 180-4)          -> crypto_hash_sha512* (libsodium API shape)
 *   - ChaCha20 (RFC 8439) as DRBG   -> randombytes()/wg_drbg_bytes()
 *   - a volatile memset             -> wg_memzero()
 *
 * The DRBG is seeded exclusively from Python's os.urandom() (see
 * wg_onion_init). No OS entropy source is touched from inside the DLL.
 */
#ifndef WG_ONION_CRYPTO_H
#define WG_ONION_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ SHA-512 */

typedef struct {
	uint64_t h[8];
	uint64_t len_lo;   /* message length in bytes, low 64 bits  */
	uint64_t len_hi;   /* message length in bytes, high 64 bits */
	uint8_t  buf[128];
	size_t   buflen;
} wg_sha512_ctx;

void wg_sha512_init(wg_sha512_ctx *c);
void wg_sha512_update(wg_sha512_ctx *c, const void *data, size_t len);
void wg_sha512_final(wg_sha512_ctx *c, uint8_t out[64]);
void wg_sha512(uint8_t out[64], const void *data, size_t len);
void wg_sha512_2(uint8_t out[64], const void *a, size_t alen,
                 const void *b, size_t blen);

/* libsodium-compatible surface, required by the vendored
 * ed25519/ed25519_impl_pre.h and ed25519-hash-custom.h. */
typedef wg_sha512_ctx crypto_hash_sha512_state;

int crypto_hash_sha512_init(crypto_hash_sha512_state *s);
int crypto_hash_sha512_update(crypto_hash_sha512_state *s,
                              const unsigned char *in,
                              unsigned long long inlen);
int crypto_hash_sha512_final(crypto_hash_sha512_state *s, unsigned char *out);
int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen);

/* ------------------------------------------------------- ChaCha20-based DRBG */

/* Seeds the DRBG. Returns 0 on success, -1 on bad arguments. */
int  wg_drbg_init(const unsigned char *seed, unsigned int seed_len);
/* Fills out[0..len) with DRBG output. Must be called after wg_drbg_init. */
void wg_drbg_bytes(void *out, size_t len);
int  wg_drbg_is_ready(void);

/* --------------------------------------------------------------- utilities */

void   wg_memzero(void *p, size_t len);
void  *wg_memcpy(void *dst, const void *src, size_t n);
void  *wg_memset(void *dst, int c, size_t n);
int    wg_memcmp(const void *a, const void *b, size_t n);
size_t wg_strnlen(const char *s, size_t maxlen);

#endif /* WG_ONION_CRYPTO_H */
