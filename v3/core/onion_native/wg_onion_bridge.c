/* wg_onion_bridge.c - native Tor v3 .onion vanity search, exported as a
 * libc-less Windows DLL.
 *
 * The batch loop is a re-implementation of mkp224o's worker_batch.inc.h
 * (cathugger/mkp224o, CC0; vendored in ./vendor, see ./vendor/UPSTREAM.txt).
 * Everything that upstream took from libc/libsodium/pthreads/filesystem has
 * been replaced so that this module links against nothing at all:
 *
 *   crypto_hash_sha512 -> ./wg_onion_crypto.c (own FIPS 180-4 SHA-512)
 *   randombytes        -> ./wg_onion_crypto.c (ChaCha20 DRBG, seeded by
 *                         Python's os.urandom() through wg_onion_init)
 *   sodium_memzero     -> wg_memzero()
 *   malloc/free/printf -> gone; every buffer below is static (BSS)
 *   file output        -> gone; the found key is returned to the caller
 *   base32_from()      -> replaced by build_filter() below, which packs the
 *                         prefix into a bit mask over the *packed public key*
 *                         bytes instead of comparing base32 strings in the hot
 *                         loop (same idea as upstream's BINFILTER)
 *
 * The important property of the batch loop (upstream's and ours) is that
 * ge25519_batchpack_destructive_1() replaces BATCHNUM independent field
 * inversions with one, which is what makes this ~3 orders of magnitude faster
 * than one-key-at-a-time Python.
 *
 * Alignment note: ge25519_batchpack_destructive_1() returns the packed *Y*
 * coordinate with the X sign bit left unwritten; ge25519_batchpack
 * _destructive_finish() fills that bit in. The bit filter therefore only ever
 * inspects bits 0..254 of the public key (prefixes are capped at 51 base32
 * characters = 255 bits). Longer prefixes are handled by comparing the full
 * address string after a filter hit.
 */

#include <stddef.h>
#include <stdint.h>

#include "types.h"
#include "likely.h"
#include "wg_onion_crypto.h"

/* The vendored dispatch glue expects CRYPTO_NAMESPACE to be defined by the
 * build system (see mkp224o's GNUmakefile.in). We supply our own prefix so the
 * donna helpers get a private, self-describing symbol namespace. */
#define CRYPTO_NAMESPACE(name) wg_onion_donna_##name
#define ED25519_donna 1
#include "ed25519_impl_pre.h"

#include "keccak.h"
#include "base32.h"

#define WG_EXPORT __declspec(dllexport)

/* ------------------------------------------------------------------ tuning */

#ifndef WGO_BATCHNUM
#define WGO_BATCHNUM 2048
#endif

#define WG_MAX_PREFIXES    4096
#define WG_MAX_PREFIX_LEN  55
/* 51 base32 chars == 255 bits == the most that fits in the packed key without
 * touching the sign bit that batchpack_destructive_1 leaves unwritten. */
#define WG_FILTER_MAXCHARS 51

#define WG_ONION_ADDR_LEN 56

/* ------------------------------------------------------- static batch state
 * Upstream keeps these on the worker thread's stack. Python worker processes
 * get a 1 MiB stack, and BATCHNUM=2048 needs ~460 KiB, so they must live in
 * BSS instead. They are never touched from more than one thread at a time: the
 * Python side parallelises with multiprocessing, not threads.
 */
static ge25519     ALIGN(16) g_ge_batch[WGO_BATCHNUM];
static bignum25519 ALIGN(16) g_tmp_batch[WGO_BATCHNUM];
static bytes32     ALIGN(16) g_pk_batch[WGO_BATCHNUM];

/* --------------------------------------------------------------- filter set */

struct wg_prefix_filter {
	unsigned char f[32];    /* required bits of the packed public key */
	unsigned char nfull;    /* number of wholly-constrained leading bytes */
	unsigned char rem;      /* constrained bits inside f[nfull] (0 or 1..7) */
	unsigned char mask;     /* mask covering those `rem` high bits */
	unsigned char plen;     /* full prefix length in characters */
	char          str[WG_MAX_PREFIX_LEN + 1];
};

static struct wg_prefix_filter g_prefix[WG_MAX_PREFIXES];
static int g_nprefix;
static int g_inited;

static int b32val(char c)
{
	if (c >= 'a' && c <= 'z') return c - 'a';
	if (c >= '2' && c <= '7') return c - '2' + 26;
	return -1;
}

/* Pack the prefix into a bit mask over the packed public key. base32 is a
 * MSB-first 5-bit encoding and the .onion address starts with the raw 32-byte
 * public key, so base32 character j fixes key bits 5j..5j+4. */
static int build_filter(struct wg_prefix_filter *bf, const char *p, int n)
{
	int nchars = n > WG_FILTER_MAXCHARS ? WG_FILTER_MAXCHARS : n;
	int bits = nchars * 5;
	int j, k;

	bf->nfull = (unsigned char)(bits / 8);
	bf->rem = (unsigned char)(bits % 8);
	bf->mask = bf->rem ? (unsigned char)(0xFFu << (8 - bf->rem)) : 0;
	bf->plen = (unsigned char)n;
	wg_memset(bf->f, 0, sizeof(bf->f));

	for (j = 0; j < nchars; ++j) {
		int v = b32val(p[j]);
		if (v < 0) return -1;
		for (k = 0; k < 5; ++k) {
			if ((v >> (4 - k)) & 1) {
				int abs = 5 * j + k;
				bf->f[abs >> 3] |= (unsigned char)(0x80u >> (abs & 7));
			}
		}
	}
	for (j = 0; j < n; ++j) bf->str[j] = p[j];
	bf->str[n] = '\0';
	return 0;
}

/* First filter that the packed key satisfies, or -1. */
static int filter_hit(const unsigned char *pk)
{
	int i;
	for (i = 0; i < g_nprefix; ++i) {
		const struct wg_prefix_filter *bf = &g_prefix[i];
		if (bf->nfull && wg_memcmp(pk, bf->f, bf->nfull) != 0)
			continue;
		if (bf->rem && ((pk[bf->nfull] & bf->mask) != bf->f[bf->nfull]))
			continue;
		return i;
	}
	return -1;
}

static int prefix_full_match(const char *addr, const struct wg_prefix_filter *bf)
{
	int i;
	for (i = 0; i < (int)bf->plen; ++i)
		if (addr[i] != bf->str[i]) return 0;
	return 1;
}

/* ------------------------------------------------------------------ address */

/* addr = base32(pub || sha3_256(".onion checksum" || pub || 0x03)[0..1] || 0x03) */
static void addr_from_pub(const unsigned char *pub, char out[WG_ONION_ADDR_LEN + 1])
{
	static const char checksumstr[] = ".onion checksum";
	unsigned char hashsrc[15 + 32 + 1];
	unsigned char sum[32];
	unsigned char raw[35];

	wg_memcpy(hashsrc, checksumstr, 15);
	wg_memcpy(hashsrc + 15, pub, 32);
	hashsrc[15 + 32] = 0x03;
	FIPS202_SHA3_256(hashsrc, sizeof(hashsrc), sum);

	wg_memcpy(raw, pub, 32);
	raw[32] = sum[0];
	raw[33] = sum[1];
	raw[34] = 0x03;
	base32_to(out, raw, 35);   /* writes 56 chars + NUL */
}

/* Little-endian add of `v` to a 32-byte scalar, exactly as upstream. */
static void addsztoscalar32(unsigned char *dst, unsigned long long v)
{
	int i;
	uint32_t c = 0;
	for (i = 0; i < 32; ++i) {
		c += (uint32_t)dst[i] + (uint32_t)(v & 0xFF);
		dst[i] = (unsigned char)(c & 0xFF);
		c >>= 8;
		v >>= 8;
	}
}

/* ======================================================================== */
/* Public C ABI                                                             */
/* ======================================================================== */

/* Seed the DRBG with caller-provided entropy (Python: os.urandom(32..64)).
 * Also initialises the ed25519-donna constants. */
WG_EXPORT int wg_onion_init(const unsigned char *seed, unsigned int seed_len)
{
	ge_initeightpoint();
	if (wg_drbg_init(seed, seed_len) != 0)
		return -1;
	g_inited = 1;
	return 0;
}

/* Install the prefix set (lowercase a-z 2-7). Returns 0, or <0 on bad input. */
WG_EXPORT int wg_onion_set_prefixes(const char *const *prefixes, int n)
{
	int i, j;

	if (n <= 0 || n > WG_MAX_PREFIXES)
		return -1;
	if (!prefixes)
		return -2;

	for (i = 0; i < n; ++i) {
		const char *p = prefixes[i];
		size_t len;

		if (!p) return -3;
		len = wg_strnlen(p, WG_MAX_PREFIX_LEN + 1);
		if (len < 1 || len > WG_MAX_PREFIX_LEN)
			return -4;
		/* reject anything outside the Tor base32 alphabet up front */
		for (j = 0; j < (int)len; ++j)
			if (b32val(p[j]) < 0) return -5;
		if (build_filter(&g_prefix[i], p, (int)len) != 0)
			return -6;
	}
	g_nprefix = n;
	return 0;
}

/* Search up to max_keys candidate keys. Returns 1 if a key matching one of the
 * installed prefixes was found (outputs filled in), 0 if the key budget was
 * exhausted without a find, <0 on error. */
WG_EXPORT int wg_onion_search(unsigned long long max_keys,
                              unsigned long long *checked_out,
                              unsigned char secret_out[64],
                              unsigned char pub_out[32],
                              unsigned char seed_out[32],
                              char onion_out[WG_ONION_ADDR_LEN + 1])
{
	unsigned long long checked = 0;
	unsigned long long counter = 0;
	unsigned char seed[32];
	unsigned char sk[64];
	unsigned char sec[64];
	char addr[WG_ONION_ADDR_LEN + 1];
	ge25519 ALIGN(16) ge_public;
	ge25519_p1p1 ALIGN(16) sum;
	int need_seed = 1;
	int result = 0;

	if (!g_inited) return -10;
	if (g_nprefix <= 0) return -11;
	if (!secret_out || !pub_out || !seed_out || !onion_out) return -12;

	while (checked < max_keys) {
		size_t bn, b;

		if (need_seed) {
			/* upstream: fresh randombytes() seed per restart */
			wg_drbg_bytes(seed, sizeof(seed));
			ed25519_seckey_expand(sk, seed);
			ge_scalarmult_base(&ge_public, sk);
			counter = 0;
			need_seed = 0;
		}

		bn = (size_t)(max_keys - checked);
		if (bn > (size_t)WGO_BATCHNUM) bn = (size_t)WGO_BATCHNUM;

		for (b = 0; b < bn; ++b) {
			g_ge_batch[b] = ge_public;
			ge_add(&sum, &ge_public, &ge_eightpoint);
			ge_p1p1_to_p3(&ge_public, &sum);
		}
		/* Batched inversion: one inversion for all bn points. The result
		 * is the packed Y coordinate; the X sign bit is still missing. */
		ge_p3_batchtobytes_destructive_1(g_pk_batch, g_ge_batch,
		                                 g_tmp_batch, bn);

		checked += bn;

		for (b = 0; b < bn; ++b) {
			int fi = filter_hit(g_pk_batch[b]);
			if (fi < 0)
				continue;

			/* finish the pack (fills in the sign bit) and verify with
			 * the real 56-character address - this also covers
			 * prefixes longer than 51 characters, which the bit
			 * filter only constrains partially. */
			ge_p3_batchtobytes_destructive_finish(g_pk_batch[b],
			                                      &g_ge_batch[b]);
			addr_from_pub(g_pk_batch[b], addr);
			if (!prefix_full_match(addr, &g_prefix[fi]))
				continue;

			wg_memcpy(sec, sk, sizeof(sec));
			addsztoscalar32(sec, counter + (unsigned long long)b * 8);
			/* same clamp sanity check as upstream: an out-of-range
			 * scalar would mean the secret does not match the key */
			if ((sec[0] & 248) != sec[0] ||
			    ((sec[31] & 63) | 64) != sec[31]) {
				need_seed = 1;
				break;
			}

			wg_memcpy(secret_out, sec, 64);
			wg_memcpy(pub_out, g_pk_batch[b], 32);
			wg_memcpy(seed_out, seed, 32);
			wg_memcpy(onion_out, addr, WG_ONION_ADDR_LEN);
			onion_out[WG_ONION_ADDR_LEN] = '\0';
			result = 1;
			goto done;
		}

		counter += (unsigned long long)bn * 8;
	}

done:
	wg_memzero(seed, sizeof(seed));
	wg_memzero(sk, sizeof(sk));
	wg_memzero(sec, sizeof(sec));
	if (checked_out) *checked_out = checked;
	return result;
}

/* Address for an arbitrary public key - used by the test suite and by any
 * caller that already holds a key. Returns 0. */
WG_EXPORT int wg_onion_addr_from_pub(const unsigned char *pub,
                                     char out[WG_ONION_ADDR_LEN + 1])
{
	if (!pub || !out) return -1;
	addr_from_pub(pub, out);
	return 0;
}

/* Does the installed bit filter accept this public key? Index of the first
 * matching prefix is stored in *prefix_index_out. Exposed so the test suite can
 * compare the native filter against Python's addr.startswith(prefix). */
WG_EXPORT int wg_onion_filter_match(const unsigned char *pub,
                                    int *prefix_index_out)
{
	int i;
	if (!pub || g_nprefix <= 0) return -1;
	i = filter_hit(pub);
	if (prefix_index_out) *prefix_index_out = i;
	return i >= 0 ? 1 : 0;
}

/* Human-readable engine identification, for diagnostics/tests.
 * Always NUL-terminates; returns the string length. */
WG_EXPORT int wg_onion_engine_info(char *out, unsigned int outlen)
{
	static const char info[] = "wg_onion/mkp224o-donna batch=2048 ed25519-donna";
	unsigned int i;
	if (!out || outlen == 0) return 0;
	for (i = 0; i + 1 < outlen && info[i]; ++i) out[i] = info[i];
	out[i] = '\0';
	return (int)i;
}

/* Parity with upstream's worker_impl.inc.h, which brackets the worker code with
 * the pre/post headers. Nothing below depends on the aliases they clean up. */
#include "ed25519_impl_post.h"
