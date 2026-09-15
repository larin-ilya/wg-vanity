/* vanity_bridge.c - native batch vanity search for BOTH key types, exported as a
 * libc-less Windows DLL:
 *
 *   kind 0 = Tor v3 .onion address   (ed25519 pubkey, base32 alphabet a-z2-7)
 *   kind 1 = WireGuard key           (X25519 u-coordinate, base64 alphabet)
 *
 * The batch loop is a re-implementation of mkp224o's worker_batch.inc.h
 * (cathugger/mkp224o, CC0; vendored in ./vendor, see ./vendor/UPSTREAM.txt).
 * Everything that upstream took from libc/libsodium/pthreads/filesystem has
 * been replaced so that this module links against nothing at all:
 *
 *   crypto_hash_sha512 -> ./vanity_crypto.c (own FIPS 180-4 SHA-512)
 *   randombytes        -> ./vanity_crypto.c (ChaCha20 DRBG, seeded by
 *                         Python's os.urandom() through vanity_init)
 *   sodium_memzero     -> vn_memzero()
 *   malloc/free/printf -> gone; every buffer below is static (BSS)
 *   file output        -> gone; the found key is returned to the caller
 *   base32_from()      -> replaced by build_filter() below, which packs the
 *                         prefix into a bit mask over the *packed public key*
 *                         bytes instead of comparing base32 strings in the hot
 *                         loop (same idea as upstream's BINFILTER)
 *
 * The important property of the batch loop (upstream's and ours) is that it
 * replaces BATCHNUM independent field inversions with one, which is what makes
 * this ~3 orders of magnitude faster than one-key-at-a-time Python.
 *
 * ---------------------------------------------------------------------------
 * onion (kind 0) - unchanged from the onion-only version of this bridge
 *
 *   seed = randombytes(32); sk64 = sha512(seed) with the ed25519 clamp (the
 *   "expanded" secret); P = sk64*B (ge_scalarmult_base); candidates are
 *   P, P+8B, P+16B, ... via ge_add/ge_p1p1_to_p3. The packed value of a
 *   candidate is the ed25519 public key Y (plus the X sign bit), and the .onion
 *   address is base32(pub || sha3_256(".onion checksum"||pub||0x03)[0..1] || 3).
 *
 * Alignment note: ge25519_batchpack_destructive_1() returns the packed *Y*
 * coordinate with the X sign bit left unwritten; ge25519_batchpack
 * _destructive_finish() fills that bit in. The bit filter therefore only ever
 * inspects bits 0..254 of the public key (prefixes are capped at 51 base32
 * characters = 255 bits). Longer prefixes are handled by comparing the full
 * address string after a filter hit.
 *
 * ---------------------------------------------------------------------------
 * WireGuard (kind 1) - same batch loop, different packing and filter
 *
 * WireGuard public keys are X25519 u-coordinates. We stay on the twisted
 * Edwards curve (that is where the fast donna additions live) and convert to
 * Montgomery only at packing time:
 *
 *   sk   = randombytes(32) with the X25519 clamp  (bit-for-bit the same clamp
 *          as the ed25519 one: sk[0]&=248; sk[31]&=127; sk[31]|=64)
 *   P    = sk*B            (ge_scalarmult_base reduces sk mod L internally;
 *          B has order L, so (sk mod L)*B == sk*B - see test 6)
 *   cand = P, P+8B, P+16B, ...   (step 8 keeps the low clamp bits at zero)
 *   pack = u = (1 + y/z) / (1 - y/z) = (z + y) / (z - y)
 *          with y = Y/Z the affine edwards y of the candidate
 *
 * The step-8 trick means candidate b has private scalar sk + 8b (a 32-byte
 * little-endian integer), which is exactly what we hand back to the caller:
 * X25519 clamps it again on use, and since we verified the clamp invariant
 * (wg_clamped_p) that is a no-op, so the caller recomputes the same key.
 *
 * The batch inversion here is curve25519_batchrecip over denominator[i] =
 * z[i] - y[i], followed by numerator[i] * denominator[i]^-1 - the same shape as
 * ge25519_batchpack_destructive_1(), which does it for y/z.
 *
 * Filtering is a bit filter over the raw 32-byte key, never over the base64
 * string: RFC 4648 base64 slices the byte stream into 6-bit groups, so base64
 * character j is determined by key bits 6j..6j+5. A prefix of up to 42
 * characters therefore constrains at most 252 bits, all of them real key bits
 * (a 44-character base64 of 32 bytes pads the last character), which makes the
 * bit filter exact - no string re-check is needed. The encoder itself is not in
 * this module: the caller gets raw bytes and turns them into base64 itself.
 */

#include <stddef.h>
#include <stdint.h>

#include "types.h"
#include "likely.h"
#include "vanity_crypto.h"

/* The vendored dispatch glue expects CRYPTO_NAMESPACE to be defined by the
 * build system (see mkp224o's GNUmakefile.in). We supply our own prefix so the
 * donna helpers get a private, self-describing symbol namespace. */
#define CRYPTO_NAMESPACE(name) vanity_core_donna_##name
#define ED25519_donna 1
#include "ed25519_impl_pre.h"

#include "keccak.h"
#include "base32.h"

/* Exported entry points. On Windows the module is a PE DLL and needs
 * __declspec(dllexport); everywhere else it is a shared object and gets the
 * default ELF visibility attribute (which matters under -fvisibility=hidden,
 * and is simply the default one otherwise). */
#ifdef _WIN32
#define VN_EXPORT __declspec(dllexport)
#else
#define VN_EXPORT __attribute__((visibility("default")))
#endif

/* ------------------------------------------------------------------- kinds */

#define VN_KIND_ONION 0
#define VN_KIND_WG    1

/* ------------------------------------------------------------------ tuning */

#ifndef VN_BATCHNUM
#define VN_BATCHNUM 2048
#endif

#define VN_MAX_PREFIXES    4096
#define VN_MAX_PREFIX_LEN  55
/* 51 base32 chars == 255 bits == the most that fits in the packed key without
 * touching the sign bit that batchpack_destructive_1 leaves unwritten. */
#define VN_ONION_FILTER_MAXCHARS 51
/* 42 base64 chars == 252 bits, all of them real bits of the 32-byte key. */
#define VN_WG_FILTER_MAXCHARS    42

#define VN_ONION_ADDR_LEN 56

/* ------------------------------------------------------- static batch state
 * Upstream keeps these on the worker thread's stack. Python worker processes
 * get a 1 MiB stack, and one BATCHNUM-sized array is already 80 KiB, so they
 * must live in BSS instead. They are never touched from more than one thread at
 * a time: the Python side parallelises with multiprocessing, not threads.
 */
static ge25519     ALIGN(16) g_ge_batch[VN_BATCHNUM];
static bignum25519 ALIGN(16) g_tmp_batch[VN_BATCHNUM];    /* onion: batchpack scratch
                                                           * wg:    denominators z-y   */
static bignum25519 ALIGN(16) g_wg_scratch[VN_BATCHNUM];   /* wg: batchrecip scratch */
static bytes32     ALIGN(16) g_pk_batch[VN_BATCHNUM];

/* --------------------------------------------------------------- filter set */

struct vn_prefix_filter {
	unsigned char f[32];    /* required bits of the packed public key */
	unsigned char nfull;    /* number of wholly-constrained leading bytes */
	unsigned char rem;      /* constrained bits inside f[nfull] (0 or 1..7) */
	unsigned char mask;     /* mask covering those `rem` high bits */
	unsigned char plen;     /* full prefix length in characters */
	char          str[VN_MAX_PREFIX_LEN + 1];
};

/* One filter set per kind: the bit layout differs (5-bit base32 vs 6-bit
 * base64), so the two must never share state. */
static struct vn_prefix_filter g_prefix[2][VN_MAX_PREFIXES];
static int g_nprefix[2];
static int g_inited;

static int b32val(char c)
{
	if (c >= 'a' && c <= 'z') return c - 'a';
	if (c >= '2' && c <= '7') return c - '2' + 26;
	return -1;
}

static int b64val(char c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

static int filter_bits(int kind)
{
	return kind == VN_KIND_ONION ? 5 : 6;
}

static int filter_maxchars(int kind)
{
	return kind == VN_KIND_ONION ? VN_ONION_FILTER_MAXCHARS
	                             : VN_WG_FILTER_MAXCHARS;
}

static int charval(int kind, char c)
{
	return kind == VN_KIND_ONION ? b32val(c) : b64val(c);
}

/* Pack the prefix into a bit mask over the packed public key.
 *
 * Both encodings are big-endian bit slices of the 32-byte key: character j
 * fixes key bits [bits*j, bits*j + bits) with the most significant bit of the
 * character value first. That is true for base32 (RFC 4648, 5 bits per
 * character) and for base64 (6 bits per character). */
static int build_filter(int kind, struct vn_prefix_filter *bf, const char *p,
                        int n)
{
	int bitsper = filter_bits(kind);
	int nchars = n > filter_maxchars(kind) ? filter_maxchars(kind) : n;
	int bits = nchars * bitsper;
	int j, k;

	bf->nfull = (unsigned char)(bits / 8);
	bf->rem = (unsigned char)(bits % 8);
	bf->mask = bf->rem ? (unsigned char)(0xFFu << (8 - bf->rem)) : 0;
	bf->plen = (unsigned char)n;
	vn_memset(bf->f, 0, sizeof(bf->f));

	for (j = 0; j < nchars; ++j) {
		int v = charval(kind, p[j]);
		if (v < 0) return -1;
		for (k = 0; k < bitsper; ++k) {
			if ((v >> (bitsper - 1 - k)) & 1) {
				int abs = bitsper * j + k;
				bf->f[abs >> 3] |= (unsigned char)(0x80u >> (abs & 7));
			}
		}
	}
	for (j = 0; j < n; ++j) bf->str[j] = p[j];
	bf->str[n] = '\0';
	return 0;
}

/* First filter of `kind` that the packed key satisfies, or -1. */
static int filter_hit(int kind, const unsigned char *pk)
{
	int i;
	for (i = 0; i < g_nprefix[kind]; ++i) {
		const struct vn_prefix_filter *bf = &g_prefix[kind][i];
		if (bf->nfull && vn_memcmp(pk, bf->f, bf->nfull) != 0)
			continue;
		if (bf->rem && ((pk[bf->nfull] & bf->mask) != bf->f[bf->nfull]))
			continue;
		return i;
	}
	return -1;
}

static int prefix_full_match(const char *addr, const struct vn_prefix_filter *bf)
{
	int i;
	for (i = 0; i < (int)bf->plen; ++i)
		if (addr[i] != bf->str[i]) return 0;
	return 1;
}

/* ------------------------------------------------------------------ address */

/* addr = base32(pub || sha3_256(".onion checksum" || pub || 0x03)[0..1] || 0x03) */
static void onion_addr_from_pub(const unsigned char *pub,
                                char out[VN_ONION_ADDR_LEN + 1])
{
	static const char checksumstr[] = ".onion checksum";
	unsigned char hashsrc[15 + 32 + 1];
	unsigned char sum[32];
	unsigned char raw[35];

	vn_memcpy(hashsrc, checksumstr, 15);
	vn_memcpy(hashsrc + 15, pub, 32);
	hashsrc[15 + 32] = 0x03;
	FIPS202_SHA3_256(hashsrc, sizeof(hashsrc), sum);

	vn_memcpy(raw, pub, 32);
	raw[32] = sum[0];
	raw[33] = sum[1];
	raw[34] = 0x03;
	base32_to(out, raw, 35);   /* writes 56 chars + NUL */
}

/* ------------------------------------------------------- WireGuard specifics */

/* X25519 clamp - byte for byte the same operation the ed25519 expanded secret
 * gets, which is why the onion and wg paths can share the batch stepping. */
static void wg_clamp(unsigned char sk[32])
{
	sk[0] &= 248;
	sk[31] &= 127;
	sk[31] |= 64;
}

/* Is this 32-byte scalar still in clamped form? Adding the batch counter to it
 * can push byte 31 past 0x7F; upstream mkp224o checks the same invariant on the
 * onion secret and restarts the batch from a fresh random seed if it breaks. */
static int wg_clamped_p(const unsigned char sk[32])
{
	return (sk[0] & 248) == sk[0] && ((sk[31] & 127) | 64) == sk[31];
}

/* Single-point Montgomery conversion: out = (z + y) / (z - y), canonicalised. */
static void wg_point_to_u(unsigned char out[32], const ge25519 *p)
{
	bignum25519 den, num;

	curve25519_sub_reduce(den, p->z, p->y);
	curve25519_recip(den, den);
	curve25519_add_reduce(num, p->z, p->y);
	curve25519_mul(num, num, den);
	curve25519_contract(out, num);
}

/* Batch version: one field inversion for `num` points instead of `num` of them.
 * `den` and `scratch` are caller-provided arrays of VN_BATCHNUM bignum25519
 * (BSS) so nothing is allocated here. */
static void wg_batch_to_u(bytes32 *out, ge25519 *in, bignum25519 *den,
                          bignum25519 *scratch, size_t num)
{
	bignum25519 numv;
	size_t i;

	for (i = 0; i < num; ++i)
		curve25519_sub_reduce(den[i], in[i].z, in[i].y);

	/* in-place batch inversion of all denominators at once */
	curve25519_batchrecip(den, den, scratch, num, sizeof(bignum25519));

	for (i = 0; i < num; ++i) {
		curve25519_add_reduce(numv, in[i].z, in[i].y);
		curve25519_mul(numv, numv, den[i]);
		curve25519_contract(out[i], numv);
	}
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
VN_EXPORT int vanity_init(const unsigned char *seed, unsigned int seed_len)
{
	ge_initeightpoint();
	if (vn_drbg_init(seed, seed_len) != 0)
		return -1;
	g_inited = 1;
	return 0;
}

/* Install the prefix set of one kind. Returns 0, or <0 on bad input.
 * onion: lowercase a-z 2-7, 1..55 characters (characters beyond 51 only narrow
 *        the bit filter and are matched against the full address string).
 * wg:    A-Z a-z 0-9 + /, 1..42 characters (the bit filter covers the whole
 *        prefix, so anything longer is rejected rather than silently relaxed). */
VN_EXPORT int vanity_set_prefixes(int kind, const char *const *prefixes, int n)
{
	int i, j, maxlen;

	if (kind != VN_KIND_ONION && kind != VN_KIND_WG)
		return -1;
	if (n <= 0 || n > VN_MAX_PREFIXES)
		return -2;
	if (!prefixes)
		return -3;
	/* onion takes up to 55 characters (only the first 51 go into the bit
	 * filter, the rest are checked against the address string); wg has no
	 * string re-check here, so 42 characters is a hard limit. */
	maxlen = (kind == VN_KIND_ONION) ? VN_MAX_PREFIX_LEN
	                                 : VN_WG_FILTER_MAXCHARS;

	for (i = 0; i < n; ++i) {
		const char *p = prefixes[i];
		size_t len;

		if (!p) return -4;
		len = vn_strnlen(p, VN_MAX_PREFIX_LEN + 1);
		if (len < 1 || len > (size_t)maxlen)
			return -5;
		/* reject anything outside the alphabet up front */
		for (j = 0; j < (int)len; ++j)
			if (charval(kind, p[j]) < 0) return -7;
		if (build_filter(kind, &g_prefix[kind][i], p, (int)len) != 0)
			return -8;
	}
	g_nprefix[kind] = n;
	return 0;
}

/* ------------------------------------------------------------ onion search */

static int onion_search(unsigned long long max_keys,
                        unsigned long long *checked_out,
                        unsigned char secret_out[64],
                        unsigned char pub_out[32],
                        unsigned char seed_out[32],
                        char onion_out[VN_ONION_ADDR_LEN + 1])
{
	unsigned long long checked = 0;
	unsigned long long counter = 0;
	unsigned char seed[32];
	unsigned char sk[64];
	unsigned char sec[64];
	char addr[VN_ONION_ADDR_LEN + 1];
	ge25519 ALIGN(16) ge_public;
	ge25519_p1p1 ALIGN(16) sum;
	int need_seed = 1;
	int result = 0;

	while (checked < max_keys) {
		size_t bn, b;

		if (need_seed) {
			/* upstream: fresh randombytes() seed per restart */
			vn_drbg_bytes(seed, sizeof(seed));
			ed25519_seckey_expand(sk, seed);
			ge_scalarmult_base(&ge_public, sk);
			counter = 0;
			need_seed = 0;
		}

		bn = (size_t)(max_keys - checked);
		if (bn > (size_t)VN_BATCHNUM) bn = (size_t)VN_BATCHNUM;

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
			int fi = filter_hit(VN_KIND_ONION, g_pk_batch[b]);
			if (fi < 0)
				continue;

			/* finish the pack (fills in the sign bit) and verify with
			 * the real 56-character address - this also covers
			 * prefixes longer than 51 characters, which the bit
			 * filter only constrains partially. */
			ge_p3_batchtobytes_destructive_finish(g_pk_batch[b],
			                                      &g_ge_batch[b]);
			onion_addr_from_pub(g_pk_batch[b], addr);
			if (!prefix_full_match(addr, &g_prefix[VN_KIND_ONION][fi]))
				continue;

			vn_memcpy(sec, sk, sizeof(sec));
			addsztoscalar32(sec, counter + (unsigned long long)b * 8);
			/* same clamp sanity check as upstream: an out-of-range
			 * scalar would mean the secret does not match the key */
			if ((sec[0] & 248) != sec[0] ||
			    ((sec[31] & 63) | 64) != sec[31]) {
				need_seed = 1;
				break;
			}

			vn_memcpy(secret_out, sec, 64);
			vn_memcpy(pub_out, g_pk_batch[b], 32);
			vn_memcpy(seed_out, seed, 32);
			vn_memcpy(onion_out, addr, VN_ONION_ADDR_LEN);
			onion_out[VN_ONION_ADDR_LEN] = '\0';
			result = 1;
			goto done;
		}

		counter += (unsigned long long)bn * 8;
	}

done:
	vn_memzero(seed, sizeof(seed));
	vn_memzero(sk, sizeof(sk));
	vn_memzero(sec, sizeof(sec));
	if (checked_out) *checked_out = checked;
	return result;
}

/* --------------------------------------------------------------- wg search */

static int wg_search(unsigned long long max_keys,
                     unsigned long long *checked_out,
                     unsigned char priv_out[64],
                     unsigned char pub_out[32],
                     unsigned char seed_out[32])
{
	unsigned long long checked = 0;
	unsigned long long counter = 0;
	unsigned char seed[32];
	unsigned char sk[32];
	unsigned char cand[32];
	ge25519 ALIGN(16) ge_public;
	ge25519_p1p1 ALIGN(16) sum;
	int need_seed = 1;
	int result = 0;

	while (checked < max_keys) {
		size_t bn, b;

		if (need_seed) {
			vn_drbg_bytes(seed, sizeof(seed));
			vn_memcpy(sk, seed, 32);
			wg_clamp(sk);
			/* ge_scalarmult_base reduces sk mod L; B has order L,
			 * so this is sk*B, which is what X25519 computes. */
			ge_scalarmult_base(&ge_public, sk);
			counter = 0;
			need_seed = 0;
		}

		bn = (size_t)(max_keys - checked);
		if (bn > (size_t)VN_BATCHNUM) bn = (size_t)VN_BATCHNUM;

		for (b = 0; b < bn; ++b) {
			g_ge_batch[b] = ge_public;
			ge_add(&sum, &ge_public, &ge_eightpoint);
			ge_p1p1_to_p3(&ge_public, &sum);
		}
		/* one inversion for all bn Montgomery conversions */
		wg_batch_to_u(g_pk_batch, g_ge_batch, g_tmp_batch, g_wg_scratch, bn);

		checked += bn;

		for (b = 0; b < bn; ++b) {
			if (filter_hit(VN_KIND_WG, g_pk_batch[b]) < 0)
				continue;

			/* candidate b is the point (sk + 8b)*B; the private key
			 * is that scalar, still in clamped form unless the
			 * increment carried into bit 7 of byte 31. */
			vn_memcpy(cand, sk, 32);
			addsztoscalar32(cand, counter + (unsigned long long)b * 8);
			if (!wg_clamped_p(cand)) {
				need_seed = 1;
				break;
			}

			vn_memzero(priv_out, 64);   /* wg uses the first 32 bytes */
			vn_memcpy(priv_out, cand, 32);
			vn_memcpy(pub_out, g_pk_batch[b], 32);
			vn_memcpy(seed_out, seed, 32);
			result = 1;
			goto done;
		}

		counter += (unsigned long long)bn * 8;
	}

done:
	vn_memzero(seed, sizeof(seed));
	vn_memzero(sk, sizeof(sk));
	vn_memzero(cand, sizeof(cand));
	if (checked_out) *checked_out = checked;
	return result;
}

/* Search up to max_keys candidate keys.
 *
 * Returns 1 if a key matching one of the installed prefixes was found (outputs
 * filled in), 0 if the key budget was exhausted without a find, <0 on error.
 *
 * On success, per kind:
 *   kind 0 (onion): priv_out = 64-byte EXPANDED ed25519 secret (sha512(seed)
 *     clamped, plus the batch counter) exactly as Tor/mkp224o store it,
 *     pub_out = 32-byte ed25519 public key, onion_out = 56-char address.
 *   kind 1 (wg): priv_out[0..32) = clamped X25519 scalar (the remaining 32
 *     bytes are zeroed), pub_out = 32-byte u-coordinate.
 * In both cases seed_out = the 32-byte DRBG seed the batch started from; the
 * caller is responsible for turning raw bytes into whatever string form it
 * needs (base64 for WireGuard). */
VN_EXPORT int vanity_search(int kind, unsigned long long max_keys,
                            unsigned long long *checked_out,
                            unsigned char priv_out[64],
                            unsigned char pub_out[32],
                            unsigned char seed_out[32],
                            char onion_out[VN_ONION_ADDR_LEN + 1])
{
	if (!g_inited) return -10;
	if (kind != VN_KIND_ONION && kind != VN_KIND_WG) return -11;
	if (g_nprefix[kind] <= 0) return -12;
	if (!priv_out || !pub_out || !seed_out) return -13;

	if (kind == VN_KIND_WG) {
		if (onion_out) onion_out[0] = '\0';
		return wg_search(max_keys, checked_out, priv_out, pub_out,
		                 seed_out);
	}
	if (!onion_out) return -14;
	return onion_search(max_keys, checked_out, priv_out, pub_out, seed_out,
	                    onion_out);
}

/* Address for an arbitrary public key. onion: the 56-character v3 address.
 * WireGuard has no native string form inside this module - the caller encodes
 * the raw key as base64 - so kind 1 is rejected with -2. Returns 0 on success. */
VN_EXPORT int vanity_addr_from_pub(int kind, const unsigned char *pub,
                                   char out[64])
{
	if (!pub || !out) return -1;
	if (kind != VN_KIND_ONION) return -2;
	onion_addr_from_pub(pub, out);
	return 0;
}

/* Public key for an arbitrary private key. This is the single-key (non-batch)
 * form of what the search loop does, and it is what the test suite uses to
 * compare the engine against libsodium/PyNaCl:
 *   kind 0: priv = 32-byte seed   -> ed25519 public key
 *   kind 1: priv = 32-byte scalar -> X25519 u-coordinate (clamped first, which
 *           matches crypto_scalarmult_base()). Returns 0, or <0 on bad input. */
VN_EXPORT int vanity_pub_from_priv(int kind, const unsigned char *priv,
                                   unsigned char pub[32])
{
	ge25519 ALIGN(16) P;

	if (!priv || !pub) return -1;

	if (kind == VN_KIND_ONION) {
		unsigned char sk[64];
		ed25519_seckey_expand(sk, priv);
		ge_scalarmult_base(&P, sk);
		ge25519_pack(pub, &P);
		vn_memzero(sk, sizeof(sk));
		return 0;
	}
	if (kind == VN_KIND_WG) {
		unsigned char sk[32];
		vn_memcpy(sk, priv, 32);
		wg_clamp(sk);
		ge_scalarmult_base(&P, sk);
		wg_point_to_u(pub, &P);
		vn_memzero(sk, sizeof(sk));
		return 0;
	}
	return -2;
}

/* Does the installed bit filter of `kind` accept this public key? Index of the
 * first matching prefix is stored in *prefix_index_out. Exposed so the test
 * suite can compare the native filter against the string comparison the Python
 * side would do (addr.startswith / base64(pub).startswith). */
VN_EXPORT int vanity_filter_match(int kind, const unsigned char *pub,
                                  int *prefix_index_out)
{
	int i;
	if (kind != VN_KIND_ONION && kind != VN_KIND_WG) return -2;
	if (!pub || g_nprefix[kind] <= 0) return -1;
	i = filter_hit(kind, pub);
	if (prefix_index_out) *prefix_index_out = i;
	return i >= 0 ? 1 : 0;
}

/* Human-readable engine identification, for diagnostics/tests.
 * Always NUL-terminates; returns the string length. */
VN_EXPORT int vanity_engine_info(char *out, unsigned int outlen)
{
	static const char info[] =
		"vanity_core/mkp224o-donna batch=2048 ed25519-donna "
		"(onion base32 + wg base64)";
	unsigned int i;
	if (!out || outlen == 0) return 0;
	for (i = 0; i + 1 < outlen && info[i]; ++i) out[i] = info[i];
	out[i] = '\0';
	return (int)i;
}

/* Parity with upstream's worker_impl.inc.h, which brackets the worker code with
 * the pre/post headers. Nothing below depends on the aliases they clean up. */
#include "ed25519_impl_post.h"
