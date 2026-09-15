/* vanity_crypto.c - see vanity_crypto.h for the rationale.
 *
 * SHA-512 is a plain FIPS 180-4 implementation. ChaCha20 is RFC 8439. The DRBG
 * is ChaCha20 with a key/nonce derived from the caller-supplied entropy, plus a
 * periodic rekey so that observing a later output does not reveal earlier ones.
 */

#include "vanity_crypto.h"

/* ====================================================================== */
/* Utilities                                                              */
/* ====================================================================== */

void *vn_memcpy(void *dst, const void *src, size_t n)
{
	unsigned char *d = (unsigned char *)dst;
	const unsigned char *s = (const unsigned char *)src;
	while (n--) *d++ = *s++;
	return dst;
}

void *vn_memset(void *dst, int c, size_t n)
{
	unsigned char *d = (unsigned char *)dst;
	while (n--) *d++ = (unsigned char)c;
	return dst;
}

int vn_memcmp(const void *a, const void *b, size_t n)
{
	const unsigned char *x = (const unsigned char *)a;
	const unsigned char *y = (const unsigned char *)b;
	while (n--) {
		if (*x != *y) return (int)*x - (int)*y;
		++x; ++y;
	}
	return 0;
}

void vn_memzero(void *p, size_t len)
{
	volatile unsigned char *v = (volatile unsigned char *)p;
	while (len--) *v++ = 0;
}

size_t vn_strnlen(const char *s, size_t maxlen)
{
	size_t n = 0;
	while (n < maxlen && s[n]) ++n;
	return n;
}

/* ====================================================================== */
/* SHA-512                                                                */
/* ====================================================================== */

static const uint64_t sha512_k[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
	0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
	0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
	0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
	0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
	0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static uint64_t rotr64(uint64_t x, int n)
{
	return (x >> n) | (x << (64 - n));
}

static uint64_t load64_be(const uint8_t *p)
{
	return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
	       ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
	       ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
	       ((uint64_t)p[6] <<  8) | ((uint64_t)p[7]);
}

static void store64_be(uint8_t *p, uint64_t v)
{
	p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
	p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
	p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
	p[6] = (uint8_t)(v >>  8); p[7] = (uint8_t)(v);
}

static void sha512_compress(uint64_t h[8], const uint8_t block[128])
{
	uint64_t w[80], a, b, c, d, e, f, g, hh, t1, t2;
	int i;

	for (i = 0; i < 16; ++i)
		w[i] = load64_be(block + i * 8);
	for (i = 16; i < 80; ++i) {
		uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^
		              (w[i - 15] >> 7);
		uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^
		              (w[i - 2] >> 6);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];

	for (i = 0; i < 80; ++i) {
		uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
		uint64_t ch = (e & f) ^ ((~e) & g);
		uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
		uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
		t1 = hh + S1 + ch + sha512_k[i] + w[i];
		t2 = S0 + mj;
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void vn_sha512_init(vn_sha512_ctx *c)
{
	c->h[0] = 0x6a09e667f3bcc908ULL;
	c->h[1] = 0xbb67ae8584caa73bULL;
	c->h[2] = 0x3c6ef372fe94f82bULL;
	c->h[3] = 0xa54ff53a5f1d36f1ULL;
	c->h[4] = 0x510e527fade682d1ULL;
	c->h[5] = 0x9b05688c2b3e6c1fULL;
	c->h[6] = 0x1f83d9abfb41bd6bULL;
	c->h[7] = 0x5be0cd19137e2179ULL;
	c->len_lo = 0;
	c->len_hi = 0;
	c->buflen = 0;
}

void vn_sha512_update(vn_sha512_ctx *c, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;

	uint64_t add = (uint64_t)len;
	c->len_lo += add;
	if (c->len_lo < add) ++c->len_hi;

	if (c->buflen) {
		size_t want = 128 - c->buflen;
		if (want > len) want = len;
		vn_memcpy(c->buf + c->buflen, p, want);
		c->buflen += want;
		p += want;
		len -= want;
		if (c->buflen == 128) {
			sha512_compress(c->h, c->buf);
			c->buflen = 0;
		}
	}

	while (len >= 128) {
		sha512_compress(c->h, p);
		p += 128;
		len -= 128;
	}

	if (len) {
		vn_memcpy(c->buf, p, len);
		c->buflen = len;
	}
}

void vn_sha512_final(vn_sha512_ctx *c, uint8_t out[64])
{
	uint64_t bits_lo, bits_hi;
	size_t i;

	/* total length in bits (128-bit big-endian) */
	bits_hi = (c->len_hi << 3) | (c->len_lo >> 61);
	bits_lo = c->len_lo << 3;

	c->buf[c->buflen++] = 0x80;
	if (c->buflen > 112) {
		vn_memset(c->buf + c->buflen, 0, 128 - c->buflen);
		sha512_compress(c->h, c->buf);
		c->buflen = 0;
	}
	vn_memset(c->buf + c->buflen, 0, 112 - c->buflen);
	store64_be(c->buf + 112, bits_hi);
	store64_be(c->buf + 120, bits_lo);
	sha512_compress(c->h, c->buf);

	for (i = 0; i < 8; ++i)
		store64_be(out + i * 8, c->h[i]);

	vn_memzero(c, sizeof(*c));
}

void vn_sha512(uint8_t out[64], const void *data, size_t len)
{
	vn_sha512_ctx c;
	vn_sha512_init(&c);
	vn_sha512_update(&c, data, len);
	vn_sha512_final(&c, out);
}

void vn_sha512_2(uint8_t out[64], const void *a, size_t alen,
                 const void *b, size_t blen)
{
	vn_sha512_ctx c;
	vn_sha512_init(&c);
	vn_sha512_update(&c, a, alen);
	vn_sha512_update(&c, b, blen);
	vn_sha512_final(&c, out);
}

int crypto_hash_sha512_init(crypto_hash_sha512_state *s)
{
	vn_sha512_init(s);
	return 0;
}

int crypto_hash_sha512_update(crypto_hash_sha512_state *s,
                              const unsigned char *in,
                              unsigned long long inlen)
{
	vn_sha512_update(s, in, (size_t)inlen);
	return 0;
}

int crypto_hash_sha512_final(crypto_hash_sha512_state *s, unsigned char *out)
{
	vn_sha512_final(s, out);
	return 0;
}

int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen)
{
	vn_sha512(out, in, (size_t)inlen);
	return 0;
}

/* ====================================================================== */
/* ChaCha20 (RFC 8439) - keystream only, no Poly1305                      */
/* ====================================================================== */

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QR(a, b, c, d)                     \
	do {                               \
		a += b; d ^= a; d = ROTL32(d, 16); \
		c += d; b ^= c; b = ROTL32(b, 12); \
		a += b; d ^= a; d = ROTL32(d, 8);  \
		c += d; b ^= c; b = ROTL32(b, 7);  \
	} while (0)

typedef struct {
	uint32_t input[16];
	uint8_t  block[64];
	size_t   have;        /* bytes of `block` still unused */
	uint64_t block_index;
} vn_chacha_ctx;

static void chacha20_block(vn_chacha_ctx *c)
{
	uint32_t x[16];
	int i;

	for (i = 0; i < 16; ++i) x[i] = c->input[i];

	for (i = 0; i < 10; ++i) {
		QR(x[0], x[4], x[8],  x[12]);
		QR(x[1], x[5], x[9],  x[13]);
		QR(x[2], x[6], x[10], x[14]);
		QR(x[3], x[7], x[11], x[15]);
		QR(x[0], x[5], x[10], x[15]);
		QR(x[1], x[6], x[11], x[12]);
		QR(x[2], x[7], x[8],  x[13]);
		QR(x[3], x[4], x[9],  x[14]);
	}

	for (i = 0; i < 16; ++i) {
		uint32_t v = x[i] + c->input[i];
		c->block[i * 4 + 0] = (uint8_t)(v);
		c->block[i * 4 + 1] = (uint8_t)(v >> 8);
		c->block[i * 4 + 2] = (uint8_t)(v >> 16);
		c->block[i * 4 + 3] = (uint8_t)(v >> 24);
	}

	/* 32-bit little-endian block counter in word 12 */
	c->input[12] += 1;
	if (c->input[12] == 0)
		c->input[13] += 1;   /* nonce words 13..15 are ours to carry into */

	c->have = 64;
	vn_memzero(x, sizeof(x));
}

static void chacha20_init(vn_chacha_ctx *c, const uint8_t key[32],
                          const uint8_t nonce[12], uint32_t counter)
{
	static const char sigma[16] = "expand 32-byte k";
	int i;

	for (i = 0; i < 4; ++i) {
		c->input[i] = (uint32_t)sigma[i * 4 + 0] |
		              ((uint32_t)sigma[i * 4 + 1] << 8) |
		              ((uint32_t)sigma[i * 4 + 2] << 16) |
		              ((uint32_t)sigma[i * 4 + 3] << 24);
	}
	for (i = 0; i < 8; ++i) {
		c->input[4 + i] = (uint32_t)key[i * 4 + 0] |
		                  ((uint32_t)key[i * 4 + 1] << 8) |
		                  ((uint32_t)key[i * 4 + 2] << 16) |
		                  ((uint32_t)key[i * 4 + 3] << 24);
	}
	c->input[12] = counter;
	c->input[13] = (uint32_t)nonce[0] | ((uint32_t)nonce[1] << 8) |
	               ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
	c->input[14] = (uint32_t)nonce[4] | ((uint32_t)nonce[5] << 8) |
	               ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
	c->input[15] = (uint32_t)nonce[8] | ((uint32_t)nonce[9] << 8) |
	               ((uint32_t)nonce[10] << 16) | ((uint32_t)nonce[11] << 24);

	c->have = 0;
	c->block_index = 0;
}

/* ====================================================================== */
/* DRBG                                                                   */
/* ====================================================================== */

/* Re-key after this much output. Bounds the amount of keystream produced under
 * a single (key, nonce) pair and gives forward secrecy between generations. */
#define WG_DRBG_REKEY_BYTES ((uint64_t)1 << 20)

static vn_chacha_ctx vn_drbg;
static uint8_t       vn_drbg_key[32];
static uint8_t       vn_drbg_nonce[12];
static uint64_t      vn_drbg_since_rekey;
static int           vn_drbg_ready;

static void drbg_start_generation(const uint8_t key[32],
                                  const uint8_t nonce[12])
{
	vn_memcpy(vn_drbg_key, key, 32);
	vn_memcpy(vn_drbg_nonce, nonce, 12);
	chacha20_init(&vn_drbg, vn_drbg_key, vn_drbg_nonce, 0);
	vn_drbg_since_rekey = 0;
}

/* Fold `len` bytes of fresh entropy into the DRBG state and restart the
 * generation. Used both for the initial seeding and for rekeying, so that an
 * attacker who learns the current state cannot rewind to earlier output. */
static void drbg_reseed(const uint8_t *extra, size_t extra_len)
{
	static const uint8_t label[24] = "wg-vanity onion drbg v1";
	uint8_t h[64];
	vn_sha512_ctx c;

	vn_sha512_init(&c);
	vn_sha512_update(&c, label, sizeof(label));
	vn_sha512_update(&c, vn_drbg_key, 32);
	vn_sha512_update(&c, &vn_drbg_since_rekey, sizeof(vn_drbg_since_rekey));
	if (extra && extra_len)
		vn_sha512_update(&c, extra, extra_len);
	vn_sha512_final(&c, h);

	drbg_start_generation(h, h + 32);
	vn_memzero(h, sizeof(h));
}

int vn_drbg_init(const unsigned char *seed, unsigned int seed_len)
{
	static const uint8_t label[24] = "wg-vanity onion drbg v1";
	uint8_t h[64];

	if (!seed || seed_len < 32)
		return -1;

	vn_memzero(&vn_drbg, sizeof(vn_drbg));
	vn_memzero(vn_drbg_key, sizeof(vn_drbg_key));
	vn_memzero(vn_drbg_nonce, sizeof(vn_drbg_nonce));
	vn_drbg_since_rekey = 0;

	vn_sha512_2(h, label, sizeof(label), seed, seed_len);
	drbg_start_generation(h, h + 32);
	vn_memzero(h, sizeof(h));

	/* warm up: throw away the first block, then fold a fresh block back in */
	{
		uint8_t warm[64];
		vn_drbg_bytes(warm, sizeof(warm));
		drbg_reseed(warm, sizeof(warm));
		vn_memzero(warm, sizeof(warm));
	}

	vn_drbg_ready = 1;
	return 0;
}

int vn_drbg_is_ready(void)
{
	return vn_drbg_ready;
}

void vn_drbg_bytes(void *out, size_t len)
{
	uint8_t *p = (uint8_t *)out;

	if (!vn_drbg_ready) {
		/* Refuse to emit predictable bytes: caller forgot vanity_init.
		 * Zero-fill is the safest failure mode for a search that only
		 * consumes these bytes as a search seed. */
		vn_memset(out, 0, len);
		return;
	}

	while (len) {
		size_t take;

		if (vn_drbg_since_rekey >= WG_DRBG_REKEY_BYTES)
			drbg_reseed(0, 0);

		if (vn_drbg.have == 0)
			chacha20_block(&vn_drbg);

		take = vn_drbg.have < len ? vn_drbg.have : len;
		vn_memcpy(p, vn_drbg.block + (64 - vn_drbg.have), take);
		vn_drbg.have -= take;
		vn_drbg_since_rekey += take;
		p += take;
		len -= take;
	}
	/* Consume the current block fully before it can be handed out again. */
	if (vn_drbg.have == 0)
		vn_memzero(vn_drbg.block, sizeof(vn_drbg.block));
}
