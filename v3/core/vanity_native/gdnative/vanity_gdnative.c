/* vanity_gdnative.c - GDNative (Godot 3 NativeScript) wrapper around the same
 * C vanity-search engine that Windows and Linux already ship.
 *
 * Why this file exists: on desktop the GUI starts an external worker process
 * (wg_worker) and talks to it over TCP loopback. Android cannot do that -
 * OS.execute() is not implemented in Godot 3 on Android and Android 10+ forbids
 * executing binaries from the app's data directory. So on Android the search
 * has to run *inside* the app, and this wrapper is the bridge: a NativeScript
 * class ("VanityEngine") that converts GDScript Variants into the plain buffers
 * vanity_bridge.c expects and back.
 *
 * It is deliberately thin - no cryptography, no base64 tables beyond the one
 * small encoder at the bottom (WireGuard keys have no string form inside the
 * engine; it hands back raw bytes). Everything heavy is the untouched, already
 * released engine:
 *
 *   vanity_bridge.c    batch loop (mkp224o ed25519-donna) + the C ABI
 *   vanity_crypto.c    SHA-512 + ChaCha20 DRBG, no libc
 *   vendor/            keccak, base32_to, ed25519-donna
 *
 * One shared object per ABI is built, containing BOTH the engine and this
 * wrapper, so the APK carries a single libvanity_gdnative.so per architecture
 * (see ../build.ps1, targets android-*).
 *
 * ---------------------------------------------------------------------------
 * THREAD SAFETY - read this before adding workers
 *
 * The engine keeps its batch state, prefix filters and DRBG in global static
 * buffers (see vanity_bridge.c) and is explicitly NOT thread safe. The Android
 * backend therefore runs ONE search thread (LocalBridge.gd forces workers=1).
 * Making it multi-threaded would mean moving that state into a per-instance
 * context inside the engine - a separate task, not done here.
 *
 * ---------------------------------------------------------------------------
 * API (registered on the VanityEngine class, see vanity_engine.gdns)
 *
 *   init(seed: PoolByteArray) -> int
 *       Seeds the DRBG (32..64 bytes, from the GDScript side). 0 on success.
 *   set_prefixes(kind: int, prefixes: PoolStringArray) -> int
 *       kind 0 = .onion base32, kind 1 = WireGuard base64. 0 on success,
 *       negative on bad input (same codes as vanity_set_prefixes).
 *   search(kind: int, max_keys: int) -> Dictionary
 *       {found: bool, error: int, checked: int, priv: PoolByteArray,
 *        pub: PoolByteArray, seed: PoolByteArray, onion: String}
 *       error == 0 and found == true  -> key found, outputs filled in
 *       error == 0 and found == false -> key budget exhausted, no match
 *       error  < 0                    -> engine refused (see vanity_search)
 *       priv is 64 bytes for kind 0 (expanded ed25519 secret) and 32 bytes for
 *       kind 1 (clamped X25519 scalar); seed is always 32 bytes and is the
 *       seed the winning batch started from (needed for the saved .txt).
 *       onion is the 56-character address for kind 0, empty for kind 1.
 *   addr_from_pub(kind: int, pub: PoolByteArray) -> String
 *       kind 0: the 56-character .onion address (computed by the engine).
 *       kind 1: base64 of the 32-byte key (the engine has no string form for
 *               WireGuard keys - the Python side encodes them too).
 *   pub_from_priv(kind: int, priv: PoolByteArray) -> PoolByteArray
 *       32-byte public key for a 32-byte private key (ed25519 seed / X25519
 *       scalar). Empty PoolByteArray on bad input.
 *   engine_info() -> String
 *       Human-readable engine identification for diagnostics.
 *
 * WireGuard note: base64 of a 32-byte key is always 44 characters, so the
 * "prefix" of a key is just the first N characters; comparing them as strings
 * is what LocalBridge.gd does for the found key's prefix label, while the hot
 * loop uses the engine's exact bit filter.
 */

#include <stddef.h>
#include <stdint.h>

/* godot_headers' android/godot_android.h unconditionally includes <jni.h> when
 * __ANDROID__ is defined, and <jni.h> only exists in the NDK. We cross-compile
 * with zig and no NDK on purpose (see ../build.ps1), so pre-empt that header's
 * include guard and provide the two opaque types it needs. We never call the
 * Android extension API - only the core and nativescript structs - so an
 * incomplete type is enough and nothing here depends on JNI layout. */
#if defined(__ANDROID__)
#define GODOT_ANDROID_H
typedef struct vn_opaque_jni_env_ vn_opaque_jni_env_;
typedef vn_opaque_jni_env_ *JNIEnv;
typedef void *jobject;
#endif

#include <gdnative_api_struct.gen.h>

/* The engine's C ABI (implemented in ../vanity_bridge.c). Declared here instead
 * of including vanity_bridge.h, which does not exist: this file is compiled
 * into the same shared object as the engine, so the symbols are local. */
int vanity_init(const unsigned char *seed, unsigned int seed_len);
int vanity_set_prefixes(int kind, const char *const *prefixes, int n);
int vanity_search(int kind, unsigned long long max_keys,
                  unsigned long long *checked_out,
                  unsigned char priv_out[64], unsigned char pub_out[32],
                  unsigned char seed_out[32],
                  char onion_out[57]);
int vanity_addr_from_pub(int kind, const unsigned char *pub, char out[64]);
int vanity_pub_from_priv(int kind, const unsigned char *priv,
                         unsigned char pub[32]);
int vanity_engine_info(char *out, unsigned int outlen);
/* from ../vanity_crypto.c: the engine's own libc-less memset variant */
void vn_memzero(void *p, size_t len);

/* Length of a NUL-terminated string, capped (nothing here is longer than a
 * .onion address). Avoids pulling in a libc strlen we do not link against. */
static int str_len(const char *s)
{
	int n = 0;

	while (n < 256 && s[n] != '\0') {
		++n;
	}
	return n;
}

/* ------------------------------------------------------------------- kinds */

#define VN_KIND_ONION 0
#define VN_KIND_WG    1

/* ------------------------------------------------------------------ limits */

#define VN_MAX_PREFIXES 4096
/* longest accepted prefix is 55 characters (onion); 64 bytes of storage per
 * prefix keeps the NUL and leaves room for the engine to reject longer ones
 * itself instead of us overrunning a buffer. */
#define VN_MAX_PREFIX_BYTES 64
#define VN_ONION_ADDR_LEN   56

/* ---------------------------------------------------------- godot_api hooks */

static const godot_gdnative_core_api_struct *g_api = NULL;
static const godot_gdnative_ext_nativescript_api_struct *g_ns = NULL;

/* Prefix staging area for set_prefixes(). The engine copies the characters it
 * keeps into its own static filter structs during the call and never retains
 * these pointers, so one reusable buffer is enough. BSS, not stack: 4096
 * prefixes would otherwise mean a quarter-megabyte frame. */
static char g_prefix_buf[VN_MAX_PREFIXES][VN_MAX_PREFIX_BYTES];
static const char *g_prefix_ptr[VN_MAX_PREFIXES];

/* --------------------------------------------------------------- Variant IO */

static godot_variant ret_nil(void)
{
	godot_variant v;
	g_api->godot_variant_new_nil(&v);
	return v;
}

static godot_variant ret_int(int64_t i)
{
	godot_variant v;
	g_api->godot_variant_new_int(&v, i);
	return v;
}

static godot_variant ret_bool(godot_bool b)
{
	godot_variant v;
	g_api->godot_variant_new_bool(&v, b);
	return v;
}

static godot_variant ret_empty_string(void)
{
	godot_variant v;
	godot_string s;
	g_api->godot_string_new(&s);
	g_api->godot_variant_new_string(&v, &s);
	g_api->godot_string_destroy(&s);
	return v;
}

/* Variant(String) from a NUL-terminated ASCII/UTF-8 buffer of known length. */
static godot_variant ret_string_n(const char *s, int n)
{
	godot_variant v;
	godot_string str;

	if (n <= 0) {
		return ret_empty_string();
	}
	g_api->godot_string_new(&str);
	g_api->godot_string_parse_utf8_with_len(&str, s, n);
	g_api->godot_variant_new_string(&v, &str);
	g_api->godot_string_destroy(&str);
	return v;
}

/* Variant(PoolByteArray) with a copy of p[0..n). The variant owns its copy, so
 * the temporary pool array is released here. */
static godot_variant ret_bytes(const unsigned char *p, int n)
{
	godot_variant v;
	godot_pool_byte_array pba;

	g_api->godot_pool_byte_array_new(&pba);
	if (n > 0) {
		godot_pool_byte_array_write_access *wa;

		g_api->godot_pool_byte_array_resize(&pba, n);
		wa = g_api->godot_pool_byte_array_write(&pba);
		if (wa != NULL) {
			unsigned char *dst = g_api->godot_pool_byte_array_write_access_ptr(wa);
			int i;
			for (i = 0; i < n; ++i) {
				dst[i] = p[i];
			}
			g_api->godot_pool_byte_array_write_access_destroy(wa);
		}
	}
	g_api->godot_variant_new_pool_byte_array(&v, &pba);
	g_api->godot_pool_byte_array_destroy(&pba);
	return v;
}

/* Read a PoolByteArray argument into buf (at most cap bytes).
 * Returns the number of bytes copied, or -1 if the argument is not a
 * PoolByteArray. */
static int arg_bytes(godot_variant *v, unsigned char *buf, int cap)
{
	godot_pool_byte_array pba;
	godot_pool_byte_array_read_access *ra;
	const uint8_t *src;
	int n, i;

	if (g_api->godot_variant_get_type(v) != GODOT_VARIANT_TYPE_POOL_BYTE_ARRAY) {
		return -1;
	}
	pba = g_api->godot_variant_as_pool_byte_array(v);
	n = (int)g_api->godot_pool_byte_array_size(&pba);
	if (n < 0 || n > cap) {
		g_api->godot_pool_byte_array_destroy(&pba);
		return -1;
	}
	ra = g_api->godot_pool_byte_array_read(&pba);
	src = g_api->godot_pool_byte_array_read_access_ptr(ra);
	for (i = 0; i < n; ++i) {
		buf[i] = src[i];
	}
	g_api->godot_pool_byte_array_read_access_destroy(ra);
	g_api->godot_pool_byte_array_destroy(&pba);
	return n;
}

/* int argument, or `fallback` if the argument is missing / not numeric.
 * A float is accepted too so `kind` and `max_keys` can be written either way
 * from GDScript. */
static int64_t arg_int(int argc, godot_variant **argv, int idx, int64_t fallback)
{
	godot_variant_type t;

	if (idx >= argc) {
		return fallback;
	}
	t = g_api->godot_variant_get_type(argv[idx]);
	if (t == GODOT_VARIANT_TYPE_INT) {
		return g_api->godot_variant_as_int(argv[idx]);
	}
	if (t == GODOT_VARIANT_TYPE_REAL) {
		return (int64_t)g_api->godot_variant_as_real(argv[idx]);
	}
	return fallback;
}

/* --------------------------------------------------------------- base64 */

static const char B64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* RFC 4648 base64 of n bytes -> out (needs 4*ceil(n/3)+1). Used for kind 1
 * only: the engine returns raw WireGuard keys and has no encoder (the Python
 * side does this with base64.b64encode). Not cryptography, just an encoder. */
static int b64_encode(const unsigned char *in, int n, char *out)
{
	int i, o = 0;

	for (i = 0; i + 2 < n; i += 3) {
		uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
		             (uint32_t)in[i + 2];
		out[o++] = B64[(v >> 18) & 63];
		out[o++] = B64[(v >> 12) & 63];
		out[o++] = B64[(v >> 6) & 63];
		out[o++] = B64[v & 63];
	}
	if (i < n) {
		uint32_t v = (uint32_t)in[i] << 16;
		int rem = n - i;

		if (rem == 2) {
			v |= (uint32_t)in[i + 1] << 8;
		}
		out[o++] = B64[(v >> 18) & 63];
		out[o++] = B64[(v >> 12) & 63];
		out[o++] = rem == 2 ? B64[(v >> 6) & 63] : '=';
		out[o++] = '=';
	}
	out[o] = '\0';
	return o;
}

/* ------------------------------------------------------- NativeScript class */

static void *vn_instance_create(godot_object *p_obj, void *p_method_data)
{
	(void)p_obj;
	(void)p_method_data;
	/* The engine keeps its own global state, so an instance has no data of its
	 * own. Returning NULL is the documented way of saying exactly that. */
	return NULL;
}

static void vn_instance_destroy(godot_object *p_obj, void *p_method_data,
                                void *p_user_data)
{
	(void)p_obj;
	(void)p_method_data;
	(void)p_user_data;
}

/* init(seed: PoolByteArray) -> int */
static godot_variant vn_method_init(godot_object *p_obj, void *p_method_data,
                                    void *p_user_data, int p_num_args,
                                    godot_variant **p_args)
{
	unsigned char seed[64];
	int n;

	(void)p_obj;
	(void)p_method_data;
	(void)p_user_data;

	if (p_num_args < 1) {
		return ret_int(-1);
	}
	n = arg_bytes(p_args[0], seed, (int)sizeof(seed));
	if (n < 32 || n > 64) {
		return ret_int(-1);
	}
	return ret_int(vanity_init(seed, (unsigned int)n));
}

/* set_prefixes(kind: int, prefixes: PoolStringArray) -> int */
static godot_variant vn_method_set_prefixes(godot_object *p_obj,
                                            void *p_method_data,
                                            void *p_user_data, int p_num_args,
                                            godot_variant **p_args)
{
	godot_pool_string_array arr;
	godot_pool_string_array_read_access *ra;
	const godot_string *items;
	int kind, n, i, rc;

	(void)p_obj;
	(void)p_method_data;
	(void)p_user_data;

	if (p_num_args < 2) {
		return ret_int(-3);
	}
	kind = (int)arg_int(p_num_args, p_args, 0, -1);
	if (kind != VN_KIND_ONION && kind != VN_KIND_WG) {
		return ret_int(-1);
	}
	if (g_api->godot_variant_get_type(p_args[1]) !=
	    GODOT_VARIANT_TYPE_POOL_STRING_ARRAY) {
		return ret_int(-3);
	}

	arr = g_api->godot_variant_as_pool_string_array(p_args[1]);
	n = (int)g_api->godot_pool_string_array_size(&arr);
	if (n <= 0 || n > VN_MAX_PREFIXES) {
		g_api->godot_pool_string_array_destroy(&arr);
		return ret_int(-2);
	}

	ra = g_api->godot_pool_string_array_read(&arr);
	items = g_api->godot_pool_string_array_read_access_ptr(ra);

	for (i = 0; i < n; ++i) {
		godot_char_string cs;
		const char *src;
		int len, j;

		cs = g_api->godot_string_utf8(&items[i]);
		src = g_api->godot_char_string_get_data(&cs);
		len = (int)g_api->godot_char_string_length(&cs);
		if (len < 1 || len >= VN_MAX_PREFIX_BYTES) {
			g_api->godot_char_string_destroy(&cs);
			g_api->godot_pool_string_array_read_access_destroy(ra);
			g_api->godot_pool_string_array_destroy(&arr);
			return ret_int(-5);
		}
		for (j = 0; j < len; ++j) {
			g_prefix_buf[i][j] = src[j];
		}
		g_prefix_buf[i][len] = '\0';
		g_prefix_ptr[i] = g_prefix_buf[i];
		g_api->godot_char_string_destroy(&cs);
	}

	g_api->godot_pool_string_array_read_access_destroy(ra);
	g_api->godot_pool_string_array_destroy(&arr);

	/* The engine validates the alphabet and the per-kind length limits. */
	rc = vanity_set_prefixes(kind, g_prefix_ptr, n);
	return ret_int(rc);
}

/* One PoolByteArray value inside the result dictionary. */
static void dict_set_bytes(godot_dictionary *d, const char *key,
                           const unsigned char *bytes, int n)
{
	godot_variant k, v;
	godot_string ks;

	g_api->godot_string_new(&ks);
	g_api->godot_string_parse_utf8_with_len(&ks, key, (int)str_len(key));
	g_api->godot_variant_new_string(&k, &ks);
	g_api->godot_string_destroy(&ks);

	v = ret_bytes(bytes, n);
	g_api->godot_dictionary_set(d, &k, &v);
	g_api->godot_variant_destroy(&k);
	g_api->godot_variant_destroy(&v);
}

static void dict_set_int(godot_dictionary *d, const char *key, int64_t i)
{
	godot_variant k, v;
	godot_string ks;

	g_api->godot_string_new(&ks);
	g_api->godot_string_parse_utf8_with_len(&ks, key, (int)str_len(key));
	g_api->godot_variant_new_string(&k, &ks);
	g_api->godot_string_destroy(&ks);

	v = ret_int(i);
	g_api->godot_dictionary_set(d, &k, &v);
	g_api->godot_variant_destroy(&k);
	g_api->godot_variant_destroy(&v);
}

static void dict_set_bool(godot_dictionary *d, const char *key, godot_bool b)
{
	godot_variant k, v;
	godot_string ks;

	g_api->godot_string_new(&ks);
	g_api->godot_string_parse_utf8_with_len(&ks, key, (int)str_len(key));
	g_api->godot_variant_new_string(&k, &ks);
	g_api->godot_string_destroy(&ks);

	v = ret_bool(b);
	g_api->godot_dictionary_set(d, &k, &v);
	g_api->godot_variant_destroy(&k);
	g_api->godot_variant_destroy(&v);
}

static void dict_set_string_n(godot_dictionary *d, const char *key,
                              const char *s, int n)
{
	godot_variant k, v;
	godot_string ks;

	g_api->godot_string_new(&ks);
	g_api->godot_string_parse_utf8_with_len(&ks, key, (int)str_len(key));
	g_api->godot_variant_new_string(&k, &ks);
	g_api->godot_string_destroy(&ks);

	v = ret_string_n(s, n);
	g_api->godot_dictionary_set(d, &k, &v);
	g_api->godot_variant_destroy(&k);
	g_api->godot_variant_destroy(&v);
}

/* search(kind: int, max_keys: int) -> Dictionary */
static godot_variant vn_method_search(godot_object *p_obj, void *p_method_data,
                                      void *p_user_data, int p_num_args,
                                      godot_variant **p_args)
{
	unsigned char priv[64];
	unsigned char pub[32];
	unsigned char seed[32];
	char onion[VN_ONION_ADDR_LEN + 1];
	unsigned long long max_keys, checked = 0;
	int kind, rc;
	godot_dictionary d;
	godot_variant out;

	(void)p_obj;
	(void)p_method_data;
	(void)p_user_data;

	kind = (int)arg_int(p_num_args, p_args, 0, -1);
	max_keys = (unsigned long long)arg_int(p_num_args, p_args, 1, 0);

	priv[0] = pub[0] = seed[0] = 0;
	onion[0] = '\0';

	if (kind != VN_KIND_ONION && kind != VN_KIND_WG || max_keys == 0) {
		rc = -11;
	} else {
		rc = vanity_search(kind, max_keys, &checked, priv, pub, seed, onion);
	}
	if (rc < 0) {
		checked = 0;
	}

	g_api->godot_dictionary_new(&d);
	dict_set_bool(&d, "found", rc == 1);
	dict_set_int(&d, "error", rc < 0 ? rc : 0);
	dict_set_int(&d, "checked", (int64_t)checked);
	dict_set_bytes(&d, "priv", priv,
	               rc == 1 ? (kind == VN_KIND_ONION ? 64 : 32) : 0);
	dict_set_bytes(&d, "pub", pub, rc == 1 ? 32 : 0);
	dict_set_bytes(&d, "seed", seed, rc == 1 ? 32 : 0);
	dict_set_string_n(&d, "onion", onion,
	                  rc == 1 && kind == VN_KIND_ONION
	                      ? str_len(onion) : 0);

	g_api->godot_variant_new_dictionary(&out, &d);
	g_api->godot_dictionary_destroy(&d);

	/* Scrub the private material we copied out of the engine's statics. The
	 * returned PoolByteArrays hold their own copies, which GDScript owns. */
	vn_memzero(priv, sizeof(priv));
	vn_memzero(seed, sizeof(seed));
	return out;
}

/* addr_from_pub(kind: int, pub: PoolByteArray) -> String */
static godot_variant vn_method_addr_from_pub(godot_object *p_obj,
                                             void *p_method_data,
                                             void *p_user_data, int p_num_args,
                                             godot_variant **p_args)
{
	unsigned char pub[32];
	char out[64];
	int kind, n;

	(void)p_obj;
	(void)p_method_data;
	(void)p_user_data;

	if (p_num_args < 2) {
		return ret_empty_string();
	}
	kind = (int)arg_int(p_num_args, p_args, 0, -1);
	n = arg_bytes(p_args[1], pub, (int)sizeof(pub));
	if (n != 32) {
		return ret_empty_string();
	}

	if (kind == VN_KIND_WG) {
		char b64[48];
		int len = b64_encode(pub, 32, b64);
		return ret_string_n(b64, len);
	}
	if (kind != VN_KIND_ONION) {
		return ret_empty_string();
	}
	if (vanity_addr_from_pub(VN_KIND_ONION, pub, out) != 0) {
		return ret_empty_string();
	}
	return ret_string_n(out, (int)str_len(out));
}

/* pub_from_priv(kind: int, priv: PoolByteArray) -> PoolByteArray */
static godot_variant vn_method_pub_from_priv(godot_object *p_obj,
                                             void *p_method_data,
                                             void *p_user_data, int p_num_args,
                                             godot_variant **p_args)
{
	unsigned char priv[64];
	unsigned char pub[32];
	int kind, n;

	(void)p_obj;
	(void)p_method_data;
	(void)p_user_data;

	pub[0] = 0;
	if (p_num_args < 2) {
		return ret_bytes(pub, 0);
	}
	kind = (int)arg_int(p_num_args, p_args, 0, -1);
	n = arg_bytes(p_args[1], priv, 32);   /* both kinds take 32 bytes */
	if (n != 32) {
		return ret_bytes(pub, 0);
	}
	if (vanity_pub_from_priv(kind, priv, pub) != 0) {
		return ret_bytes(pub, 0);
	}
	return ret_bytes(pub, 32);
}

/* engine_info() -> String */
static godot_variant vn_method_engine_info(godot_object *p_obj,
                                           void *p_method_data,
                                           void *p_user_data, int p_num_args,
                                           godot_variant **p_args)
{
	char info[192];
	int n;

	(void)p_obj;
	(void)p_method_data;
	(void)p_user_data;
	(void)p_num_args;
	(void)p_args;

	n = vanity_engine_info(info, (unsigned int)sizeof(info));
	return ret_string_n(info, n);
}

static void register_method(void *handle, const char *name,
                            godot_instance_method method)
{
	godot_method_attributes attr;

	attr.rpc_type = GODOT_METHOD_RPC_MODE_DISABLED;
	method.method_data = NULL;
	method.free_func = NULL;
	g_ns->godot_nativescript_register_method(handle, "VanityEngine", name,
	                                         attr, method);
}

/* ------------------------------------------------------------- entry points */

#if defined(_WIN32)
#define VN_EXPORT __declspec(dllexport)
#else
#define VN_EXPORT __attribute__((visibility("default")))
#endif

void VN_EXPORT godot_gdnative_init(godot_gdnative_init_options *options)
{
	unsigned int i;

	g_api = options->api_struct;
	g_ns = NULL;
	/* Walk the extension chain for NativeScript 1.0 - that is the struct the
	 * registration functions below live in. Everything goes through these api
	 * structs on purpose: the matching free functions declared in
	 * nativescript/godot_nativescript.h are engine exports, and on Android a
	 * dlopen'd library cannot rely on the engine's dynamic symbol table. */
	unsigned int _next = g_api->num_extensions; if (_next > 32) _next = 32; for (i = 0; i < _next; ++i) {
		if (g_api->extensions[i]->type == GDNATIVE_EXT_NATIVESCRIPT) {
			g_ns = (const godot_gdnative_ext_nativescript_api_struct *)
			       g_api->extensions[i];
			break;
		}
	}
}

void VN_EXPORT godot_gdnative_terminate(
	godot_gdnative_terminate_options *options)
{
	(void)options;
	g_api = NULL;
	g_ns = NULL;
}

void VN_EXPORT godot_nativescript_init(void *handle)
{
	godot_instance_create_func create;
	godot_instance_destroy_func destroy;
	godot_instance_method m;

	if (g_ns == NULL) {
		return;
	}

	create.create_func = &vn_instance_create;
	create.method_data = NULL;
	create.free_func = NULL;
	destroy.destroy_func = &vn_instance_destroy;
	destroy.method_data = NULL;
	destroy.free_func = NULL;

	g_ns->godot_nativescript_register_class(handle, "VanityEngine", "Reference",
	                                        create, destroy);

	m.method = &vn_method_init;
	register_method(handle, "init", m);
	m.method = &vn_method_set_prefixes;
	register_method(handle, "set_prefixes", m);
	m.method = &vn_method_search;
	register_method(handle, "search", m);
	m.method = &vn_method_addr_from_pub;
	register_method(handle, "addr_from_pub", m);
	m.method = &vn_method_pub_from_priv;
	register_method(handle, "pub_from_priv", m);
	m.method = &vn_method_engine_info;
	register_method(handle, "engine_info", m);
}
