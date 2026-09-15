# vendored from cathugger/mkp224o

Minimal, unmodified subset of [mkp224o](https://github.com/cathugger/mkp224o),
vendored at commit `5172c0fd71740ca0b11da8149a2575dcf331d7ab` (2024-02-15),
license **CC0 1.0 Universal** (public domain dedication, see `COPYING.txt`).

Exact file list and what was left out: `UPSTREAM.txt`.

Why these files:

- `ed25519/ed25519-donna/*` — the only backend that provides
  `ge25519_batchpack_destructive_1/_finish` (the batch point-to-bytes
  conversion that makes this search fast). `ref10`, `amd64-51-30k` and
  `amd64-64-24k` cannot do batched inversion.
- `keccak.c/.h` — SHA3-256 for the `.onion` checksum.
- `base32_to.c/.h`, `base32_from` (in `base32_from.c` upstream, not vendored
  here — the prefix→bitmask conversion is done by `wg_onion_bridge.c`) —
  RFC 4648 base32 for the 56-character onion address.
- `types.h`, `likely.h` — the tiny typedef/`likely()` helpers the above need.

Nothing here is modified. All the new code (batch loop, filters, RNG, SHA-512,
C ABI) lives one level up in `../wg_onion_bridge.c` and `../wg_onion_crypto.c`.
