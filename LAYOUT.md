# Sealed object, version 1: byte layout

Every object is exactly 1114 bytes. All integers are big-endian.

## Outer (what a relay sees)

| offset | length | field |
|---|---|---|
| 0 | 1 | version, `0x01` |
| 1 | 8 | recipient hint: the first 8 bytes of the recipient key id (the key id is SHA-256 over the recipient's sealing public key, 65-byte SEC1 uncompressed) |
| 9 | 65 | HPKE encapsulated key (P-256, uncompressed) |
| 74 | 1040 | AES-256-GCM ciphertext of the 1024-byte inner block, plus a 16-byte tag |

- **HPKE (RFC 9180):** base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. The info string is `arrowmem-core v1 seal`.
- **AAD:** bytes 0 to 8 (version and hint), so a relay cannot change them.

## Inner (after decryption, 1024 bytes)

| offset | length | field |
|---|---|---|
| 0 | 33 | sender's signing public key (P-256, SEC1 compressed) |
| 33 | 32 | recipient key id, all 32 bytes, signed (must equal the opener's own key id) |
| 65 | 8 | counter: the sender's own monotonic counter, not a clock (invariant 5) |
| 73 | 2 | body length L, at most 885 |
| 75 | L | body |
| 75+L | 64 | ECDSA P-256 / SHA-256 signature, r then s, over `arrowmem-core v1 sign` followed by inner bytes 0 to 75+L |
| 139+L | rest | zero padding; any non-zero byte is refused |

## Content id
The content id is SHA-256 over all 1114 bytes (invariant 1).

## Refusals, in the order `open` checks them
1. Wrong size, then wrong version, then a hint that is not mine.
2. A bad encapsulated key, or a failed decrypt. A failed decrypt yields no bytes at all.
3. Wrong inner size, or a body length over 885.
4. A signed key id that is not mine.
5. Non-zero padding.
6. A bad sender key, then a bad signature.

Replay and counter acceptance is the caller's job (step 2).

## Known ceilings, recorded on purpose
- **One fixed size:** a body is at most 885 bytes. Larger buckets come when files ride.
- **The hint is fixed per recipient,** so objects to one person are linkable by a relay. It is replaced when rotating relay IDs land.
- **Software signing key in step 1.** The hardware key (Secure Enclave or StrongBox) comes in step 3.
- **Open question for the phone binding:** the hpke crate's decrypt needs the raw private sealing key. A hardware-held ECDH key needs either a split (hardware ECDH, then software KDF and AEAD) or a software sealing key under hardware wrapping.
- **ECDSA signatures are malleable (high and low S).** The content id is taken over the ciphertext, so dedupe is unaffected. Whether low-S should be enforced is open.
- **crypto-bigint is held at 0.7.9 in Cargo.lock.** 0.7.10 carried a one-day-old constant-time change; 0.7.6 to 0.7.8 are yanked. A plain `cargo update` would lift it, so re-pin with `cargo update -p crypto-bigint --precise 0.7.9` until a newer one is reviewed. `cargo audit` 0.22.2: 0 advisories across 65 crates on 2026-10-26. Residual: 0.7.9 is itself dated 2026-10-25 and no older patched release exists, so it soaks with time, not by pinning. Rerun `cargo audit` before any publish and after the first dependency update.
