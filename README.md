# arrowmem-core

Sealed messages, all one fixed size.

arrowmem-core is a small Rust library. It takes a message, signs it, seals it to one recipient, and pads it to a fixed size. Whoever relays the result sees a block of bytes of one length, so a short note and a long one look alike by size. They cannot read it. If they change it, the recipient detects that and refuses it.

It is the sealing and admission layer behind ArrowBridge, which lets a phone reach a vault that stays on the owner's own hardware. The library does not choose a network or talk to a server: how objects travel is up to the caller.

Licence: Apache-2.0. Version 0.1.0, early. We make no claim of an independent audit.

## What it does

- **Sealing.** HPKE (RFC 9180), base mode, with P-256 key agreement, HKDF-SHA256 and AES-256-GCM. One sender, one recipient, one object.
- **Signing.** Each object is signed with ECDSA P-256 before it is sealed, so the recipient knows who sent it. The library takes signatures through a signer interface, so a key held in phone hardware can be used without the private key entering the library. That hardware binding is not shipped yet: today the signing and sealing keys are software keys.
- **Fixed size.** Every sealed object is exactly 1114 bytes, with room for a body of up to 885 bytes. The padding must be all zero, and anything else is refused.
- **Replay protection.** Each sender has a counter. The admission layer, not the opening step, refuses an object it has already accepted, one 128 or more counters behind the newest, and one that jumps more than 2^20 ahead. Opening an object on its own does not check replay.
- **Admission.** Strangers do not reach the person. A first contact becomes a request that waits until the person accepts or declines it. A contact can vouch for a newcomer with an introduction, and an introduction only puts the newcomer at the top of the requests. It never admits anyone.
- **Pairing.** Invites and introductions are how two devices and two people first find each other.
- **Backup export.** The admission state can be exported to the vault, sealed so the vault can check it without being able to read it.
- **Key wiping.** Secrets and spare memory are overwritten when the library is done with them. This is best effort: it cannot reach copies the operating system, the compiler or other code may have made.
- **Radio fragments.** An object can be cut into small pieces for links such as Bluetooth Low Energy and put back together on the other side.
- **C interface.** `include/arrowmem.h` is the C header for the phone app. The library builds as a Rust library, a shared library and a static library. Every call returns zero or a negative error code, and a test fails if the header drifts from the code.

The exact byte layout, the order of the checks and the known ceilings are written down in [LAYOUT.md](LAYOUT.md). Read the "Known ceilings" section before you rely on this for anything.

## Build and test

You need a recent stable Rust toolchain (the 2024 edition).

```
cargo build
cargo test
```

Fuzzing lives in its own crate so its tools never ship with the library. It needs the nightly toolchain and cargo-fuzz:

```
cargo install cargo-fuzz
cargo +nightly fuzz run open_raw
cargo +nightly fuzz run open_flipped
```

`open_raw` throws arbitrary bytes at the opening step, and `open_flipped` flips bits in valid objects. Both must only ever return an error, never crash and never accept.

## Try it

Two terminals, one sealed object over plain TCP on your own machine:

```
cargo run --example lan -- recv 127.0.0.1:7411
cargo run --example lan -- send 127.0.0.1:7411 <the key it printed> "hello"
```

Use a LAN address only on a network you trust. The object is sealed, but the port is open while it waits.

## Check a backup export

`arrowmem-verify-export` checks one backup export without decrypting it. It is for the vault, which stores backups it cannot read.

```
cargo run --bin arrowmem-verify-export -- <registered backup key, 66 hex characters> < export.bin
```

It prints one line and exits 0 or 1: `OK epoch=... stamp=... bucket=... vault=...`, or `ERR <reason>`.

## What this is not

- It does not hide that two parties are talking. The recipient hint in each object is fixed per recipient, so a relay can link objects sent to one person. LAYOUT.md says so and says what replaces it.
- It does not decide where objects travel. Transport is up to the caller.
- It has no forward secrecy: if a recipient's sealing key is ever exposed, objects sealed to it earlier can be opened.
- It is not post-quantum. P-256 and ECDSA are broken by a large enough quantum computer.
- Its ECDSA signatures are malleable (high and low S forms). Dedupe uses the content id over the ciphertext, so it is unaffected; LAYOUT.md records the open question.
- It is not a messaging app. It is the part that decides what may be opened and who may reach the person.

## Reporting a problem

Send security reports to security@arrowmem.ca. Please do not open a public issue for a vulnerability.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
