//! arrowmem-core: sealed envelope, version 1.
//!
//! A sealed object is signed by the sender, then encrypted to one recipient.
//! Every object is exactly OBJECT_SIZE bytes, so a relay cannot tell a short
//! note from a long one. Byte layout: see LAYOUT.md.

use hpke::{
    Deserializable, Kem as _, OpModeR, OpModeS, Serializable, aead::AesGcm256, kdf::HkdfSha256,
    kem::DhP256HkdfSha256,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
// Tests across the crate build software signing keys.
#[cfg(test)]
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

// The HPKE suite: P-256 key agreement, HKDF-SHA256, AES-256-GCM (RFC 9180).
type Kem = DhP256HkdfSha256;
pub type SealPublicKey = <Kem as hpke::Kem>::PublicKey;
pub type SealPrivateKey = <Kem as hpke::Kem>::PrivateKey;

const VERSION: u8 = 0x01;
// Labels keep a signature or key from one use being replayed in another.
const HPKE_INFO: &[u8] = b"arrowmem-core v1 seal";
const SIGN_DOMAIN: &[u8] = b"arrowmem-core v1 sign";

// Outer header: version (1) + recipient hint (8) + HPKE encapped key (65).
const HINT_LEN: usize = 8;
const ENC_LEN: usize = 65;
const AAD_LEN: usize = 1 + HINT_LEN; // version + hint, authenticated by the cipher
const HEADER_LEN: usize = AAD_LEN + ENC_LEN;
// Inner plaintext is padded to one fixed size.
// NOTE: one size only; add larger buckets when photos or files ride.
pub const INNER_SIZE: usize = 1024;
const TAG_LEN: usize = 16; // AES-GCM authentication tag
pub const OBJECT_SIZE: usize = HEADER_LEN + INNER_SIZE + TAG_LEN;
// Inner fields before the body: sender key (33) + recipient key id (32) + counter (8) + body length (2).
const SENDER_LEN: usize = 33;
const KEY_ID_LEN: usize = 32; // full SHA-256 of the recipient's sealing key
const KEY_ID_AT: usize = SENDER_LEN;
const COUNTER_AT: usize = KEY_ID_AT + KEY_ID_LEN;
const LEN_AT: usize = COUNTER_AT + 8;
const INNER_FIXED: usize = LEN_AT + 2;
const SIG_LEN: usize = 64;
pub const MAX_BODY: usize = INNER_SIZE - INNER_FIXED - SIG_LEN;

/// Why an object was refused. Never a crash, always one of these.
/// The order is part of the C surface (ffi.rs maps it to codes): add new
/// variants at the end only.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BodyTooLong,
    WrongSize,
    WrongVersion,
    NotForMe,
    Decrypt,
    BadLayout,
    BadPadding,
    BadSenderKey,
    BadSignature,
    Replay,  // this counter was already accepted from this sender
    TooOld,  // 128 or more below the highest counter seen
    JumpTooFar, // counter leapt over 2^20 ahead: the app offers a re-pair
    BadRequestKey, // a request without a real sealing key inside its signed body
    BadRequestText, // request text breaks the rules in inbox.rs
    RequestPending, // this stranger already has a request waiting
    InboxFull,  // 32 requests waiting; earlier ones are kept
    Declined,   // this key was declined recently; stays quiet
    TooManyIntroduced, // per-introducer (4) or total introduced (16) cap reached
    IntroKeyMismatch, // the intro vouches for a different sealing key than the request carries
    BadIntro,
    Blocked,    // this key is blocked; refused before anything else
    BadKind,    // an empty body, or an unknown kind byte
    AlreadyContact, // a contact sent something other than a MESSAGE
    Stranger,   // a stranger sent a MESSAGE, or accept found no request
    UnknownInvite, // no open invite matches; nothing is created
    TooManyInvites, // 32 invites are already open
    ContactsFull, // 1024 contacts
    BlockListFull, // 4096 blocks; old blocks are never dropped
    TombstonesFull, // 1024 removals; prune by hand
    BadExport,  // a backup export that is malformed, over a cap, or not canonical
    StaleEpoch, // a backup no newer than the one already held
    NotPaired,  // a vault action that needs the paired channel (and, for reset, their confirmation)
    WrongBackupKey, // signed by a key other than the one registered for this slot
    CounterExhausted, // the send counter reached its maximum; this key can send no more
    RandomFailed, // the operating system could not give random bytes   // an intro that is malformed, for someone else, or carried by the wrong key
}

/// An object that passed every check. Only `open` can build one.
// No derived Debug: a log line must never print the body.
// Fields are private: code outside this crate can read them but never build one.
pub struct Verified {
    sender: VerifyingKey,
    counter: u64,
    body: Vec<u8>,
}

impl Verified {
    /// Who signed it.
    pub fn sender(&self) -> &VerifyingKey {
        &self.sender
    }
    /// The sender's counter for this object.
    pub fn counter(&self) -> u64 {
        self.counter
    }
    /// The message words.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

// Debug shows who and which counter, never the words.
impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verified")
            .field("sender", &self.sender)
            .field("counter", &self.counter)
            .field("body", &format_args!("<{} bytes hidden>", self.body.len()))
            .finish()
    }
}

// When a Verified is dropped, wipe the body from memory.
impl Drop for Verified {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}


/// Make a new sealing keypair from the OS random source.
pub fn new_seal_keypair() -> (SealPrivateKey, SealPublicKey) {
    Kem::gen_keypair()
}

// What the signature covers: a domain label, then the inner fields and body.
fn signed_bytes(fields_and_body: &[u8]) -> Vec<u8> {
    [SIGN_DOMAIN, fields_and_body].concat()
}

mod id;
mod open;
mod admit;
mod export;
mod wipe;
pub mod ffi;
pub mod frame;
pub mod hf;
mod inbox;
mod intro;
mod pad;
mod replay;
mod seal;
mod signer;

pub use id::{content_id, fingerprint, hint, key_id};
pub use open::open;
pub use admit::{Admission, Admitted, KIND_INTRO, KIND_INVITE, KIND_MESSAGE, KIND_REQUEST};
pub use export::{BUCKETS, MAX_EXPORT_LEN, RESTORE_MARGIN, restored_counter, MAX_EPOCH_STEP, MAX_FIRST_EPOCH, OverCap, next_epoch, BackupKeys, Contact, Header, Restored, State, Tier, VaultSlot, export, merge, open_export, parse_header, restored, verify_export};
pub use inbox::{Inbox, SenderKey, check_request_text};
pub use intro::{INTRO_LEN, Intro, make_intro, verify_intro};
pub use replay::ReplayWindow;
pub use seal::seal;
pub use signer::{ExternalSigner, SigFormat, checked_signature};
#[cfg(test)]
use seal::seal_to;

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> SigningKey {
        use p256::elliptic_curve::Generate;
        SigningKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap()
    }

    // Turns "4f64" into [0x4f, 0x64]. Test-only, so a panic on bad hex is fine.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // RFC 9180 Appendix A.3.1, sequence 0: proves the hpke crate's P-256 key
    // agreement and HKDF match the standard. The RFC's P-256 vector uses
    // AES-128-GCM; our AES-256 cipher is checked by the round-trip tests.
    #[test]
    fn rfc9180_a3_vector_opens() {
        use hpke::aead::AesGcm128;
        let (sk, pk) = Kem::derive_keypair(&hex("668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550"));
        assert_eq!(pk.to_bytes().to_vec(), hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"));
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")).unwrap();
        let pt = hpke::single_shot_open::<AesGcm128, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            &hex("4f6465206f6e2061204772656369616e2055726e"), // info
            &hex("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"), // ct
            &hex("436f756e742d30"), // aad
        )
        .unwrap();
        assert_eq!(pt, hex("4265617574792069732074727574682c20747275746820626561757479"));
    }

    #[test]
    fn debug_hides_the_body() {
        let (sk, pk) = new_seal_keypair();
        let v = open(&seal(&signer(), &pk, 1, b"secret words").unwrap(), &sk, &pk).unwrap();
        assert!(!format!("{v:?}").contains("secret"));
    }

    // An id that matches the hint (first 8 bytes) but not the
    // rest must still be refused, so the full 32 bytes are what is checked.
    #[test]
    fn key_id_matching_only_the_hint_is_refused() {
        let (sk, pk) = new_seal_keypair();
        let mut near = key_id(&pk);
        near[20] ^= 1; // past the 8 hint bytes
        let obj = seal_to(&signer(), &pk, &near, 1, b"x").unwrap();
        assert_eq!(open(&obj, &sk, &pk).unwrap_err(), Error::NotForMe);
    }

    // The official CFRG HPKE vector for OUR exact suite (mode 0,
    // kem_id 16 P-256, kdf_id 1 HKDF-SHA256, aead_id 2 AES-256-GCM).
    // Source: cfrg/draft-irtf-cfrg-hpke test-vectors.json.
    #[test]
    fn cfrg_vector_our_suite_aes256() {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Payload}};
        let info = hex("4f6465206f6e2061204772656369616e2055726e");
        let aad = hex("436f756e742d30");
        let ct = hex("58c61a45059d0c5704560e9d88b564a8b63f1364b8d1fcb3c4c6ddc1d291742465e902cd216f8908da49f8f96f");
        let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
        let (sk, pk) = Kem::derive_keypair(&hex("a0ce15d49e28bd47a18a97e147582d814b08cbe00109fed5ec27d1b4e9f6f5e3"));
        assert_eq!(pk.to_bytes().to_vec(), hex("04abc7e49a4c6b3566d77d0304addc6ed0e98512ffccf505e6a8e3eb25c685136f853148544876de76c0f2ef99cdc3a05ccf5ded7860c7c021238f9e2073d2356c"));
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex("04c06b4f6bebc7bb495cb797ab753f911aff80aefb86fd8b6fcc35525f3ab5f03e0b21bd31a86c6048af3cb2d98e0d3bf01da5cc4c39ff5370d331a4f1f7d5a4e0")).unwrap();
        // 1. The full HPKE open, with the cipher we actually use.
        let got = hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(&OpModeR::Base, &sk, &enc, &info, &ct, &aad).unwrap();
        assert_eq!(got, pt);
        // 2. The key schedule's outputs: the vector's key and base_nonce open the
        //    same ciphertext directly, so HPKE derived exactly that key and nonce
        //    (for sequence 0 the nonce is base_nonce itself).
        let cipher = Aes256Gcm::new_from_slice(&hex("ee16802a936d5f544771131900ee6973d0551de9e852ece2ef34bf0d5f9e1d1d")).unwrap();
        let nonce = hex("9bc50980832a7b4b58c40161");
        let direct = cipher.decrypt(nonce.as_slice().try_into().unwrap(), Payload { msg: &ct, aad: &aad }).unwrap();
        assert_eq!(direct, pt);
    }

    // A signer that returns a signature for the wrong message: sealing must
    // refuse, so a broken hardware signer can never send a bad object.
    struct WrongSigner(SigningKey);
    impl ExternalSigner for WrongSigner {
        fn public_key(&self) -> VerifyingKey {
            *self.0.verifying_key()
        }
        fn sign_bytes(&self, _msg: &[u8]) -> Result<(Vec<u8>, SigFormat), Error> {
            self.0.sign_bytes(b"not the message")
        }
    }

    #[test]
    fn a_bad_signer_cannot_seal() {
        let (_, pk) = new_seal_keypair();
        assert_eq!(seal(&WrongSigner(signer()), &pk, 1, b"x"), Err(Error::BadSignature));
    }

    #[test]
    fn round_trip() {
        let alice = signer();
        let (sk, pk) = new_seal_keypair();
        let obj = seal(&alice, &pk, 7, "bonjour, ça va?".as_bytes()).unwrap();
        assert_eq!(obj.len(), OBJECT_SIZE);
        let v = open(&obj, &sk, &pk).unwrap();
        assert_eq!(v.body(), "bonjour, ça va?".as_bytes());
        assert_eq!(v.counter(), 7);
        assert_eq!(*v.sender(), *alice.verifying_key());
    }

    #[test]
    fn same_words_look_different_each_time() {
        let alice = signer();
        let (_, pk) = new_seal_keypair();
        assert_ne!(seal(&alice, &pk, 1, b"hi").unwrap(), seal(&alice, &pk, 1, b"hi").unwrap());
    }

    #[test]
    fn short_and_long_are_the_same_size() {
        assert_eq!(MAX_BODY, 885); // matches LAYOUT.md
        let (sk, pk) = new_seal_keypair();
        let short = seal(&signer(), &pk, 1, b"").unwrap();
        let long = seal(&signer(), &pk, 1, &[b'x'; MAX_BODY]).unwrap();
        assert_eq!(short.len(), long.len());
        assert_eq!(open(&long, &sk, &pk).unwrap().body().len(), MAX_BODY);
        assert_eq!(seal(&signer(), &pk, 1, &[0; MAX_BODY + 1]).unwrap_err(), Error::BodyTooLong);
    }

    #[test]
    fn every_flipped_bit_is_refused() {
        let (sk, pk) = new_seal_keypair();
        let obj = seal(&signer(), &pk, 1, b"x").unwrap();
        for i in 0..obj.len() {
            let mut bad = obj.clone();
            bad[i] ^= 1;
            assert!(open(&bad, &sk, &pk).is_err(), "byte {i} accepted");
        }
    }

    #[test]
    fn wrong_recipient_and_wrong_size() {
        let (_, pk) = new_seal_keypair();
        let (sk2, pk2) = new_seal_keypair();
        let obj = seal(&signer(), &pk, 1, b"x").unwrap();
        assert_eq!(open(&obj, &sk2, &pk2).unwrap_err(), Error::NotForMe);
        assert_eq!(open(&obj[1..], &sk2, &pk2).unwrap_err(), Error::WrongSize);
    }
}
