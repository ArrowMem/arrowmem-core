//! Introductions: a contact vouches for a newcomer.
//! An intro NEVER admits anyone. A valid one only puts the newcomer at the
//! top of the request inbox, and the person taps to accept.

use crate::*;
use hpke::Deserializable;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::{Signer, Verifier}};

const INTRO_DOMAIN: &[u8] = b"arrowmem-core v1 intro";
pub const INTRO_LEN: usize = 33 + 65 + 8 + 64; // introducer key, newcomer seal key, counter, signature

/// What a valid intro says, once its signature has checked out.
#[derive(Debug, PartialEq, Eq)]
pub struct Intro {
    pub by: inbox::SenderKey,      // the contact who vouched
    pub newcomer_seal: [u8; 65],   // so the person can reply once they accept
    pub counter: u64,              // the introducer's intro counter, for its replay window
}

// What the introducer signs: who it is for, who the newcomer is, and a counter.
fn intro_signed_bytes(target_id: &[u8; 32], newcomer_sign: &[u8; 33], newcomer_seal: &[u8; 65], counter: u64) -> Vec<u8> {
    [INTRO_DOMAIN, target_id, newcomer_sign, newcomer_seal, &counter.to_be_bytes()].concat()
}

/// The introducer C makes an intro of newcomer N for target A.
pub fn make_intro(
    by: &SigningKey,
    target: &SealPublicKey,
    newcomer_sign: &VerifyingKey,
    newcomer_seal: &SealPublicKey,
    counter: u64,
) -> [u8; INTRO_LEN] {
    let n_sign: [u8; 33] = newcomer_sign.to_sec1_point(true).as_bytes().try_into().unwrap(); // always 33 when compressed
    let n_seal: [u8; 65] = newcomer_seal.to_bytes().as_slice().try_into().unwrap(); // always 65, uncompressed
    let sig: Signature = by.sign(&intro_signed_bytes(&key_id(target), &n_sign, &n_seal, counter));
    let mut out = [0u8; INTRO_LEN];
    out[..33].copy_from_slice(by.verifying_key().to_sec1_point(true).as_bytes());
    out[33..98].copy_from_slice(&n_seal);
    out[98..106].copy_from_slice(&counter.to_be_bytes());
    out[106..].copy_from_slice(&sig.to_bytes());
    out
}

/// Check an intro carried by `sender` (the newcomer, already proven by `open`).
/// Proves only the signature binding. The caller must still check that `by`
/// is a current, unblocked contact and run `counter` through `by`'s intro window.
pub fn verify_intro(intro: &[u8], my_pk: &SealPublicKey, sender: &VerifyingKey) -> Result<Intro, Error> {
    if intro.len() != INTRO_LEN {
        return Err(Error::BadIntro);
    }
    let by_key = VerifyingKey::from_sec1_bytes(&intro[..33]).map_err(|_| Error::BadIntro)?;
    let mut n_seal = [0u8; 65];
    n_seal.copy_from_slice(&intro[33..98]);
    // Must be a real P-256 point, so no garbage key is ever stored.
    SealPublicKey::from_bytes(&n_seal).map_err(|_| Error::BadIntro)?;
    let mut c = [0u8; 8];
    c.copy_from_slice(&intro[98..106]);
    let counter = u64::from_be_bytes(c);
    let sig = Signature::from_slice(&intro[106..]).map_err(|_| Error::BadIntro)?;
    // The newcomer's signing key is NOT carried: we use the key that signed the
    // object, so only the newcomer named by C can use C's intro.
    let n_sign: [u8; 33] = sender.to_sec1_point(true).as_bytes().try_into().map_err(|_| Error::BadIntro)?;
    // The target is always us: an intro made for someone else fails here.
    by_key
        .verify(&intro_signed_bytes(&key_id(my_pk), &n_sign, &n_seal, counter), &sig)
        .map_err(|_| Error::BadIntro)?;
    let mut by = [0u8; 33];
    by.copy_from_slice(&intro[..33]);
    Ok(Intro { by, newcomer_seal: n_seal, counter })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> SigningKey {
        use p256::elliptic_curve::Generate;
        SigningKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap()
    }

    struct World {
        c: SigningKey,
        n: SigningKey,
        n_seal: SealPublicKey,
        a_pk: SealPublicKey,
    }

    fn world() -> World {
        World { c: signer(), n: signer(), n_seal: new_seal_keypair().1, a_pk: new_seal_keypair().1 }
    }

    #[test]
    fn valid_intro_names_the_introducer() {
        let w = world();
        let intro = make_intro(&w.c, &w.a_pk, w.n.verifying_key(), &w.n_seal, 5);
        let got = verify_intro(&intro, &w.a_pk, w.n.verifying_key()).unwrap();
        assert_eq!(&got.by[..], w.c.verifying_key().to_sec1_point(true).as_bytes());
        assert_eq!(got.counter, 5);
        assert_eq!(&got.newcomer_seal[..], w.n_seal.to_bytes().as_slice());
    }

    #[test]
    fn intro_for_someone_else_fails() {
        let w = world();
        let other = new_seal_keypair().1;
        let intro = make_intro(&w.c, &other, w.n.verifying_key(), &w.n_seal, 5);
        assert_eq!(verify_intro(&intro, &w.a_pk, w.n.verifying_key()), Err(Error::BadIntro));
    }

    #[test]
    fn a_third_key_cannot_use_the_intro() {
        let w = world();
        let intro = make_intro(&w.c, &w.a_pk, w.n.verifying_key(), &w.n_seal, 5);
        let thief = signer();
        assert_eq!(verify_intro(&intro, &w.a_pk, thief.verifying_key()), Err(Error::BadIntro));
    }

    #[test]
    fn garbage_newcomer_key_refused_even_if_signed() {
        let w = world();
        // C signs over a sealing key that is not a curve point.
        let mut bogus = [0u8; 65];
        bogus[0] = 4;
        let n_sign: [u8; 33] = w.n.verifying_key().to_sec1_point(true).as_bytes().try_into().unwrap();
        let sig: Signature = w.c.sign(&intro_signed_bytes(&key_id(&w.a_pk), &n_sign, &bogus, 1));
        let mut intro = [0u8; INTRO_LEN];
        intro[..33].copy_from_slice(w.c.verifying_key().to_sec1_point(true).as_bytes());
        intro[33..98].copy_from_slice(&bogus);
        intro[98..106].copy_from_slice(&1u64.to_be_bytes());
        intro[106..].copy_from_slice(&sig.to_bytes());
        assert_eq!(verify_intro(&intro, &w.a_pk, w.n.verifying_key()), Err(Error::BadIntro));
    }

    #[test]
    fn every_flipped_bit_fails() {
        let w = world();
        let intro = make_intro(&w.c, &w.a_pk, w.n.verifying_key(), &w.n_seal, 5);
        for i in 0..INTRO_LEN {
            let mut bad = intro;
            bad[i] ^= 1;
            assert!(verify_intro(&bad, &w.a_pk, w.n.verifying_key()).is_err(), "byte {i} accepted");
        }
        assert_eq!(verify_intro(&intro[1..], &w.a_pk, w.n.verifying_key()), Err(Error::BadIntro));
    }
}
