//! Names: who an object is for, and what an object is.

// Imports come from lib.rs: the crate's types, sizes and labels live there.
use crate::*;

/// Full SHA-256 of the recipient's sealing key. Signed inside, so a signature
/// names exactly one recipient.
pub fn key_id(pk: &SealPublicKey) -> [u8; KEY_ID_LEN] {
    Sha256::digest(pk.to_bytes()).into()
}

/// First 8 bytes of the key id: the short public label a relay sees.
// NOTE: a fixed hint links objects to one recipient; rotating hints come with relay IDs.
pub fn hint(pk: &SealPublicKey) -> [u8; HINT_LEN] {
    let mut out = [0u8; HINT_LEN];
    out.copy_from_slice(&key_id(pk)[..HINT_LEN]);
    out
}

/// Content id of a sealed object: SHA-256 of all its bytes.
pub fn content_id(object: &[u8]) -> [u8; 32] {
    Sha256::digest(object).into()
}

/// What two people compare on screen when pairing in person: 80 bits over
/// both of a person's public keys (signing key, then sealing key). The app
/// shows it as words. 80 bits, not the 64-bit hint, so a lookalike key is
/// out of reach.
pub fn fingerprint(sign_key: &[u8; 33], seal_key: &[u8; 65]) -> [u8; 10] {
    let d: [u8; 32] = Sha256::new()
        .chain_update(b"arrowmem-core v1 fingerprint")
        .chain_update(sign_key)
        .chain_update(seal_key)
        .finalize()
        .into();
    d[..10].try_into().unwrap() // the first 10 bytes of 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_covers_both_keys() {
        let (a, b) = ([1u8; 33], [2u8; 65]);
        let f = fingerprint(&a, &b);
        let mut a2 = a;
        a2[32] ^= 1;
        let mut b2 = b;
        b2[64] ^= 1;
        assert_ne!(fingerprint(&a2, &b), f);
        assert_ne!(fingerprint(&a, &b2), f);
        assert_eq!(fingerprint(&a, &b), f); // the same keys, the same words
    }
}
