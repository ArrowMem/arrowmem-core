//! Signing through something that holds the key, such as the phone's secure
//! hardware. The key never comes to this crate; only the signature does.
//!

use crate::Error;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::{Signer, Verifier}};

/// How the signer returned its signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigFormat {
    /// 64 bytes: r then s.
    Raw,
    /// ASN.1 DER, as Android Keystore and the Secure Enclave return it.
    Der,
}

/// Anything that can sign with a P-256 key it keeps to itself.
pub trait ExternalSigner {
    /// The public half of the key it signs with.
    fn public_key(&self) -> VerifyingKey;
    /// ECDSA P-256 / SHA-256 over `msg`. Bytes in whichever format it has.
    fn sign_bytes(&self, msg: &[u8]) -> Result<(Vec<u8>, SigFormat), Error>;
}

/// A software key behind the same interface: used in tests, and until a
/// device has hardware signing.
impl ExternalSigner for SigningKey {
    fn public_key(&self) -> VerifyingKey {
        *self.verifying_key()
    }
    fn sign_bytes(&self, msg: &[u8]) -> Result<(Vec<u8>, SigFormat), Error> {
        let sig: Signature = self.sign(msg);
        Ok((sig.to_bytes().to_vec(), SigFormat::Raw))
    }
}

/// Turn what a signer returned into a signature we trust. The DER parse is
/// strict (it refuses padded or short integers that a hand-written converter
/// would mangle now and then). Then the signature must verify against the
/// signer's own public key, BEFORE anything is sealed. Then it is put in
/// low-S form, since hardware does not promise one.
pub fn checked_signature(bytes: &[u8], format: SigFormat, msg: &[u8], public: &VerifyingKey) -> Result<Signature, Error> {
    let sig = match format {
        SigFormat::Raw => Signature::from_slice(bytes),
        SigFormat::Der => Signature::from_der(bytes),
    }
    .map_err(|_| Error::BadSignature)?;
    public.verify(msg, &sig).map_err(|_| Error::BadSignature)?;
    Ok(sig.normalize_s())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        use p256::elliptic_curve::Generate;
        SigningKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap()
    }

    // A signer that hands back DER, like the phone hardware does.
    struct DerSigner(SigningKey);
    impl ExternalSigner for DerSigner {
        fn public_key(&self) -> VerifyingKey {
            *self.0.verifying_key()
        }
        fn sign_bytes(&self, msg: &[u8]) -> Result<(Vec<u8>, SigFormat), Error> {
            let sig: Signature = self.0.sign(msg);
            Ok((sig.to_der().as_bytes().to_vec(), SigFormat::Der))
        }
    }

    #[test]
    fn thousands_of_der_signatures_all_convert() {
        // Many signatures include short (leading zero) or padded (33-byte)
        // integers in DER. Every one must convert and verify.
        let s = DerSigner(key());
        let pk = s.public_key();
        let mut short_or_padded = 0;
        for i in 0u32..3000 {
            let msg = i.to_be_bytes();
            let (der, fmt) = s.sign_bytes(&msg).unwrap();
            if der.len() != 70 {
                short_or_padded += 1; // 2 + (2+32) + (2+32) is the plain length
            }
            let sig = checked_signature(&der, fmt, &msg, &pk).unwrap();
            assert_eq!(sig.normalize_s(), sig); // always low-S
        }
        assert!(short_or_padded > 0, "the sample should include odd lengths");
    }

    #[test]
    fn garbage_wrong_key_and_wrong_message_refused() {
        let k = key();
        let pk = *k.verifying_key();
        let (raw, _) = k.sign_bytes(b"m").unwrap();
        assert_eq!(checked_signature(&[0u8; 64], SigFormat::Raw, b"m", &pk), Err(Error::BadSignature));
        assert_eq!(checked_signature(&[0x30, 0x02, 0x01], SigFormat::Der, b"m", &pk), Err(Error::BadSignature));
        assert_eq!(checked_signature(&raw, SigFormat::Raw, b"other", &pk), Err(Error::BadSignature));
        assert_eq!(checked_signature(&raw, SigFormat::Raw, b"m", key().verifying_key()), Err(Error::BadSignature));
        // Raw bytes passed as DER are refused, not misread.
        assert_eq!(checked_signature(&raw, SigFormat::Der, b"m", &pk), Err(Error::BadSignature));
    }

    #[test]
    fn high_s_is_normalized() {
        let k = key();
        let sig: Signature = k.sign(b"m");
        let high = Signature::from_scalars(sig.r(), -sig.s()).unwrap();
        let got = checked_signature(&high.to_bytes(), SigFormat::Raw, b"m", k.verifying_key()).unwrap();
        assert_eq!(got, high.normalize_s());
        assert_eq!(got.normalize_s(), got);
    }

    #[test]
    fn non_minimal_der_is_refused() {
        // Add a needless leading zero to r: valid as a number, not minimal DER.
        let k = key();
        let sig: Signature = k.sign(b"m");
        let der = sig.to_der();
        let d = der.as_bytes();
        let rlen = d[3] as usize;
        let mut bad = vec![0x30, d[1] + 1, 0x02, (rlen + 1) as u8, 0x00];
        bad.extend_from_slice(&d[4..4 + rlen]);
        bad.extend_from_slice(&d[4 + rlen..]);
        if d[4] & 0x80 == 0 {
            // Only non-minimal when r did not already need the zero.
            assert_eq!(checked_signature(&bad, SigFormat::Der, b"m", k.verifying_key()), Err(Error::BadSignature));
        }
    }
}
