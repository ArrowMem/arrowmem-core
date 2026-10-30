//! HF (shortwave) radio: sending and listening, built once, in full.
//! When he transmits is his call; the code does not hold it back.
//!
//! Sends carry public signed frames: `send` takes a `PublicFrame`, and a
//! sealed object cannot become one. When his callsign is set, it is put on
//! every send. Nothing on HF transmits on its own; the caller sends.

use crate::OBJECT_SIZE;

/// Largest public frame HF will carry. Far below a sealed object, so even a
/// mistake in a caller cannot push one through as "public".
pub const MAX_PUBLIC: usize = 512;
/// The v1 public signed frame (arrowmem-envelope): version, 8-byte key id,
/// 64-byte signature, then the readable words.
pub const PUBLIC_VERSION: u8 = 0x01;
const PUBLIC_HEADER: usize = 1 + 8 + 64;

#[derive(Debug, PartialEq, Eq)]
pub enum HfError {
    /// Not a v1 public frame, empty words, or too long for HF.
    NotPublic,
    /// A callsign that is not letters and digits with at least one digit.
    BadCallsign,
}

/// A frame that is readable by anyone, so it may go on air. The signature is
/// checked by the receiver against the sender's public key; here only the
/// shape is checked, so a sealed object can never be passed off as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicFrame(Vec<u8>);

impl PublicFrame {
    pub fn from_bytes(b: &[u8]) -> Result<PublicFrame, HfError> {
        let shape_ok = b.len() > PUBLIC_HEADER && b.len() <= MAX_PUBLIC && b[0] == PUBLIC_VERSION;
        // Belt and braces: the fixed sealed size is never public.
        if !shape_ok || b.len() == OBJECT_SIZE {
            return Err(HfError::NotPublic);
        }
        Ok(PublicFrame(b.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Default)]
pub struct HfStation {
    callsign: Option<String>,
}

impl HfStation {
    /// His callsign, once he has one. Letters and digits only, 3 to 8 long,
    /// at least one digit; stored in capitals.
    pub fn set_callsign(&mut self, call: &str) -> Result<(), HfError> {
        let c = call.trim().to_ascii_uppercase();
        let ok = (3..=8).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric()) && c.bytes().any(|b| b.is_ascii_digit());
        if !ok {
            return Err(HfError::BadCallsign);
        }
        self.callsign = Some(c);
        Ok(())
    }

    pub fn clear_callsign(&mut self) {
        self.callsign = None;
    }

    /// The bytes to put on air: the callsign line when one is set, then the frame.
    pub fn send(&self, frame: &PublicFrame) -> Vec<u8> {
        match &self.callsign {
            Some(c) => [format!("DE {c}\n").as_bytes(), frame.as_bytes()].concat(),
            None => frame.as_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(words: &[u8]) -> Vec<u8> {
        [&[PUBLIC_VERSION][..], &[7u8; 8], &[9u8; 64], words].concat()
    }

    #[test]
    fn sends_with_or_without_a_callsign() {
        let f = PublicFrame::from_bytes(&frame(b"shelter open")).unwrap();
        let mut st = HfStation::default();
        assert_eq!(st.send(&f), frame(b"shelter open"));
        st.set_callsign(" ve3xyz ").unwrap();
        let on_air = st.send(&f);
        assert!(on_air.starts_with(b"DE VE3XYZ\n"));
        assert!(on_air.ends_with(b"shelter open"));
        st.clear_callsign();
        assert_eq!(st.send(&f), frame(b"shelter open"));
    }

    #[test]
    fn sealed_objects_never_reach_hf() {
        use p256::elliptic_curve::Generate;
        let (_, pk) = crate::new_seal_keypair();
        let me = p256::ecdsa::SigningKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap();
        let sealed = crate::seal(&me, &pk, 1, b"private").unwrap();
        assert_eq!(PublicFrame::from_bytes(&sealed), Err(HfError::NotPublic));
        let mut fake = sealed.clone();
        fake[0] = PUBLIC_VERSION; // even dressed up as public, the size gives it away
        assert_eq!(PublicFrame::from_bytes(&fake), Err(HfError::NotPublic));
        assert_eq!(PublicFrame::from_bytes(&frame(b"")), Err(HfError::NotPublic)); // no words
        assert_eq!(PublicFrame::from_bytes(&frame(&[b'x'; MAX_PUBLIC])), Err(HfError::NotPublic));
        let mut v2 = frame(b"hi");
        v2[0] = 2;
        assert_eq!(PublicFrame::from_bytes(&v2), Err(HfError::NotPublic));
    }

    #[test]
    fn callsign_shape() {
        let mut g = HfStation::default();
        for bad in ["", "VE", "VEXYZ", "VE3 XYZ", "VE3-XY", "VE3XYZ123"] {
            assert_eq!(g.set_callsign(bad), Err(HfError::BadCallsign), "{bad}");
        }
        assert!(g.set_callsign("VA3ABC").is_ok());
    }
}
