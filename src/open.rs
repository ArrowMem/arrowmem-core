//! Opening: THE TRUST BOUNDARY. Every check an untrusted object must pass.

// Imports come from lib.rs: the crate's types, sizes and labels live there.
use crate::*;

/// THE TRUST BOUNDARY. Bytes from anyone go in; a Verified comes out only if
/// every check passes. Replay and counter rules are the caller's; this function does not check them.
pub fn open(object: &[u8], my_sk: &SealPrivateKey, my_pk: &SealPublicKey) -> Result<Verified, Error> {
    // Cheap checks first, before any crypto work.
    if object.len() != OBJECT_SIZE {
        return Err(Error::WrongSize);
    }
    if object[0] != VERSION {
        return Err(Error::WrongVersion);
    }
    let me = hint(my_pk);
    if object[1..AAD_LEN] != me {
        return Err(Error::NotForMe);
    }
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&object[AAD_LEN..HEADER_LEN])
        .map_err(|_| Error::Decrypt)?;
    let mut inner = hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Base,
        my_sk,
        &enc,
        HPKE_INFO,
        &object[HEADER_LEN..],
        &object[..AAD_LEN], // same AAD as seal
    )
    .map_err(|_| Error::Decrypt)?; // a failed decrypt gives us no bytes at all
    let result = parse_inner(&inner, &key_id(my_pk));
    inner.zeroize(); // wipe the plaintext whether or not it passed
    result
}

// Checks the decrypted inner bytes. Split out so every exit wipes `inner` above.
fn parse_inner(inner: &[u8], me: &[u8; KEY_ID_LEN]) -> Result<Verified, Error> {
    if inner.len() != INNER_SIZE {
        return Err(Error::BadLayout);
    }
    let len = u16::from_be_bytes([inner[LEN_AT], inner[LEN_AT + 1]]) as usize;
    if len > MAX_BODY {
        return Err(Error::BadLayout);
    }
    let body_end = INNER_FIXED + len;
    let sig_end = body_end + SIG_LEN;
    // The signed key id must be ours: stops someone re-sealing another person's signed body to us.
    if inner[KEY_ID_AT..COUNTER_AT] != *me {
        return Err(Error::NotForMe);
    }
    if !pad::padding_is_zero(&inner[sig_end..]) {
        return Err(Error::BadPadding);
    }
    let sender = VerifyingKey::from_sec1_bytes(&inner[..SENDER_LEN]).map_err(|_| Error::BadSenderKey)?;
    let sig = Signature::from_slice(&inner[body_end..sig_end]).map_err(|_| Error::BadSignature)?;
    let mut to_check = signed_bytes(&inner[..body_end]);
    let checked = sender.verify(&to_check, &sig);
    to_check.zeroize(); // wipe the copy before we look at the answer
    checked.map_err(|_| Error::BadSignature)?;

    let mut counter = [0u8; 8];
    counter.copy_from_slice(&inner[COUNTER_AT..LEN_AT]);
    Ok(Verified {
        sender,
        counter: u64::from_be_bytes(counter),
        body: inner[INNER_FIXED..body_end].to_vec(),
    })
}
