//! Sealing: sign as the sender, pad, then encrypt to one recipient.

// Imports come from lib.rs: the crate's types, sizes and labels live there.
use crate::*;

/// Sign `body` as `sender`, then encrypt it to `recipient`.
/// `counter` must go up by at least one for every object this sender makes.
pub fn seal(
    sender: &dyn ExternalSigner,
    recipient: &SealPublicKey,
    counter: u64,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_to(sender, recipient, &key_id(recipient), counter, body)
}

// Same as seal, but the signed key id is passed in. Only tests pass a wrong one.
pub(crate) fn seal_to(
    sender: &dyn ExternalSigner,
    recipient: &SealPublicKey,
    to_id: &[u8; KEY_ID_LEN],
    counter: u64,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    if body.len() > MAX_BODY {
        return Err(Error::BodyTooLong);
    }
    let to = hint(recipient);

    // Build the inner plaintext: fields, body, then the signature over them.
    let mut inner = Vec::with_capacity(INNER_SIZE);
    let public = sender.public_key();
    inner.extend_from_slice(public.to_sec1_point(true).as_bytes()); // 33 bytes, compressed
    inner.extend_from_slice(to_id); // who it is for, all 32 bytes, under the signature
    inner.extend_from_slice(&counter.to_be_bytes());
    inner.extend_from_slice(&(body.len() as u16).to_be_bytes()); // fits: MAX_BODY < 65536
    inner.extend_from_slice(body);
    let mut to_sign = signed_bytes(&inner);
    // The signer (perhaps the phone's hardware) signs; we check before sealing.
    let signed = sender
        .sign_bytes(&to_sign)
        .and_then(|(bytes, format)| signer::checked_signature(&bytes, format, &to_sign, &public));
    to_sign.zeroize(); // this copy holds the body too
    let sig = match signed {
        Ok(sig) => sig,
        Err(e) => {
            inner.zeroize(); // nothing leaves, and nothing lingers
            return Err(e);
        }
    };
    inner.extend_from_slice(&sig.to_bytes());
    pad::pad_to_inner(&mut inner);

    // Version + hint go in the clear, but the cipher authenticates them (AAD).
    let mut object = Vec::with_capacity(OBJECT_SIZE);
    object.push(VERSION);
    object.extend_from_slice(&to);
    let sealed = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem>(
        &OpModeS::Base,
        recipient,
        HPKE_INFO,
        &inner,
        &object, // AAD = version + hint
    );
    inner.zeroize(); // wipe the plaintext copy before anything else can return
    let (enc, ct) = sealed.map_err(|_| Error::Decrypt)?;

    object.extend_from_slice(&enc.to_bytes());
    object.extend_from_slice(&ct);
    debug_assert_eq!(object.len(), OBJECT_SIZE);
    Ok(object)
}
