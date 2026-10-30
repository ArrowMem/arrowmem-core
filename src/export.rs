//! Admission state backup to the vault.
//!
//! Seal, then sign the ciphertext: the state is sealed to a key only the
//! recovery phrase can rebuild, and the signature covers header, enc and
//! ciphertext, so the vault checks it WITHOUT being able to read the state.

use crate::*;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable, aead::AesGcm256, kdf::HkdfSha256};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::{Signer, Verifier}};

const LABEL: &[u8] = b"arrowmem-core v1 export";
const SEAL_LABEL: &[u8] = b"arrowmem-core v1 export seal";
const SIGN_LABEL: &[u8] = b"arrowmem-core v1 export sign";
const FORMAT: u8 = 1;

// Header: label (23) + format (1) + vault id (32) + epoch (8) + stamp (8) + bucket (4).
pub const HEADER_LEN: usize = 23 + 1 + 32 + 8 + 8 + 4;
const ENC_LEN: usize = 65;
const TAG_LEN: usize = 16;
const SIG_LEN: usize = 64;
/// Plaintext sizes. The smallest that fits is used.
pub const BUCKETS: [usize; 4] = [16 << 10, 64 << 10, 256 << 10, 512 << 10];
/// The largest export on the wire. Anything longer is refused unread.
pub const MAX_EXPORT_LEN: usize = HEADER_LEN + ENC_LEN + (512 << 10) + TAG_LEN + SIG_LEN;

// List caps. Over a cap is BadExport, never truncation.
pub const MAX_CONTACTS: usize = 1024;
pub const MAX_BLOCKS: usize = 4096;
pub const MAX_TOMBSTONES: usize = 1024;
pub const MAX_DECLINED: usize = 128;
pub const MAX_INTRO_WINDOWS: usize = 1024;

// One contact on the wire: sign key, seal key, window, tier, flag, introduced_by.
const CONTACT_LEN: usize = 33 + 65 + 24 + 1 + 1 + 33;
const INTRO_WINDOW_LEN: usize = 33 + 24;
// Five u16 counts, then the lists at their caps.
const MAX_STATE_LEN: usize = 10
    + 8 // own counter, at the end
    + MAX_CONTACTS * CONTACT_LEN
    + (MAX_BLOCKS + MAX_DECLINED) * 33
    + MAX_TOMBSTONES * (33 + 8)
    + MAX_INTRO_WINDOWS * INTRO_WINDOW_LEN;
// A full state must fit the largest bucket, checked when the crate is built.
// This is why "backup incomplete" cannot happen today: if the caps ever grow
// past the buckets, the build fails instead.
const _: () = assert!(4 + MAX_STATE_LEN <= 512 << 10);

pub type Key33 = [u8; 33];

/// How much the person has confirmed a contact. Higher is stricter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Confirmed = 0,
    Unconfirmed = 1,
}

// No derived Debug: a log line must never print who someone knows.
#[derive(Clone, PartialEq, Eq)]
pub struct Contact {
    pub sign: Key33,
    pub seal: [u8; 65],
    pub window: ReplayWindow,
    pub tier: Tier,
    pub introduced_by: Option<Key33>,
}

/// Everything admission remembers. Invites are deliberately absent: they are
/// never exported and are all void after a restore.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct State {
    pub contacts: Vec<Contact>,
    pub blocks: Vec<Key33>,
    // (removed key, the highest counter ever seen from it). The counter is why
    // a replayed old REQUEST cannot re-admit them below it.
    pub tombstones: Vec<(Key33, u64)>,
    pub declined: Vec<Key33>,
    pub intro_windows: Vec<(Key33, ReplayWindow)>,
    /// This phone's own send counter at export time, so a restored phone can
    /// start above everything it ever sent.
    pub own_counter: u64,
}

impl std::fmt::Debug for Contact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Contact {{ <hidden>, tier: {:?} }}", self.tier)
    }
}

// Counts only, never keys.
impl State {
    /// Overwrite every list, spare capacity included (see wipe.rs).
    pub(crate) fn wipe_in_place(&mut self) {
        crate::wipe::wipe_vec(&mut self.contacts);
        crate::wipe::wipe_vec(&mut self.blocks);
        crate::wipe::wipe_vec(&mut self.tombstones);
        crate::wipe::wipe_vec(&mut self.declined);
        crate::wipe::wipe_vec(&mut self.intro_windows);
        self.own_counter = 0;
    }
}

/// Holds a State while it is being built; if building fails part way, the
/// half-built State is wiped instead of left in freed memory.
pub(crate) struct Building(pub(crate) State);
impl Building {
    pub(crate) fn done(mut self) -> State {
        std::mem::take(&mut self.0) // leaves an empty State for Drop to wipe
    }
}
impl Drop for Building {
    fn drop(&mut self) {
        self.0.wipe_in_place();
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "State {{ contacts: {}, blocks: {}, tombstones: {}, declined: {}, intro_windows: {} }}",
            self.contacts.len(),
            self.blocks.len(),
            self.tombstones.len(),
            self.declined.len(),
            self.intro_windows.len()
        )
    }
}

/// Which lists a merge left over their export cap. The phone must
/// not store such a state without telling the person to prune by hand.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OverCap {
    pub contacts: bool,
    pub blocks: bool,
    pub tombstones: bool,
    pub intro_windows: bool,
}

impl OverCap {
    pub fn any(&self) -> bool {
        self.contacts || self.blocks || self.tombstones || self.intro_windows
    }
}

/// The public part of an export, readable by the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub vault_id: [u8; 32],
    pub epoch: u64,
    pub stamp: u64,
    pub bucket: usize,
}

/// The two backup keys, rebuilt from the recovery phrase's root.
pub struct BackupKeys {
    pub seal_sk: SealPrivateKey,
    pub seal_pk: SealPublicKey,
    pub sign: SigningKey,
}

// HKDF from the root with a label, then RFC 9180 DeriveKeyPair (section 7.1.3:
// rejection sampling, never a bare reduction mod n).
fn derive(root: &[u8], label: &[u8]) -> (SealPrivateKey, SealPublicKey) {
    let mut ikm = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, root).expand(label, &mut ikm).expect("32 bytes is a valid length");
    let pair = <DhP256HkdfSha256 as hpke::Kem>::derive_keypair(&ikm);
    zeroize::Zeroize::zeroize(&mut ikm);
    pair
}

impl BackupKeys {
    pub fn from_root(root: &[u8]) -> Self {
        let (seal_sk, seal_pk) = derive(root, SEAL_LABEL);
        let (sign_sk, _) = derive(root, SIGN_LABEL);
        let mut b = sign_sk.to_bytes();
        // A P-256 scalar from DeriveKeyPair is always valid for ECDSA.
        let sign = SigningKey::from_slice(&b).expect("valid P-256 scalar");
        zeroize::Zeroize::zeroize(&mut b[..]);
        BackupKeys { seal_sk, seal_pk, sign }
    }

    pub fn sign_public(&self) -> Key33 {
        self.sign.verifying_key().to_sec1_point(true).as_bytes().try_into().unwrap() // 33 compressed
    }
}

fn header_bytes(h: &Header) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..23].copy_from_slice(LABEL);
    out[23] = FORMAT;
    out[24..56].copy_from_slice(&h.vault_id);
    out[56..64].copy_from_slice(&h.epoch.to_be_bytes());
    out[64..72].copy_from_slice(&h.stamp.to_be_bytes());
    out[72..76].copy_from_slice(&(h.bucket as u32).to_be_bytes());
    out
}

/// Read the header without trusting it. The vault then calls verify_export.
pub fn parse_header(bytes: &[u8]) -> Result<Header, Error> {
    if bytes.len() < HEADER_LEN || bytes.len() > MAX_EXPORT_LEN {
        return Err(Error::BadExport);
    }
    if &bytes[..23] != LABEL || bytes[23] != FORMAT {
        return Err(Error::BadExport);
    }
    let u64_at = |i: usize| u64::from_be_bytes(bytes[i..i + 8].try_into().unwrap());
    let bucket = u32::from_be_bytes(bytes[72..76].try_into().unwrap()) as usize;
    if !BUCKETS.contains(&bucket) {
        return Err(Error::BadExport);
    }
    // The total length is fixed by the bucket.
    if bytes.len() != HEADER_LEN + ENC_LEN + bucket + TAG_LEN + SIG_LEN {
        return Err(Error::BadExport);
    }
    Ok(Header { vault_id: bytes[24..56].try_into().unwrap(), epoch: u64_at(56), stamp: u64_at(64), bucket })
}

/// THE VAULT'S CHECK. Needs only the registered backup public key, never the
/// sealing key: the vault stays blind to the state.
pub fn verify_export(bytes: &[u8], registered: &Key33) -> Result<Header, Error> {
    let h = parse_header(bytes)?;
    let key = VerifyingKey::from_sec1_bytes(registered).map_err(|_| Error::BadExport)?;
    let (signed, sig) = bytes.split_at(bytes.len() - SIG_LEN);
    let sig = Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
    // Only the low-S form is valid, so nobody can make a second valid
    // signature for the same export and race it in.
    if sig.normalize_s() != sig {
        return Err(Error::BadSignature);
    }
    key.verify(signed, &sig).map_err(|_| Error::BadSignature)?;
    Ok(h)
}

/// Seal `state` for the vault. Refuses a state over any cap.
pub fn export(state: &State, keys: &BackupKeys, vault_id: [u8; 32], epoch: u64, stamp: u64) -> Result<Vec<u8>, Error> {
    let mut plain = encode_state(state)?;
    let len = plain.len();
    // Smallest bucket that holds the length prefix plus the state.
    let bucket = *BUCKETS.iter().find(|&&b| 4 + len <= b).ok_or(Error::BadExport)?;
    let mut padded = Vec::with_capacity(bucket);
    padded.extend_from_slice(&(len as u32).to_be_bytes());
    padded.extend_from_slice(&plain);
    padded.resize(bucket, 0);
    zeroize::Zeroize::zeroize(&mut plain);

    let header = header_bytes(&Header { vault_id, epoch, stamp, bucket });
    let sealed = hpke::single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeS::Base,
        &keys.seal_pk,
        LABEL, // info: differs from the envelope's, so no cross-opening
        &padded,
        &header, // AAD: the header cannot be moved onto another ciphertext
    );
    zeroize::Zeroize::zeroize(&mut padded);
    let (enc, ct) = sealed.map_err(|_| Error::Decrypt)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ENC_LEN + ct.len() + SIG_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ct);
    let sig: Signature = keys.sign.sign(&out); // over header || enc || ciphertext
    let sig = sig.normalize_s(); // always the low-S form
    out.extend_from_slice(&sig.to_bytes());
    Ok(out)
}

/// THE PHONE'S RESTORE CHECK. `floor` is the phone's own last-exported epoch,
/// if it still has one; an older copy is refused (an old-disk vault).
pub fn open_export(bytes: &[u8], keys: &BackupKeys, vault_id: &[u8; 32], floor: Option<u64>) -> Result<(Header, State), Error> {
    let h = verify_export(bytes, &keys.sign_public())?;
    if h.vault_id != *vault_id {
        return Err(Error::BadExport);
    }
    if floor.is_some_and(|f| h.epoch < f) {
        return Err(Error::StaleEpoch);
    }
    let enc = <DhP256HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&bytes[HEADER_LEN..HEADER_LEN + ENC_LEN])
        .map_err(|_| Error::Decrypt)?;
    let ct = &bytes[HEADER_LEN + ENC_LEN..bytes.len() - SIG_LEN];
    let mut plain = hpke::single_shot_open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeR::Base,
        &keys.seal_sk,
        &enc,
        LABEL,
        ct,
        &bytes[..HEADER_LEN],
    )
    .map_err(|_| Error::Decrypt)?;
    let result = parse_plain(&plain);
    zeroize::Zeroize::zeroize(&mut plain);
    result.map(|s| (h, s))
}

fn parse_plain(plain: &[u8]) -> Result<State, Error> {
    if plain.len() < 4 {
        return Err(Error::BadExport);
    }
    let len = u32::from_be_bytes(plain[..4].try_into().unwrap()) as usize;
    if len > plain.len() - 4 {
        return Err(Error::BadExport);
    }
    // Padding must be all zero, as in the envelope.
    if plain[4 + len..].iter().any(|&b| b != 0) {
        return Err(Error::BadExport);
    }
    decode_state(&plain[4..4 + len])
}

pub(crate) fn encode_state(s: &State) -> Result<Vec<u8>, Error> {
    if s.contacts.len() > MAX_CONTACTS
        || s.blocks.len() > MAX_BLOCKS
        || s.tombstones.len() > MAX_TOMBSTONES
        || s.declined.len() > MAX_DECLINED
        || s.intro_windows.len() > MAX_INTRO_WINDOWS
    {
        return Err(Error::BadExport);
    }
    let mut out = Vec::new();
    for n in [s.contacts.len(), s.blocks.len(), s.tombstones.len(), s.declined.len(), s.intro_windows.len()] {
        out.extend_from_slice(&(n as u16).to_be_bytes()); // every cap is under 65536
    }
    for c in &s.contacts {
        out.extend_from_slice(&c.sign);
        out.extend_from_slice(&c.seal);
        out.extend_from_slice(&c.window.to_bytes());
        out.push(c.tier as u8);
        match c.introduced_by {
            Some(k) => {
                out.push(1);
                out.extend_from_slice(&k);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 33]); // canonical: zeros when absent
            }
        }
    }
    for k in &s.blocks {
        out.extend_from_slice(k);
    }
    for (k, highest) in &s.tombstones {
        out.extend_from_slice(k);
        out.extend_from_slice(&highest.to_be_bytes());
    }
    for k in &s.declined {
        out.extend_from_slice(k);
    }
    for (k, w) in &s.intro_windows {
        out.extend_from_slice(k);
        out.extend_from_slice(&w.to_bytes());
    }
    out.extend_from_slice(&s.own_counter.to_be_bytes());
    Ok(out)
}

// A small cursor that refuses to read past the end.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);
impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::BadExport);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    pub(crate) fn key(&mut self) -> Result<Key33, Error> {
        Ok(self.take(33)?.try_into().unwrap())
    }
    fn window(&mut self) -> Result<ReplayWindow, Error> {
        let w = ReplayWindow::from_bytes(self.take(24)?.try_into().unwrap());
        if !w.has_highest() {
            return Err(Error::BadExport); // a real window always has bit 0 set
        }
        Ok(w)
    }
}

// Refuse a list with the same key twice.
pub(crate) fn no_duplicates(keys: impl Iterator<Item = Key33>) -> Result<(), Error> {
    let mut seen = std::collections::HashSet::new();
    for k in keys {
        if !seen.insert(k) {
            return Err(Error::BadExport);
        }
    }
    Ok(())
}

/// Canonical parse: exactly one byte string means each state.
pub(crate) fn decode_state(b: &[u8]) -> Result<State, Error> {
    let mut r = Reader(b);
    let mut n = [0usize; 5];
    for x in n.iter_mut() {
        *x = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
    }
    let caps = [MAX_CONTACTS, MAX_BLOCKS, MAX_TOMBSTONES, MAX_DECLINED, MAX_INTRO_WINDOWS];
    if n.iter().zip(caps).any(|(&x, cap)| x > cap) {
        return Err(Error::BadExport);
    }
    let mut b = Building(State::default());
    let s = &mut b.0;
    for _ in 0..n[0] {
        let sign = r.key()?;
        let seal: [u8; 65] = r.take(65)?.try_into().unwrap();
        SealPublicKey::from_bytes(&seal).map_err(|_| Error::BadExport)?;
        let window = r.window()?;
        let tier = match r.take(1)?[0] {
            0 => Tier::Confirmed,
            1 => Tier::Unconfirmed,
            _ => return Err(Error::BadExport), // unknown tier
        };
        let flag = r.take(1)?[0];
        let by = r.key()?;
        let introduced_by = match flag {
            0 if by == [0u8; 33] => None,
            1 => Some(by),
            _ => return Err(Error::BadExport), // bad flag, or junk where zeros belong
        };
        s.contacts.push(Contact { sign, seal, window, tier, introduced_by });
    }
    for _ in 0..n[1] {
        s.blocks.push(r.key()?);
    }
    for _ in 0..n[2] {
        let k = r.key()?;
        let highest = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
        s.tombstones.push((k, highest));
    }
    for _ in 0..n[3] {
        s.declined.push(r.key()?);
    }
    for _ in 0..n[4] {
        let k = r.key()?;
        s.intro_windows.push((k, r.window()?));
    }
    s.own_counter = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
    if !r.0.is_empty() {
        return Err(Error::BadExport); // trailing bytes
    }
    no_duplicates(s.contacts.iter().map(|c| c.sign))?;
    no_duplicates(s.blocks.iter().copied())?;
    no_duplicates(s.tombstones.iter().map(|(k, _)| *k))?;
    no_duplicates(s.declined.iter().copied())?;
    no_duplicates(s.intro_windows.iter().map(|(k, _)| *k))?;
    if s.contacts.iter().any(|c| s.tombstones.iter().any(|(k, _)| *k == c.sign)) {
        return Err(Error::BadExport); // both a contact and removed
    }
    Ok(b.done())
}

// Union of two key lists, keeping order: phone first, then the copy's extras.
// `keep` > 0 keeps only the newest `keep` (the last ones).
fn union(phone: &[Key33], copy: &[Key33], keep: usize) -> Vec<Key33> {
    let mut out: Vec<Key33> = phone.to_vec();
    for k in copy {
        if !out.contains(k) {
            out.push(*k);
        }
    }
    if keep > 0 && out.len() > keep {
        out.drain(..out.len() - keep);
    }
    out
}

// Union of tombstones by key, keeping the larger highest counter. Never capped.
fn union_tombstones(phone: &[(Key33, u64)], copy: &[(Key33, u64)]) -> Vec<(Key33, u64)> {
    let mut out = phone.to_vec();
    for (k, h) in copy {
        match out.iter_mut().find(|(x, _)| x == k) {
            Some((_, have)) => *have = (*have).max(*h),
            None => out.push((*k, *h)),
        }
    }
    out
}

// Merge a window: the larger highest, and every counter at or below it seen.
fn tighten(a: Option<ReplayWindow>, b: ReplayWindow) -> ReplayWindow {
    let highest = a.map_or(b.highest(), |a| a.highest().max(b.highest()));
    ReplayWindow::all_seen_up_to(highest)
}

/// RESTORE ONLY TIGHTENS. Nothing in `copy` can
/// un-block, revive a removed contact, loosen a tier, or reopen a counter.
pub fn merge(phone: &State, copy: &State) -> (State, OverCap) {
    // Blocks and tombstones are never capped down here: dropping a block
    // un-blocks someone, and dropping a tombstone revives a removed contact.
    let blocks = union(&phone.blocks, &copy.blocks, 0);
    let tombstones = union_tombstones(&phone.tombstones, &copy.tombstones);
    let declined = union(&phone.declined, &copy.declined, MAX_DECLINED);
    let barred = |k: &Key33| blocks.contains(k) || tombstones.iter().any(|(t, _)| t == k);

    let mut contacts: Vec<Contact> = Vec::new();
    for c in &phone.contacts {
        if barred(&c.sign) {
            continue;
        }
        let mut c = c.clone();
        if let Some(old) = copy.contacts.iter().find(|o| o.sign == c.sign) {
            c.tier = c.tier.max(old.tier); // the stricter one
            c.window = tighten(Some(c.window), old.window);
        } else {
            c.window = tighten(None, c.window);
        }
        contacts.push(c);
    }
    for o in &copy.contacts {
        if !barred(&o.sign) && !contacts.iter().any(|c| c.sign == o.sign) {
            let mut c = o.clone();
            c.window = tighten(None, o.window);
            contacts.push(c);
        }
    }
    let mut intro_windows: Vec<(Key33, ReplayWindow)> = Vec::new();
    for (k, w) in phone.intro_windows.iter().chain(copy.intro_windows.iter()) {
        match intro_windows.iter_mut().find(|(x, _)| x == k) {
            Some((_, have)) => *have = tighten(Some(*have), *w),
            None => intro_windows.push((*k, tighten(None, *w))),
        }
    }
    let over = OverCap {
        contacts: contacts.len() > MAX_CONTACTS,
        blocks: blocks.len() > MAX_BLOCKS,
        tombstones: tombstones.len() > MAX_TOMBSTONES,
        intro_windows: intro_windows.len() > MAX_INTRO_WINDOWS,
    };
    // The higher send counter wins, so a restored phone never reuses a number.
    let own_counter = phone.own_counter.max(copy.own_counter);
    (State { contacts, blocks, tombstones, declined, intro_windows, own_counter }, over)
}

/// What the app shows after a restore. A warning, never a refusal.
#[derive(Debug, PartialEq, Eq)]
pub struct Restored {
    pub stamp: u64,
    pub age_seconds: u64,
    pub stale: bool,
    pub stamp_in_future: bool,
}

pub const STALE_AFTER: u64 = 7 * 86_400;

pub fn restored(stamp: u64, now: u64) -> Restored {
    let stamp_in_future = stamp > now;
    let age_seconds = now.saturating_sub(stamp);
    Restored { stamp, age_seconds, stale: age_seconds > STALE_AFTER, stamp_in_future }
}

/// How far above the exported counter a restored phone starts (2^18, no send limit). Counters are exported at most hourly, so this must
/// cover every object sent between exports; it stays under the 2^20 jump cap.
pub const RESTORE_MARGIN: u64 = 1 << 18;

/// Where a restored phone starts counting: above both what it still has
/// locally and what the backup says plus the margin. Never wraps.
pub fn restored_counter(local: Option<u64>, exported: u64) -> u64 {
    local.unwrap_or(0).max(exported.saturating_add(RESTORE_MARGIN))
}

/// Bounds on the epoch: the first one, and the largest step after.
pub const MAX_FIRST_EPOCH: u64 = 1 << 32;
pub const MAX_EPOCH_STEP: u64 = 1 << 20;

/// The phone's next epoch after `floor`. Never wraps.
pub fn next_epoch(floor: u64) -> Result<u64, Error> {
    floor.checked_add(1).ok_or(Error::StaleEpoch)
}

/// Reference logic for the vault's slot. The companion builds the real store; this is
/// what it must do, and what the tests pin.
#[derive(Default)]
pub struct VaultSlot {
    pub registered: Option<Key33>,
    pub vault_id: Option<[u8; 32]>,
    pub epoch: u64,
    pub stored: Vec<u8>,
}

impl VaultSlot {
    /// `paired` is true only when the bytes came over the paired ArrowBridge
    /// channel. The first export registers its key and must arrive that way.
    pub fn put(&mut self, bytes: &[u8], key: &Key33, paired: bool) -> Result<(), Error> {
        let reg = match self.registered {
            None if paired => *key,
            None => return Err(Error::NotPaired),
            Some(r) if r == *key => r,
            Some(_) => return Err(Error::WrongBackupKey), // never replaced
        };
        let h = verify_export(bytes, &reg)?; // signature BEFORE the epoch
        match self.vault_id {
            Some(v) if v != h.vault_id => return Err(Error::BadExport), // another vault's export
            _ => {}
        }
        if self.registered.is_none() {
            // A first epoch near u64::MAX would freeze the slot forever.
            if !(1..=MAX_FIRST_EPOCH).contains(&h.epoch) {
                return Err(Error::StaleEpoch);
            }
        } else if h.epoch <= self.epoch || h.epoch - self.epoch > MAX_EPOCH_STEP {
            return Err(Error::StaleEpoch);
        }
        self.registered = Some(reg);
        self.vault_id = Some(h.vault_id);
        self.epoch = h.epoch;
        self.stored = bytes.to_vec();
        Ok(())
    }

    /// Clear the slot so a recreated vault root can register again. Needs the
    /// paired channel AND the person's confirmation on the home machine.
    pub fn reset(&mut self, paired: bool, confirmed_on_home_machine: bool) -> Result<(), Error> {
        if !(paired && confirmed_on_home_machine) {
            return Err(Error::NotPaired);
        }
        *self = VaultSlot::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> BackupKeys {
        BackupKeys::from_root(b"test root, never a real recovery phrase")
    }
    const VAULT: [u8; 32] = [7; 32];

    fn seal_bytes(n: u8) -> [u8; 65] {
        // A real point: the public half of a key derived from n.
        let (_, pk) = <DhP256HkdfSha256 as hpke::Kem>::derive_keypair(&[n; 32]);
        pk.to_bytes().as_slice().try_into().unwrap()
    }

    fn contact(n: u8) -> Contact {
        Contact { sign: [n; 33], seal: seal_bytes(n), window: ReplayWindow::starting_at(5), tier: Tier::Confirmed, introduced_by: None }
    }

    fn small_state() -> State {
        State {
            contacts: vec![contact(1), Contact { introduced_by: Some([9; 33]), tier: Tier::Unconfirmed, ..contact(2) }],
            blocks: vec![[3; 33]],
            tombstones: vec![([4; 33], 0)],
            declined: vec![[5; 33]],
            intro_windows: vec![([1; 33], ReplayWindow::starting_at(2))],
            own_counter: 77,
        }
    }

    // Distinct 33-byte keys for big lists.
    fn k(i: usize, tag: u8) -> Key33 {
        let mut out = [tag; 33];
        out[..4].copy_from_slice(&(i as u32).to_be_bytes());
        out
    }

    fn full_state() -> State {
        State {
            contacts: (0..MAX_CONTACTS).map(|i| Contact { sign: k(i, 1), ..contact(1) }).collect(),
            blocks: (0..MAX_BLOCKS).map(|i| k(i, 2)).collect(),
            tombstones: (0..MAX_TOMBSTONES).map(|i| (k(i, 3), u64::MAX)).collect(),
            declined: (0..MAX_DECLINED).map(|i| k(i, 4)).collect(),
            intro_windows: (0..MAX_INTRO_WINDOWS).map(|i| (k(i, 5), ReplayWindow::starting_at(1))).collect(),
            own_counter: u64::MAX,
        }
    }

    #[test]
    fn round_trip_and_vault_blind_verify() {
        let ks = keys();
        let bytes = export(&small_state(), &ks, VAULT, 3, 1000).unwrap();
        // The vault needs only the public signing key, no sealing key at all.
        let h = verify_export(&bytes, &ks.sign_public()).unwrap();
        assert_eq!((h.epoch, h.stamp, h.bucket), (3, 1000, 16 << 10));
        let (_, back) = open_export(&bytes, &ks, &VAULT, None).unwrap();
        assert_eq!(back, small_state());
    }

    #[test]
    fn keys_rebuild_from_the_same_root_and_differ_by_label() {
        let a = keys();
        let b = keys();
        assert_eq!(a.sign_public(), b.sign_public());
        assert_eq!(a.seal_pk.to_bytes(), b.seal_pk.to_bytes());
        // The seal and sign labels give different keys.
        assert_ne!(&a.seal_sk.to_bytes()[..], &a.sign.to_bytes()[..]);
        let other = BackupKeys::from_root(b"another root");
        assert_ne!(a.sign_public(), other.sign_public());
    }

    #[test]
    fn every_flipped_bit_is_refused_by_the_vault() {
        let ks = keys();
        let bytes = export(&State::default(), &ks, VAULT, 1, 1).unwrap();
        // Step through the header, enc, the start and end of the ciphertext, and the signature.
        let n = bytes.len();
        let spots: Vec<usize> = (0..HEADER_LEN + ENC_LEN + 64).chain(n - SIG_LEN - 64..n).collect();
        for i in spots {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            assert!(verify_export(&bad, &ks.sign_public()).is_err(), "byte {i} accepted");
        }
    }

    #[test]
    fn wrong_key_and_cross_opening() {
        let ks = keys();
        let bytes = export(&State::default(), &ks, VAULT, 1, 1).unwrap();
        let other = BackupKeys::from_root(b"another root");
        assert_eq!(verify_export(&bytes, &other.sign_public()), Err(Error::BadSignature));
        // An envelope object is not an export, and an export is not an object.
        let (sk, pk) = new_seal_keypair();
        let sender = {
            use p256::elliptic_curve::Generate;
            SigningKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap()
        };
        let obj = seal(&sender, &pk, 1, b"x").unwrap();
        assert_eq!(parse_header(&obj), Err(Error::BadExport));
        assert!(open(&bytes, &sk, &pk).is_err());
        assert!(open(&bytes[..OBJECT_SIZE], &sk, &pk).is_err());
    }

    #[test]
    fn header_cannot_move_to_another_ciphertext() {
        let ks = keys();
        let a = export(&small_state(), &ks, VAULT, 1, 1).unwrap();
        let b = export(&small_state(), &ks, VAULT, 2, 1).unwrap();
        let mut mixed = b.clone();
        mixed[..HEADER_LEN].copy_from_slice(&a[..HEADER_LEN]);
        assert_eq!(verify_export(&mixed, &ks.sign_public()), Err(Error::BadSignature));
    }

    #[test]
    fn phone_floor_and_vault_id() {
        let ks = keys();
        let bytes = export(&State::default(), &ks, VAULT, 5, 1).unwrap();
        assert_eq!(open_export(&bytes, &ks, &VAULT, Some(6)).unwrap_err(), Error::StaleEpoch);
        assert!(open_export(&bytes, &ks, &VAULT, Some(5)).is_ok());
        assert!(open_export(&bytes, &ks, &VAULT, None).is_ok()); // a new phone has no floor
        assert_eq!(open_export(&bytes, &ks, &[8; 32], None).unwrap_err(), Error::BadExport);
    }

    #[test]
    fn caps_fit_the_largest_bucket() {
        let ks = keys();
        let bytes = export(&full_state(), &ks, VAULT, 1, 1).unwrap();
        assert_eq!(parse_header(&bytes).unwrap().bucket, 512 << 10);
        assert_eq!(open_export(&bytes, &ks, &VAULT, None).unwrap().1, full_state());
        // One over any cap is refused, never truncated.
        let mut s = full_state();
        s.blocks.push(k(MAX_BLOCKS, 2));
        assert_eq!(export(&s, &ks, VAULT, 1, 1), Err(Error::BadExport));
    }

    #[test]
    fn bucket_boundaries() {
        let ks = keys();
        // Grow the block list until each bucket overflows into the next.
        let mut last = 0;
        for n in [0usize, 490, 491, 1975, 1976, 4096] {
            let s = State { blocks: (0..n).map(|i| k(i, 2)).collect(), ..State::default() };
            let b = parse_header(&export(&s, &ks, VAULT, 1, 1).unwrap()).unwrap().bucket;
            assert!(b >= last);
            last = b;
            let need = 4 + 10 + 8 + 33 * n;
            let expect = *BUCKETS.iter().find(|&&x| need <= x).unwrap();
            assert_eq!(b, expect, "{n} blocks");
        }
        // 4 + 10 + 8 + 33 * 495 = 16357 fits 16 KiB; 496 needs 64 KiB.
        let fits = |n: usize| {
            let s = State { blocks: (0..n).map(|i| k(i, 2)).collect(), ..State::default() };
            parse_header(&export(&s, &ks, VAULT, 1, 1).unwrap()).unwrap().bucket
        };
        assert_eq!(fits(495), 16 << 10);
        assert_eq!(fits(496), 64 << 10);
        // Exactly full: 4 + 10 + 8 + 8*57 + 482*33 = 16384 still fits 16 KiB.
        let exact = State {
            blocks: (0..482).map(|i| k(i, 2)).collect(),
            intro_windows: (0..8).map(|i| (k(i, 5), ReplayWindow::starting_at(1))).collect(),
            ..State::default()
        };
        assert_eq!(4 + encode_state(&exact).unwrap().len(), 16 << 10);
        assert_eq!(parse_header(&export(&exact, &ks, VAULT, 1, 1).unwrap()).unwrap().bucket, 16 << 10);
    }

    // Build a sealed export around hand-made plaintext, to test the parser.
    fn export_raw(plain_state: &[u8], pad_junk: bool) -> Vec<u8> {
        let ks = keys();
        let bucket = 16 << 10;
        let mut padded = (plain_state.len() as u32).to_be_bytes().to_vec();
        padded.extend_from_slice(plain_state);
        padded.resize(bucket, 0);
        if pad_junk {
            padded[bucket - 1] = 1;
        }
        let header = header_bytes(&Header { vault_id: VAULT, epoch: 1, stamp: 1, bucket });
        let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(&OpModeS::Base, &ks.seal_pk, LABEL, &padded, &header).unwrap();
        let mut out = header.to_vec();
        out.extend_from_slice(&enc.to_bytes());
        out.extend_from_slice(&ct);
        let sig: Signature = ks.sign.sign(&out);
        let sig = sig.normalize_s();
        out.extend_from_slice(&sig.to_bytes());
        out
    }

    fn parse_of(plain_state: &[u8]) -> Result<State, Error> {
        open_export(&export_raw(plain_state, false), &keys(), &VAULT, None).map(|(_, s)| s)
    }

    #[test]
    fn canonical_parse_rules() {
        let good = encode_state(&small_state()).unwrap();
        assert_eq!(parse_of(&good).unwrap(), small_state());
        // Non-zero padding.
        assert_eq!(open_export(&export_raw(&good, true), &keys(), &VAULT, None).unwrap_err(), Error::BadExport);
        // Trailing bytes after the lists.
        let mut t = good.clone();
        t.push(0);
        assert_eq!(parse_of(&t).unwrap_err(), Error::BadExport);
        // Duplicate key in a list.
        let dup = State { blocks: vec![[3; 33], [3; 33]], ..State::default() };
        assert_eq!(parse_of(&encode_state(&dup).unwrap()).unwrap_err(), Error::BadExport);
        let dup_c = State { contacts: vec![contact(1), contact(1)], ..State::default() };
        assert_eq!(parse_of(&encode_state(&dup_c).unwrap()).unwrap_err(), Error::BadExport);
        // Both a contact and a tombstone.
        let both = State { contacts: vec![contact(1)], tombstones: vec![([1; 33], 0)], ..State::default() };
        assert_eq!(parse_of(&encode_state(&both).unwrap()).unwrap_err(), Error::BadExport);
        // Contact field offsets: counts (10), then sign 33, seal 65, window 24, tier, flag, by.
        let one = encode_state(&State { contacts: vec![contact(1)], ..State::default() }).unwrap();
        let tier_at = 10 + 33 + 65 + 24;
        let mut bad_tier = one.clone();
        bad_tier[tier_at] = 2;
        assert_eq!(parse_of(&bad_tier).unwrap_err(), Error::BadExport);
        let mut bad_flag = one.clone();
        bad_flag[tier_at + 1] = 2;
        assert_eq!(parse_of(&bad_flag).unwrap_err(), Error::BadExport);
        let mut junk_by = one.clone();
        junk_by[tier_at + 2] = 1; // flag 0 but introduced_by not zero
        assert_eq!(parse_of(&junk_by).unwrap_err(), Error::BadExport);
        // A window without bit 0 (the last seen byte is the low bits).
        let mut no_bit0 = one.clone();
        no_bit0[tier_at - 1] = 0;
        assert_eq!(parse_of(&no_bit0).unwrap_err(), Error::BadExport);
        // A sealing key that is not a curve point.
        let mut bad_seal = one.clone();
        bad_seal[10 + 33 + 10] ^= 1;
        assert_eq!(parse_of(&bad_seal).unwrap_err(), Error::BadExport);
        // A count over its cap.
        let mut over = vec![0u8; 10];
        over[2..4].copy_from_slice(&((MAX_BLOCKS + 1) as u16).to_be_bytes());
        assert_eq!(parse_of(&over).unwrap_err(), Error::BadExport);
        // A count claiming more than is there.
        let mut short = vec![0u8; 10];
        short[3] = 1;
        assert_eq!(parse_of(&short).unwrap_err(), Error::BadExport);
    }

    #[test]
    fn merge_only_tightens() {
        let phone = State {
            contacts: vec![contact(1), Contact { tier: Tier::Confirmed, ..contact(2) }],
            blocks: vec![[20; 33]],
            ..State::default()
        };
        let mut late = contact(1);
        late.window = ReplayWindow::starting_at(900);
        let copy = State {
            contacts: vec![late, Contact { tier: Tier::Unconfirmed, ..contact(2) }, contact(3), contact(4)],
            blocks: vec![[4; 33]], // contact 4 is blocked in the copy
            tombstones: vec![([3; 33], 0)], // contact 3 was removed
            ..State::default()
        };
        let (m, over) = merge(&phone, &copy);
        assert!(!over.any());
        let signs: Vec<u8> = m.contacts.iter().map(|c| c.sign[0]).collect();
        assert_eq!(signs, [1, 2]); // 3 tombstoned and 4 blocked are not brought back
        assert!(m.blocks.contains(&[20; 33]) && m.blocks.contains(&[4; 33])); // phone block survives
        assert_eq!(m.contacts[1].tier, Tier::Unconfirmed); // the stricter tier
        // Window: the higher highest, and everything at or below it seen.
        let mut w = m.contacts[0].window;
        assert_eq!(w.check_and_mark(900), Err(Error::Replay));
        assert_eq!(w.check_and_mark(899), Err(Error::Replay));
        assert_eq!(w.check_and_mark(901), Ok(()));
    }

    #[test]
    fn tombstone_counter_survives_merge_as_the_larger() {
        let phone = State { tombstones: vec![([3; 33], 10)], ..State::default() };
        let copy = State { tombstones: vec![([3; 33], 50)], ..State::default() };
        assert_eq!(merge(&phone, &copy).0.tombstones, vec![([3; 33], 50)]);
        assert_eq!(merge(&copy, &phone).0.tombstones, vec![([3; 33], 50)]);
        // And the counter survives an export round trip.
        let ks = keys();
        let b = export(&copy, &ks, VAULT, 1, 1).unwrap();
        assert_eq!(open_export(&b, &ks, &VAULT, None).unwrap().1.tombstones, vec![([3; 33], 50)]);
    }

    #[test]
    fn merge_never_drops_a_block_even_past_the_cap() {
        let phone = State { blocks: (0..MAX_BLOCKS).map(|i| k(i, 2)).collect(), ..State::default() };
        let copy = State { blocks: vec![k(99_999, 2)], ..State::default() };
        let (m, over) = merge(&phone, &copy);
        assert_eq!(m.blocks.len(), MAX_BLOCKS + 1);
        assert!(over.blocks && !over.contacts);
        assert!(m.blocks.contains(&k(0, 2)));
    }

    #[test]
    fn stale_flag() {
        assert!(!restored(0, STALE_AFTER).stale);
        assert!(restored(0, STALE_AFTER + 1).stale);
        let f = restored(100, 50);
        assert_eq!((f.age_seconds, f.stale, f.stamp_in_future), (0, false, true));
    }

    #[test]
    fn vault_slot_rules() {
        let ks = keys();
        let key = ks.sign_public();
        let e1 = export(&State::default(), &ks, VAULT, 1, 1).unwrap();
        let e2 = export(&State::default(), &ks, VAULT, 2, 1).unwrap();
        let mut slot = VaultSlot::default();
        assert_eq!(slot.put(&e1, &key, false), Err(Error::NotPaired)); // first must be paired
        slot.put(&e1, &key, true).unwrap();
        assert_eq!(slot.put(&e1, &key, true), Err(Error::StaleEpoch)); // equal epoch
        // Another key is refused, even over the pairing.
        let other = BackupKeys::from_root(b"another root");
        let o9 = export(&State::default(), &other, VAULT, 9, 1).unwrap();
        assert_eq!(slot.put(&o9, &other.sign_public(), true), Err(Error::WrongBackupKey));
        // A high epoch with a bad signature does not move the epoch.
        let mut forged = export(&State::default(), &ks, VAULT, 1_000, 1).unwrap();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(slot.put(&forged, &key, false).is_err());
        assert_eq!(slot.epoch, 1);
        slot.put(&e2, &key, false).unwrap();
        assert_eq!(slot.epoch, 2);
        // Reset needs both the pairing and the person's confirmation.
        assert_eq!(slot.reset(true, false), Err(Error::NotPaired));
        assert_eq!(slot.reset(false, true), Err(Error::NotPaired));
        slot.reset(true, true).unwrap();
        slot.put(&o9, &other.sign_public(), true).unwrap(); // new root registers
    }

    #[test]
    fn tombstone_at_cap_is_never_dropped_and_contact_stays_removed() {
        // Phone at 1024 tombstones, copy has one more plus a contact
        // matching the phone's OLDEST tombstone. It must stay removed.
        let phone = State { tombstones: (0..MAX_TOMBSTONES).map(|i| (k(i, 3), 0)).collect(), ..State::default() };
        let copy = State {
            tombstones: vec![(k(50_000, 3), 0)],
            contacts: vec![Contact { sign: k(0, 3), ..contact(1) }],
            ..State::default()
        };
        let (m, over) = merge(&phone, &copy);
        assert!(m.contacts.is_empty());
        assert!(m.tombstones.iter().any(|(t, _)| *t == k(0, 3)));
        assert_eq!(m.tombstones.len(), MAX_TOMBSTONES + 1);
        assert!(over.tombstones);
    }

    #[test]
    fn merge_reports_contacts_over_cap() {
        let a = State { contacts: (0..MAX_CONTACTS).map(|i| Contact { sign: k(i, 1), ..contact(1) }).collect(), ..State::default() };
        let b = State { contacts: (0..MAX_CONTACTS).map(|i| Contact { sign: k(i, 9), ..contact(1) }).collect(), ..State::default() };
        let (m, over) = merge(&a, &b);
        assert_eq!(m.contacts.len(), 2 * MAX_CONTACTS);
        assert!(over.contacts && over.any());
        assert_eq!(export(&m, &keys(), VAULT, 1, 1), Err(Error::BadExport)); // why the flag matters
    }

    #[test]
    fn debug_shows_counts_not_keys() {
        let text = format!("{:?} {:?}", small_state(), contact(1));
        assert!(text.contains("contacts: 2"));
        assert!(!text.contains("[1, 1"));
        assert!(!text.contains("101")); // no byte lists at all
    }

    #[test]
    fn high_s_twin_is_refused() {
        let ks = keys();
        let bytes = export(&State::default(), &ks, VAULT, 1, 1).unwrap();
        let n = bytes.len();
        let sig = Signature::from_slice(&bytes[n - SIG_LEN..]).unwrap();
        assert_eq!(sig.normalize_s(), sig); // we always sign low-S
        // The twin (r, n - s) verifies under plain ECDSA, so it must be refused by rule.
        let twin = Signature::from_scalars(sig.r(), -sig.s()).unwrap();
        assert_ne!(twin, sig);
        let mut bad = bytes.clone();
        bad[n - SIG_LEN..].copy_from_slice(&twin.to_bytes());
        assert_eq!(verify_export(&bad, &ks.sign_public()), Err(Error::BadSignature));
    }

    // Re-sign a changed export with the real key, so only the HPKE layer can catch it.
    fn resign(mut b: Vec<u8>) -> Vec<u8> {
        let n = b.len();
        let sig: Signature = keys().sign.sign(&b[..n - SIG_LEN]);
        b[n - SIG_LEN..].copy_from_slice(&sig.normalize_s().to_bytes());
        b
    }

    #[test]
    fn header_is_bound_by_the_aad_not_only_the_signature() {
        let ks = keys();
        let mut b = export(&small_state(), &ks, VAULT, 1, 1).unwrap();
        b[64] ^= 1; // the stamp, inside the header
        let b = resign(b);
        verify_export(&b, &ks.sign_public()).unwrap(); // the signature is fine now
        assert_eq!(open_export(&b, &ks, &VAULT, None).unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn sealed_under_the_envelope_label_does_not_open() {
        let ks = keys();
        let header = header_bytes(&Header { vault_id: VAULT, epoch: 1, stamp: 1, bucket: 16 << 10 });
        let mut padded = vec![0u8; 16 << 10];
        padded[3] = 18; // state length 18: five zero counts and the own counter
        let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
            &OpModeS::Base, &ks.seal_pk, b"arrowmem-core v1 seal", &padded, &header,
        ).unwrap();
        let mut b = header.to_vec();
        b.extend_from_slice(&enc.to_bytes());
        b.extend_from_slice(&ct);
        b.extend_from_slice(&[0u8; SIG_LEN]);
        let b = resign(b);
        assert_eq!(open_export(&b, &ks, &VAULT, None).unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn first_epoch_and_step_are_bounded() {
        let ks = keys();
        let key = ks.sign_public();
        let at = |e: u64| export(&State::default(), &ks, VAULT, e, 1).unwrap();
        let mut slot = VaultSlot::default();
        assert_eq!(slot.put(&at(u64::MAX), &key, true), Err(Error::StaleEpoch));
        assert_eq!(slot.put(&at(0), &key, true), Err(Error::StaleEpoch));
        assert_eq!(slot.put(&at(MAX_FIRST_EPOCH + 1), &key, true), Err(Error::StaleEpoch));
        slot.put(&at(MAX_FIRST_EPOCH), &key, true).unwrap();
        assert_eq!(slot.put(&at(MAX_FIRST_EPOCH + MAX_EPOCH_STEP + 1), &key, false), Err(Error::StaleEpoch));
        slot.put(&at(MAX_FIRST_EPOCH + MAX_EPOCH_STEP), &key, false).unwrap();
        // Another vault's export, same key, is refused.
        let other = export(&State::default(), &ks, [8; 32], MAX_FIRST_EPOCH + MAX_EPOCH_STEP + 1, 1).unwrap();
        assert_eq!(slot.put(&other, &key, false), Err(Error::BadExport));
        assert_eq!(next_epoch(u64::MAX), Err(Error::StaleEpoch));
        assert_eq!(next_epoch(4), Ok(5));
    }

    #[test]
    fn own_counter_round_trips_and_merges_to_the_higher() {
        let ks = keys();
        let a = State { own_counter: 900, ..State::default() };
        let b = export(&a, &ks, VAULT, 1, 1).unwrap();
        assert_eq!(open_export(&b, &ks, &VAULT, None).unwrap().1.own_counter, 900);
        let c = State { own_counter: 50, ..State::default() };
        assert_eq!(merge(&a, &c).0.own_counter, 900);
        assert_eq!(merge(&c, &a).0.own_counter, 900);
    }

    #[test]
    fn restore_counter_floor() {
        assert_eq!(restored_counter(None, 10), 10 + RESTORE_MARGIN);
        assert_eq!(restored_counter(Some(5), 10), 10 + RESTORE_MARGIN);
        assert_eq!(restored_counter(Some(u64::MAX - 1), 10), u64::MAX - 1); // the local one is higher
        assert_eq!(restored_counter(None, u64::MAX), u64::MAX); // never wraps
        assert!(RESTORE_MARGIN < 1 << 20); // stays inside the jump cap
    }
}
