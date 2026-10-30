//! Admission: the ONE path from a sealed object to the app.
//!
//! `open` proves who signed it. `admit` decides whether that signer may reach
//! the person, and how. Nothing reaches the app any other way.

use crate::*;
use export::{Contact, Key33, State, Tier};
use hpke::Deserializable;
use sha2::{Digest, Sha256};

pub const KIND_MESSAGE: u8 = 0x01;
pub const KIND_INVITE: u8 = 0x02;
pub const KIND_INTRO: u8 = 0x03;
pub const KIND_REQUEST: u8 = 0x04;

pub const MAX_OPEN_INVITES: usize = 32;
const INVITE_LABEL: &[u8] = b"arrowmem-core v1 invite";
const LOCAL_LABEL: &[u8] = b"arrowmem-core v1 local";

/// What the app gets back. Words reach it only in Message and NewContact.
#[derive(PartialEq, Eq)]
pub enum Admitted {
    /// A contact's message, after the replay window let it through once.
    Message { from: Key33, counter: u64, body: Vec<u8> },
    /// A stranger redeemed one of his invites and is now a contact.
    NewContact { from: Key33, first_message: Vec<u8> },
    /// A stranger's request (plain or introduced) is waiting in the inbox.
    Requested { from: Key33 },
}

// Never print message words into a log (same rule as Verified).
impl std::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Admitted::Message { counter, body, .. } => write!(f, "Message {{ counter: {counter}, {} bytes }}", body.len()),
            Admitted::NewContact { first_message, .. } => write!(f, "NewContact {{ {} bytes }}", first_message.len()),
            Admitted::Requested { .. } => write!(f, "Requested"),
        }
    }
}

/// Everything admission keeps. The app stores it (encrypted at rest) and
/// must persist it BEFORE showing what admit returned (persist-then-display).
#[derive(Default)]
pub struct Admission {
    pub state: State,
    pub inbox: Inbox,
    // SHA-256 of each open invite's secret. The secret itself is never kept.
    invites: Vec<[u8; 32]>,
    // The counter of each waiting request, so an accepted contact's window
    // starts at the object that admitted them.
    request_counters: Vec<(Key33, u64)>,
    // Goes up by one on every save; an older saved blob is refused on load,
    // so state (and the send counter in it) never rolls back.
    pub(crate) generation: u64,
}

fn invite_hash(secret: &[u8; 16]) -> [u8; 32] {
    Sha256::new().chain_update(INVITE_LABEL).chain_update(secret).finalize().into()
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.wipe_in_place();
    }
}

impl Admission {
    /// Make a one-time invite. The app shows the returned secret (with his
    /// keys) as a QR code or link; only its hash is kept here.
    pub fn new_invite(&mut self) -> Result<[u8; 16], Error> {
        if self.invites.len() >= MAX_OPEN_INVITES {
            return Err(Error::TooManyInvites);
        }
        let mut secret = [0u8; 16];
        getrandom::fill(&mut secret).map_err(|_| Error::RandomFailed)?;
        self.invites.push(invite_hash(&secret));
        Ok(secret)
    }

    pub fn open_invites(&self) -> usize {
        self.invites.len()
    }

    /// After a restore every open invite is void.
    pub fn void_invites(&mut self) {
        self.invites.clear();
    }

    /// True if he removed this key before. A removed person may still ask
    /// again by REQUEST; the app can show this next to it so his
    /// tap is informed. How it is shown is the app's design, not the crate's.
    pub fn was_removed(&self, k: &Key33) -> bool {
        self.removed_highest(k).is_some()
    }

    // The highest counter ever seen from a removed key, if it was removed.
    fn removed_highest(&self, k: &Key33) -> Option<u64> {
        self.state.tombstones.iter().find(|(t, _)| t == k).map(|(_, h)| *h)
    }

    // An admitting object from a removed key must be NEWER than anything seen
    // from it before, or a relay could replay an old REQUEST, get it accepted,
    // and then replay old messages.
    fn check_not_old(&self, k: &Key33, counter: u64) -> Result<(), Error> {
        match self.removed_highest(k) {
            Some(h) if counter <= h => Err(Error::Replay),
            _ => Ok(()),
        }
    }

    fn is_blocked(&self, k: &Key33) -> bool {
        self.state.blocks.contains(k)
    }

    fn is_contact(&self, k: &Key33) -> bool {
        self.state.contacts.iter().any(|c| c.sign == *k)
    }

    fn contact_mut(&mut self, k: &Key33) -> Option<&mut Contact> {
        self.state.contacts.iter_mut().find(|c| c.sign == *k)
    }

    // Every check that add_contact makes, with nothing changed: check first,
    // mutate after, so a failure leaves everything as it was.
    fn can_add(&self, sign: &Key33) -> Result<(), Error> {
        if self.is_contact(sign) {
            return Err(Error::AlreadyContact);
        }
        if self.state.contacts.len() >= export::MAX_CONTACTS {
            return Err(Error::ContactsFull);
        }
        Ok(())
    }

    // Only call after can_add succeeded; this one cannot fail.
    fn add_contact(&mut self, sign: Key33, seal: [u8; 65], counter: u64, introduced_by: Option<Key33>) {
        // check_not_old already refused any admitting counter at or below what
        // this key sent before it was removed, so `counter` is above it.
        let seed = counter;
        // He chose to let this key back in, so its removal mark goes.
        self.state.tombstones.retain(|(t, _)| *t != sign);
        // Any waiting request from this key is now settled.
        self.inbox.accept(&sign);
        self.request_counters.retain(|(k, _)| *k != sign);
        // all_seen_up_to, not starting_at: nothing at or below the admitting
        // counter can ever arrive later as a fresh message.
        let window = ReplayWindow::all_seen_up_to(seed);
        self.state.contacts.push(Contact { sign, seal, window, tier: Tier::Confirmed, introduced_by });
    }

    /// THE ADMISSION BOUNDARY. Untrusted bytes in; what may reach the person out.
    /// The app should drop every Err silently and never reply: an answer would
    /// tell the sender whether they are blocked or a contact.
    pub fn admit(&mut self, object: &[u8], my_sk: &SealPrivateKey, my_pk: &SealPublicKey) -> Result<Admitted, Error> {
        let v = open(object, my_sk, my_pk)?;
        let from: Key33 = v.sender().to_sec1_point(true).as_bytes().try_into().map_err(|_| Error::BadSenderKey)?;
        // Blocked keys are refused before any other admission work.
        if self.is_blocked(&from) {
            return Err(Error::Blocked);
        }
        let (&kind, rest) = v.body().split_first().ok_or(Error::BadKind)?;
        let counter = v.counter();

        if let Some(c) = self.contact_mut(&from) {
            // A contact may only send messages. Anything else touches nothing.
            if kind != KIND_MESSAGE {
                return Err(Error::AlreadyContact);
            }
            c.window.check_and_mark(counter)?; // only after open succeeded
            return Ok(Admitted::Message { from, counter, body: rest.to_vec() });
        }

        // From here on the sender is a stranger.
        match kind {
            KIND_INVITE | KIND_INTRO | KIND_REQUEST => self.check_not_old(&from, counter)?,
            KIND_MESSAGE => return Err(Error::Stranger),
            _ => return Err(Error::BadKind),
        }
        match kind {
            KIND_INVITE => self.redeem_invite(from, counter, rest),
            KIND_INTRO => self.offer_intro(from, counter, rest, my_pk, v.sender()),
            _ => {
                self.inbox.offer(from, rest)?;
                self.request_counters.retain(|(k, _)| *k != from);
                self.request_counters.push((from, counter));
                Ok(Admitted::Requested { from })
            }
        }
    }

    // INVITE body: the newcomer's sealing key (65), the secret (16), a first message.
    fn redeem_invite(&mut self, from: Key33, counter: u64, rest: &[u8]) -> Result<Admitted, Error> {
        if rest.len() < 65 + 16 {
            return Err(Error::UnknownInvite);
        }
        let seal: [u8; 65] = rest[..65].try_into().unwrap();
        let mut secret: [u8; 16] = rest[65..81].try_into().unwrap();
        let hash = invite_hash(&secret);
        zeroize::Zeroize::zeroize(&mut secret);
        let at = self.invites.iter().position(|h| *h == hash).ok_or(Error::UnknownInvite)?;
        SealPublicKey::from_bytes(&seal).map_err(|_| Error::BadRequestKey)?;
        self.can_add(&from)?; // before the invite is burned
        // Burn it in the same step it is used: one invite, one contact.
        self.invites.remove(at);
        self.add_contact(from, seal, counter, None);
        Ok(Admitted::NewContact { from, first_message: rest[81..].to_vec() })
    }

    // INTRO body: the intro (INTRO_LEN), then the newcomer's sealing key (65), then text.
    fn offer_intro(&mut self, from: Key33, counter: u64, rest: &[u8], my_pk: &SealPublicKey, sender: &p256::ecdsa::VerifyingKey) -> Result<Admitted, Error> {
        if rest.len() < INTRO_LEN {
            return Err(Error::BadIntro);
        }
        let intro = verify_intro(&rest[..INTRO_LEN], my_pk, sender)?;
        // Rule 1: the introducer must be a current contact, and not blocked.
        if self.is_blocked(&intro.by) || !self.is_contact(&intro.by) {
            return Err(Error::BadIntro);
        }
        // Rule 4: each of C's intros works once (keyed on C's counter).
        // Work on a copy and keep it only if the inbox takes the request, so a
        // full inbox never burns C's intro.
        let found = self.state.intro_windows.iter().position(|(k, _)| *k == intro.by);
        let window = match found {
            Some(i) => {
                let mut w = self.state.intro_windows[i].1;
                w.check_and_mark(intro.counter)?;
                w
            }
            None if self.state.intro_windows.len() >= export::MAX_INTRO_WINDOWS => return Err(Error::TooManyIntroduced),
            None => ReplayWindow::starting_at(intro.counter),
        };
        // An intro never admits. It only goes to the top of the inbox.
        self.inbox.offer_introduced(from, intro.by, &intro.newcomer_seal, &rest[INTRO_LEN..])?;
        match found {
            Some(i) => self.state.intro_windows[i].1 = window,
            None => self.state.intro_windows.push((intro.by, window)),
        }
        self.request_counters.retain(|(k, _)| *k != from);
        self.request_counters.push((from, counter));
        Ok(Admitted::Requested { from })
    }

    /// He tapped accept. The request's own signed sealing key is the only key used.
    pub fn accept_request(&mut self, from: &Key33) -> Result<String, Error> {
        // Blocked since the request arrived: never admit.
        if self.is_blocked(from) {
            return Err(Error::Blocked);
        }
        let by = self.inbox.pending().iter().find(|(k, _, _, _)| k == from).map(|(_, _, b, _)| *b).ok_or(Error::Stranger)?;
        let counter = self.request_counters.iter().find(|(k, _)| k == from).map(|(_, c)| *c).ok_or(Error::Stranger)?;
        self.can_add(from)?; // before anything is removed
        let (text, seal) = self.inbox.accept(from).ok_or(Error::Stranger)?;
        self.add_contact(*from, seal, counter, by);
        Ok(text)
    }

    /// Overwrite everything held: who he knows, who he blocked, what strangers
    /// wrote. Replacing self drops the old value, and every part wipes itself.
    pub fn wipe(&mut self) {
        *self = Admission::default();
    }

    // Every list overwritten, spare capacity included (wipe.rs).
    pub(crate) fn wipe_in_place(&mut self) {
        crate::wipe::wipe_vec(&mut self.invites);
        crate::wipe::wipe_vec(&mut self.request_counters);
        self.state.wipe_in_place();
        self.inbox.wipe();
    }

    /// Everything admission keeps, as bytes for the app to store (encrypted
    /// at rest with authenticated encryption). The result
    /// is PLAINTEXT: the caller wipes it once it is encrypted.
    pub fn to_local_bytes(&self) -> Result<Vec<u8>, Error> {
        let state = export::encode_state(&self.state)?;
        let mut out = Vec::new();
        out.extend_from_slice(LOCAL_LABEL);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&(state.len() as u32).to_be_bytes());
        out.extend_from_slice(&state);
        out.extend_from_slice(&(self.invites.len() as u16).to_be_bytes());
        for h in &self.invites {
            out.extend_from_slice(h);
        }
        out.extend_from_slice(&(self.request_counters.len() as u16).to_be_bytes());
        for (k, c) in &self.request_counters {
            out.extend_from_slice(k);
            out.extend_from_slice(&c.to_be_bytes());
        }
        self.inbox.encode_into(&mut out);
        Ok(out)
    }

    /// Read what to_local_bytes wrote. Strict: any damage is BadExport.
    pub fn from_local_bytes(b: &[u8]) -> Result<Self, Error> {
        let mut r = export::Reader(b);
        if r.take(LOCAL_LABEL.len())? != LOCAL_LABEL {
            return Err(Error::BadExport);
        }
        let generation = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
        let len = u32::from_be_bytes(r.take(4)?.try_into().unwrap()) as usize;
        // If anything below fails, the decoded state is wiped, not left behind.
        let state = export::Building(export::decode_state(r.take(len)?)?);
        let n = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
        if n > MAX_OPEN_INVITES {
            return Err(Error::BadExport);
        }
        let mut invites = Vec::with_capacity(n);
        for _ in 0..n {
            invites.push(<[u8; 32]>::try_from(r.take(32)?).unwrap());
        }
        let m = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
        if m > inbox::MAX_PENDING + inbox::MAX_INTRODUCED_TOTAL {
            return Err(Error::BadExport);
        }
        let mut request_counters = Vec::with_capacity(m);
        for _ in 0..m {
            let k = r.key()?;
            request_counters.push((k, u64::from_be_bytes(r.take(8)?.try_into().unwrap())));
        }
        let inbox = Inbox::decode_from(&mut r)?;
        if !r.0.is_empty() {
            return Err(Error::BadExport); // trailing bytes
        }
        // Every waiting request has exactly one counter, and nothing else does.
        export::no_duplicates(request_counters.iter().map(|(k, _)| *k))?;
        let pending: Vec<Key33> = inbox.pending().iter().map(|(k, _, _, _)| *k).collect();
        if request_counters.len() != pending.len() || !request_counters.iter().all(|(k, _)| pending.contains(k)) {
            return Err(Error::BadExport);
        }
        // States that offer and admit can never create are refused:
        let s = &state.0;
        let is_contact = |k: &Key33| s.contacts.iter().any(|c| c.sign == *k);
        for (k, _, by, _) in inbox.pending() {
            // a waiting request from someone blocked, a contact, or declined;
            if s.blocks.contains(k) || is_contact(k) || inbox.is_declined(k) {
                return Err(Error::BadExport);
            }
            // an introduced request whose introducer is not a contact;
            if by.is_some_and(|b| !is_contact(&b)) {
                return Err(Error::BadExport);
            }
        }
        // a request counter no window could ever move past.
        if request_counters.iter().any(|(_, c)| *c == u64::MAX) {
            return Err(Error::BadExport);
        }
        Ok(Admission { state: state.done(), inbox, invites, request_counters, generation })
    }

    /// He tapped decline. The key stays quiet for the next 128 declines.
    pub fn decline_request(&mut self, from: &Key33) {
        self.inbox.decline(from);
        self.request_counters.retain(|(k, _)| k != from);
    }

    /// Block a key: refused before everything else from now on.
    pub fn block(&mut self, k: &Key33) -> Result<(), Error> {
        if self.is_blocked(k) {
            return Ok(());
        }
        // A full block list never drops an old block; it refuses a new one.
        if self.state.blocks.len() >= export::MAX_BLOCKS {
            return Err(Error::BlockListFull);
        }
        self.state.blocks.push(*k);
        self.inbox.decline(k);
        self.request_counters.retain(|(x, _)| x != k);
        Ok(())
    }

    /// Remove a contact: a tombstone holding the highest counter seen from
    /// them, so neither a restore nor a replay can bring them back.
    pub fn remove_contact(&mut self, k: &Key33) -> Result<(), Error> {
        let seen = self.state.contacts.iter().find(|c| c.sign == *k).map(|c| c.window.highest());
        // Already removed: only raise the counter, never refuse (order matters).
        if let Some((_, h)) = self.state.tombstones.iter_mut().find(|(t, _)| t == k) {
            *h = (*h).max(seen.unwrap_or(0));
            self.state.contacts.retain(|c| c.sign != *k);
            return Ok(());
        }
        if self.state.tombstones.len() >= export::MAX_TOMBSTONES {
            return Err(Error::TombstonesFull);
        }
        self.state.contacts.retain(|c| c.sign != *k);
        self.state.tombstones.push((*k, seen.unwrap_or(0)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::Serializable;
    use p256::ecdsa::SigningKey;

    fn signer() -> SigningKey {
        use p256::elliptic_curve::Generate;
        SigningKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap()
    }

    fn k33(s: &SigningKey) -> Key33 {
        s.verifying_key().to_sec1_point(true).as_bytes().try_into().unwrap()
    }

    struct Me {
        sk: SealPrivateKey,
        pk: SealPublicKey,
        a: Admission,
    }

    fn me() -> Me {
        let (sk, pk) = new_seal_keypair();
        Me { sk, pk, a: Admission::default() }
    }

    fn their_seal() -> [u8; 65] {
        new_seal_keypair().1.to_bytes().as_slice().try_into().unwrap()
    }

    fn body(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
        let mut b = vec![kind];
        for p in parts {
            b.extend_from_slice(p);
        }
        b
    }

    impl Me {
        fn take(&mut self, from: &SigningKey, counter: u64, b: &[u8]) -> Result<Admitted, Error> {
            let obj = seal(from, &self.pk, counter, b).unwrap();
            self.a.admit(&obj, &self.sk, &self.pk)
        }
        // Make `s` a contact through a real invite.
        fn befriend(&mut self, s: &SigningKey, counter: u64) {
            let secret = self.a.new_invite().unwrap();
            self.take(s, counter, &body(KIND_INVITE, &[&their_seal(), &secret])).unwrap();
        }
    }

    #[test]
    fn invite_works_once_then_messages_flow() {
        let mut m = me();
        let n = signer();
        let secret = m.a.new_invite().unwrap();
        let got = m.take(&n, 10, &body(KIND_INVITE, &[&their_seal(), &secret, b"salut"])).unwrap();
        assert_eq!(got, Admitted::NewContact { from: k33(&n), first_message: b"salut".to_vec() });
        assert_eq!(m.a.open_invites(), 0); // burned
        // Second use by another key fails, and creates no request.
        let o = signer();
        assert_eq!(m.take(&o, 1, &body(KIND_INVITE, &[&their_seal(), &secret])), Err(Error::UnknownInvite));
        assert!(m.a.inbox.pending().is_empty());
        // Messages from the new contact flow once each.
        assert!(matches!(m.take(&n, 11, &body(KIND_MESSAGE, &[b"hi"])), Ok(Admitted::Message { counter: 11, .. })));
        assert_eq!(m.take(&n, 11, &body(KIND_MESSAGE, &[b"hi"])), Err(Error::Replay));
    }

    #[test]
    fn window_starts_at_the_admitting_object() {
        // An object the stranger signed BEFORE the invite (counter 3)
        // must not arrive later as a fresh message.
        let mut m = me();
        let n = signer();
        let early = seal(&n, &m.pk, 3, &body(KIND_MESSAGE, &[b"old"])).unwrap();
        m.befriend(&n, 5);
        assert_eq!(m.a.admit(&early, &m.sk, &m.pk), Err(Error::Replay));
    }

    #[test]
    fn stranger_message_and_unknown_kind_refused() {
        let mut m = me();
        let s = signer();
        assert_eq!(m.take(&s, 1, &body(KIND_MESSAGE, &[b"hi"])), Err(Error::Stranger));
        assert_eq!(m.take(&s, 2, &body(0x09, &[b"hi"])), Err(Error::BadKind));
        assert_eq!(m.take(&s, 3, &[]), Err(Error::BadKind));
        assert!(m.a.inbox.pending().is_empty());
    }

    #[test]
    fn contact_sending_a_request_touches_nothing() {
        let mut m = me();
        let n = signer();
        m.befriend(&n, 1);
        let before = m.a.state.contacts[0].window;
        assert_eq!(m.take(&n, 2, &body(KIND_REQUEST, &[&their_seal(), b"hi"])), Err(Error::AlreadyContact));
        assert_eq!(m.a.state.contacts[0].window, before); // no bit moved
    }

    #[test]
    fn request_then_accept_uses_the_signed_key_and_counter() {
        let mut m = me();
        let s = signer();
        let seal_key = their_seal();
        assert_eq!(m.take(&s, 40, &body(KIND_REQUEST, &[&seal_key, b"bonjour"])), Ok(Admitted::Requested { from: k33(&s) }));
        assert_eq!(m.a.accept_request(&k33(&s)).unwrap(), "bonjour");
        let c = &m.a.state.contacts[0];
        assert_eq!(c.seal, seal_key);
        assert_eq!(c.window.highest(), 40);
        assert_eq!(m.take(&s, 40, &body(KIND_MESSAGE, &[b"x"])), Err(Error::Replay)); // the request itself
    }

    #[test]
    fn blocked_refused_first_and_decline_stays_quiet() {
        let mut m = me();
        let s = signer();
        m.a.block(&k33(&s)).unwrap();
        assert_eq!(m.take(&s, 1, &body(KIND_REQUEST, &[&their_seal(), b"hi"])), Err(Error::Blocked));
        let d = signer();
        m.take(&d, 1, &body(KIND_REQUEST, &[&their_seal(), b"hi"])).unwrap();
        m.a.decline_request(&k33(&d));
        assert_eq!(m.take(&d, 2, &body(KIND_REQUEST, &[&their_seal(), b"hi"])), Err(Error::Declined));
    }

    #[test]
    fn intro_goes_to_inbox_once_and_never_admits() {
        let mut m = me();
        let c = signer();
        m.befriend(&c, 1);
        let n = signer();
        let n_seal_pk = new_seal_keypair().1;
        let n_seal: [u8; 65] = n_seal_pk.to_bytes().as_slice().try_into().unwrap();
        let intro = make_intro(&c, &m.pk, n.verifying_key(), &n_seal_pk, 7);
        let b = body(KIND_INTRO, &[&intro, &n_seal, b"via C"]);
        assert_eq!(m.take(&n, 1, &b), Ok(Admitted::Requested { from: k33(&n) }));
        assert_eq!(m.a.state.contacts.len(), 1); // still only C
        assert_eq!(m.a.inbox.pending()[0].2, Some(k33(&c)));
        // The same intro again (another object) is refused by C's intro window.
        // Even after the request is gone, the same intro cannot be used again.
        m.a.inbox.accept(&k33(&n));
        assert_eq!(m.take(&n, 2, &b), Err(Error::Replay));
    }

    #[test]
    fn intro_from_non_contact_or_blocked_introducer_fails() {
        let mut m = me();
        let c = signer();
        let n = signer();
        let n_seal_pk = new_seal_keypair().1;
        let n_seal: [u8; 65] = n_seal_pk.to_bytes().as_slice().try_into().unwrap();
        let intro = make_intro(&c, &m.pk, n.verifying_key(), &n_seal_pk, 1);
        let b = body(KIND_INTRO, &[&intro, &n_seal, b"x"]);
        assert_eq!(m.take(&n, 1, &b), Err(Error::BadIntro)); // C is not a contact
        m.befriend(&c, 1);
        m.a.block(&k33(&c)).unwrap();
        assert_eq!(m.take(&n, 2, &b), Err(Error::BadIntro)); // C is blocked
        assert!(m.a.inbox.pending().is_empty());
    }

    #[test]
    fn removed_contact_is_a_stranger_and_invite_cap() {
        let mut m = me();
        let n = signer();
        m.befriend(&n, 1);
        m.a.remove_contact(&k33(&n)).unwrap();
        assert_eq!(m.take(&n, 2, &body(KIND_MESSAGE, &[b"x"])), Err(Error::Stranger));
        assert!(m.a.was_removed(&k33(&n)));
        // A removed person can still ask again, and the request says so.
        assert_eq!(m.take(&n, 3, &body(KIND_REQUEST, &[&their_seal(), b"again"])), Ok(Admitted::Requested { from: k33(&n) }));
        assert!(m.a.was_removed(&k33(&n)));
        for _ in 0..MAX_OPEN_INVITES {
            m.a.new_invite().unwrap();
        }
        assert_eq!(m.a.new_invite(), Err(Error::TooManyInvites));
        m.a.void_invites();
        assert_eq!(m.a.open_invites(), 0);
    }

    #[test]
    fn block_list_full_refuses_and_keeps_old_blocks() {
        let mut m = me();
        for i in 0..export::MAX_BLOCKS {
            let mut k = [2u8; 33];
            k[..4].copy_from_slice(&(i as u32).to_be_bytes());
            m.a.block(&k).unwrap();
        }
        assert_eq!(m.a.block(&[9; 33]), Err(Error::BlockListFull));
        assert_eq!(m.a.state.blocks.len(), export::MAX_BLOCKS);
    }

    #[test]
    fn debug_hides_words() {
        let a = Admitted::Message { from: [1; 33], counter: 2, body: b"secret".to_vec() };
        assert!(!format!("{a:?}").contains("secret"));
    }

    fn fill_contacts(m: &mut Me) {
        for i in 0..export::MAX_CONTACTS {
            let mut k = [1u8; 33];
            k[..4].copy_from_slice(&(i as u32).to_be_bytes());
            m.a.state.contacts.push(Contact { sign: k, seal: their_seal(), window: ReplayWindow::starting_at(1), tier: Tier::Confirmed, introduced_by: None });
        }
    }

    #[test]
    fn removed_then_old_request_replayed_cannot_readmit() {
        // Request(5) accepted, message(50) delivered, removed. A relay
        // replays request(5): refused. A fresh request(60) is accepted, and the
        // old message(50) replayed after that is still refused.
        let mut m = me();
        let s = signer();
        let req5 = seal(&s, &m.pk, 5, &body(KIND_REQUEST, &[&their_seal(), b"hi"])).unwrap();
        let msg50 = seal(&s, &m.pk, 50, &body(KIND_MESSAGE, &[b"once"])).unwrap();
        m.a.admit(&req5, &m.sk, &m.pk).unwrap();
        m.a.accept_request(&k33(&s)).unwrap();
        assert!(matches!(m.a.admit(&msg50, &m.sk, &m.pk), Ok(Admitted::Message { .. })));
        m.a.remove_contact(&k33(&s)).unwrap();
        assert_eq!(m.a.admit(&req5, &m.sk, &m.pk), Err(Error::Replay));
        m.take(&s, 60, &body(KIND_REQUEST, &[&their_seal(), b"again"])).unwrap();
        m.a.accept_request(&k33(&s)).unwrap();
        assert_eq!(m.a.admit(&msg50, &m.sk, &m.pk), Err(Error::Replay));
    }

    #[test]
    fn a_refused_intro_offer_does_not_burn_the_intro() {
        // The inbox refuses the first try (bad text), and the same
        // intro still works on the retry, because C's window only moves on success.
        let mut m = me();
        let c = signer();
        m.befriend(&c, 1);
        let n = signer();
        let n_pk = new_seal_keypair().1;
        let n_seal: [u8; 65] = n_pk.to_bytes().as_slice().try_into().unwrap();
        let intro = make_intro(&c, &m.pk, n.verifying_key(), &n_pk, 9);
        let bad = body(KIND_INTRO, &[&intro, &n_seal, "a\u{202E}b".as_bytes()]);
        assert_eq!(m.take(&n, 1, &bad), Err(Error::BadRequestText));
        let good = body(KIND_INTRO, &[&intro, &n_seal, b"via C"]);
        assert_eq!(m.take(&n, 2, &good), Ok(Admitted::Requested { from: k33(&n) }));
    }

    #[test]
    fn intro_gets_a_place_even_when_plain_requests_fill_32() {
        // Introductions have places of their own.
        let mut m = me();
        let c = signer();
        m.befriend(&c, 1);
        for _ in 0..inbox::MAX_PENDING {
            m.take(&signer(), 1, &body(KIND_REQUEST, &[&their_seal(), b"x"])).unwrap();
        }
        assert_eq!(m.take(&signer(), 1, &body(KIND_REQUEST, &[&their_seal(), b"x"])), Err(Error::InboxFull));
        let n = signer();
        let n_pk = new_seal_keypair().1;
        let n_seal: [u8; 65] = n_pk.to_bytes().as_slice().try_into().unwrap();
        let b = body(KIND_INTRO, &[&make_intro(&c, &m.pk, n.verifying_key(), &n_pk, 9), &n_seal, b"via C"]);
        assert_eq!(m.take(&n, 1, &b), Ok(Admitted::Requested { from: k33(&n) }));
        assert_eq!(m.a.inbox.pending()[0].0, k33(&n)); // at the top
    }

    #[test]
    fn failures_leave_state_unchanged() {
        // Contacts full. The invite stays open, the request stays waiting.
        let mut m = me();
        fill_contacts(&mut m);
        let code = m.a.new_invite().unwrap();
        let n = signer();
        assert_eq!(m.take(&n, 1, &body(KIND_INVITE, &[&their_seal(), &code])), Err(Error::ContactsFull));
        assert_eq!(m.a.open_invites(), 1);
        let s = signer();
        m.take(&s, 1, &body(KIND_REQUEST, &[&their_seal(), b"hi"])).unwrap();
        assert_eq!(m.a.accept_request(&k33(&s)), Err(Error::ContactsFull));
        assert_eq!(m.a.inbox.pending().len(), 1);
        // A bad sealing key in an invite leaves the invite open too.
        let mut bad = their_seal();
        bad[30] ^= 1;
        let mut m2 = me();
        let code2 = m2.a.new_invite().unwrap();
        assert_eq!(m2.take(&n, 1, &body(KIND_INVITE, &[&bad, &code2])), Err(Error::BadRequestKey));
        assert_eq!(m2.a.open_invites(), 1);
    }

    #[test]
    fn request_then_invite_leaves_one_contact() {
        let mut m = me();
        let s = signer();
        m.take(&s, 1, &body(KIND_REQUEST, &[&their_seal(), b"hi"])).unwrap();
        let code = m.a.new_invite().unwrap();
        m.take(&s, 2, &body(KIND_INVITE, &[&their_seal(), &code])).unwrap();
        assert!(m.a.inbox.pending().is_empty()); // the waiting request is settled
        assert_eq!(m.a.accept_request(&k33(&s)), Err(Error::Stranger));
        assert_eq!(m.a.state.contacts.len(), 1);
    }

    #[test]
    fn accept_after_block_is_refused_and_block_clears_the_request() {
        let mut m = me();
        let s = signer();
        m.take(&s, 1, &body(KIND_REQUEST, &[&their_seal(), b"hi"])).unwrap();
        // A block that reached the list some other way (a restore, say).
        m.a.state.blocks.push(k33(&s));
        assert_eq!(m.a.accept_request(&k33(&s)), Err(Error::Blocked));
        m.a.state.blocks.clear();
        m.a.block(&k33(&s)).unwrap();
        assert!(m.a.inbox.pending().is_empty());
    }

    #[test]
    fn readmit_clears_the_tombstone_and_accept_keeps_introducer() {
        let mut m = me();
        let n = signer();
        m.befriend(&n, 1);
        m.a.remove_contact(&k33(&n)).unwrap();
        m.a.remove_contact(&k33(&n)).unwrap(); // twice is fine
        let code = m.a.new_invite().unwrap();
        m.take(&n, 5, &body(KIND_INVITE, &[&their_seal(), &code])).unwrap();
        assert!(!m.a.was_removed(&k33(&n)));
        // Accept keeps who introduced them.
        let c = signer();
        m.befriend(&c, 1);
        let x = signer();
        let x_pk = new_seal_keypair().1;
        let x_seal: [u8; 65] = x_pk.to_bytes().as_slice().try_into().unwrap();
        m.take(&x, 1, &body(KIND_INTRO, &[&make_intro(&c, &m.pk, x.verifying_key(), &x_pk, 1), &x_seal, b"y"])).unwrap();
        m.a.accept_request(&k33(&x)).unwrap();
        let added = m.a.state.contacts.iter().find(|ct| ct.sign == k33(&x)).unwrap();
        assert_eq!(added.introduced_by, Some(k33(&c)));
    }

    #[test]
    fn remove_at_cap_for_an_already_removed_key_is_ok() {
        let mut m = me();
        let n = signer();
        m.befriend(&n, 1);
        m.a.remove_contact(&k33(&n)).unwrap();
        for i in 1..export::MAX_TOMBSTONES {
            let mut k = [3u8; 33];
            k[..4].copy_from_slice(&(i as u32).to_be_bytes());
            m.a.state.tombstones.push((k, 0));
        }
        assert_eq!(m.a.remove_contact(&k33(&n)), Ok(()));
        assert_eq!(m.a.remove_contact(&[9; 33]), Err(Error::TombstonesFull));
    }

    #[test]
    fn accept_refuses_a_key_that_is_already_a_contact() {
        let mut m = me();
        let s = signer();
        m.take(&s, 1, &body(KIND_REQUEST, &[&their_seal(), b"hi"])).unwrap();
        // The key became a contact by some other path while its request waited.
        m.a.state.contacts.push(Contact { sign: k33(&s), seal: their_seal(), window: ReplayWindow::starting_at(1), tier: Tier::Confirmed, introduced_by: None });
        assert_eq!(m.a.accept_request(&k33(&s)), Err(Error::AlreadyContact));
        assert_eq!(m.a.state.contacts.len(), 1);
    }

    #[test]
    fn a_second_intro_from_the_same_introducer_also_works_only_once() {
        let mut m = me();
        let c = signer();
        m.befriend(&c, 1);
        let mk = |m: &Me, n: &SigningKey, ctr: u64| {
            let pk = new_seal_keypair().1;
            let sl: [u8; 65] = pk.to_bytes().as_slice().try_into().unwrap();
            body(KIND_INTRO, &[&make_intro(&c, &m.pk, n.verifying_key(), &pk, ctr), &sl, b"hi"])
        };
        let (n1, n2) = (signer(), signer());
        let b1 = mk(&m, &n1, 9);
        m.take(&n1, 1, &b1).unwrap(); // C's first intro: makes C's window
        let b2 = mk(&m, &n2, 10);
        m.take(&n2, 1, &b2).unwrap(); // C's second intro: moves C's window
        m.a.decline_request(&k33(&n2));
        m.a.inbox.decline(&[0; 33]); // unrelated
        // n2 cannot reuse intro 10, even once its request is gone.
        let mut fresh = Admission::default();
        std::mem::swap(&mut fresh.state, &mut m.a.state); // keep windows, empty inbox
        m.a = fresh;
        assert_eq!(m.take(&n2, 2, &b2), Err(Error::Replay));
    }

    // The boundary of check_not_old. Admit with counter 5 and send
    // nothing else, so the tombstone's highest is exactly 5, then come back at 5.
    #[test]
    fn removed_at_exactly_the_admitting_counter_request() {
        let mut m = me();
        let s = signer();
        let req5 = seal(&s, &m.pk, 5, &body(KIND_REQUEST, &[&their_seal(), b"hi"])).unwrap();
        m.a.admit(&req5, &m.sk, &m.pk).unwrap();
        m.a.accept_request(&k33(&s)).unwrap();
        m.a.remove_contact(&k33(&s)).unwrap();
        assert_eq!(m.a.admit(&req5, &m.sk, &m.pk), Err(Error::Replay)); // the identical object
    }

    #[test]
    fn removed_at_exactly_the_admitting_counter_invite() {
        let mut m = me();
        let s = signer();
        let code = m.a.new_invite().unwrap();
        let inv5 = seal(&s, &m.pk, 5, &body(KIND_INVITE, &[&their_seal(), &code])).unwrap();
        m.a.admit(&inv5, &m.sk, &m.pk).unwrap();
        m.a.remove_contact(&k33(&s)).unwrap();
        assert_eq!(m.a.admit(&inv5, &m.sk, &m.pk), Err(Error::Replay));
        // A NEW invite used with the same counter 5 is refused too: only a higher one re-admits.
        let code2 = m.a.new_invite().unwrap();
        assert_eq!(m.take(&s, 5, &body(KIND_INVITE, &[&their_seal(), &code2])), Err(Error::Replay));
        assert!(matches!(m.take(&s, 6, &body(KIND_INVITE, &[&their_seal(), &code2])), Ok(Admitted::NewContact { .. })));
    }

    #[test]
    fn removed_at_exactly_the_admitting_counter_intro() {
        let mut m = me();
        let c = signer();
        m.befriend(&c, 1);
        let n = signer();
        let mk = |m: &Me, ctr: u64| {
            let pk = new_seal_keypair().1;
            let sl: [u8; 65] = pk.to_bytes().as_slice().try_into().unwrap();
            body(KIND_INTRO, &[&make_intro(&c, &m.pk, n.verifying_key(), &pk, ctr), &sl, b"hi"])
        };
        let b9 = mk(&m, 9);
        m.take(&n, 5, &b9).unwrap();
        m.a.accept_request(&k33(&n)).unwrap();
        m.a.remove_contact(&k33(&n)).unwrap();
        // A fresh intro from C (counter 10), carried in an object at N's old counter 5:
        // only the tombstone can refuse it, since C's window has never seen 10.
        let b10 = mk(&m, 10);
        assert_eq!(m.take(&n, 5, &b10), Err(Error::Replay));
        assert_eq!(m.take(&n, 6, &b10), Ok(Admitted::Requested { from: k33(&n) }));
    }

    #[test]
    fn local_bytes_round_trip_and_refuse_damage() {
        let mut m = me();
        let c = signer();
        m.befriend(&c, 3);
        m.a.new_invite().unwrap();
        let s = signer();
        m.take(&s, 9, &body(KIND_REQUEST, &[&their_seal(), "salut, ça va?".as_bytes()])).unwrap();
        m.a.decline_request(&k33(&signer()));
        let b = m.a.to_local_bytes().unwrap();
        let back = Admission::from_local_bytes(&b).unwrap();
        assert_eq!(back.to_local_bytes().unwrap(), b);
        assert_eq!(back.open_invites(), 1);
        assert_eq!(back.inbox.pending()[0].1, "salut, ça va?");
        // Trailing bytes, a truncation and a wrong label are all refused.
        let mut t = b.clone();
        t.push(0);
        assert!(Admission::from_local_bytes(&t).is_err());
        assert!(Admission::from_local_bytes(&b[..b.len() - 1]).is_err());
        let mut l = b.clone();
        l[0] ^= 1;
        assert!(Admission::from_local_bytes(&l).is_err());
        // Every single-byte truncation point fails cleanly (no panic).
        for n in 0..b.len() {
            assert!(Admission::from_local_bytes(&b[..n]).is_err());
        }
    }

    #[test]
    fn wipe_in_place_zeroes_every_list_and_spare_room() {
        let mut m = me();
        let c = signer();
        m.befriend(&c, 1);
        m.a.block(&[7; 33]).unwrap();
        m.a.remove_contact(&k33(&c)).unwrap(); // leaves an old entry in spare room
        m.a.new_invite().unwrap();
        m.take(&signer(), 1, &body(KIND_REQUEST, &[&their_seal(), b"private words"])).unwrap();
        m.a.decline_request(&[9; 33]);
        m.a.wipe_in_place();
        use crate::wipe::all_zero;
        assert!(all_zero(&m.a.state.contacts) && all_zero(&m.a.state.blocks) && all_zero(&m.a.state.tombstones));
        assert!(all_zero(&m.a.invites) && all_zero(&m.a.request_counters));
        assert!(m.a.inbox.pending().is_empty() && m.a.inbox.wiped_all_zero());
    }

    // Build saved bytes by hand-editing a real Admission, then check decode refuses.
    fn refuses(edit: impl FnOnce(&mut Admission)) {
        let mut m = me();
        let c = signer();
        m.befriend(&c, 1);
        let s = signer();
        m.take(&s, 3, &body(KIND_REQUEST, &[&their_seal(), b"hi"])).unwrap();
        edit(&mut m.a);
        let b = m.a.to_local_bytes().unwrap();
        assert_eq!(Admission::from_local_bytes(&b).err(), Some(Error::BadExport));
    }

    #[test]
    fn decode_refuses_impossible_states() {
        // A waiting request from a key that is blocked.
        refuses(|a| {
            let k = a.inbox.pending()[0].0;
            a.state.blocks.push(k);
        });
        // ... from a key that is already a contact.
        refuses(|a| {
            let k = a.inbox.pending()[0].0;
            let mut c = a.state.contacts[0].clone();
            c.sign = k;
            a.state.contacts.push(c);
        });
        // ... from a declined key.
        refuses(|a| {
            let k = a.inbox.pending()[0].0;
            a.inbox.decline_raw_for_test(k);
        });
        // A request counter no window could move past.
        refuses(|a| a.request_counters[0].1 = u64::MAX);
    }

    #[test]
    fn decode_refuses_intro_from_a_non_contact() {
        let mut m = me();
        let c = signer();
        m.befriend(&c, 1);
        let n = signer();
        let n_pk = new_seal_keypair().1;
        let n_seal: [u8; 65] = n_pk.to_bytes().as_slice().try_into().unwrap();
        m.take(&n, 1, &body(KIND_INTRO, &[&make_intro(&c, &m.pk, n.verifying_key(), &n_pk, 1), &n_seal, b"y"])).unwrap();
        m.a.state.contacts.clear(); // the introducer is gone
        let b = m.a.to_local_bytes().unwrap();
        assert_eq!(Admission::from_local_bytes(&b).err(), Some(Error::BadExport));
    }
}
