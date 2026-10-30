//! Request inbox: the only way a stranger's words reach the app.
//!

use crate::{Error, SealPublicKey};
use hpke::Deserializable;

/// A sender's signing key, SEC1 compressed: who a request is from.
pub type SenderKey = [u8; 33];

pub const MAX_PENDING: usize = 32;
pub const MAX_DECLINED: usize = 128;
pub const MAX_REQUEST_BYTES: usize = 280;
// One contact must not fill the inbox with intros.
pub const MAX_INTRODUCED_PER_INTRODUCER: usize = 4;
pub const MAX_INTRODUCED_TOTAL: usize = 16; // extra, on top of the 32 plain

/// Refuse request text that could fool the person reading it.
/// Allowed: valid UTF-8, at most 280 bytes, no control characters except
/// a plain newline, and no characters that flip text direction.
pub fn check_request_text(text: &[u8]) -> Result<&str, Error> {
    if text.len() > MAX_REQUEST_BYTES {
        return Err(Error::BadRequestText);
    }
    let s = std::str::from_utf8(text).map_err(|_| Error::BadRequestText)?;
    for c in s.chars() {
        // is_control covers C0 (U+0000-001F), DEL and C1 (U+0080-009F).
        let control = c.is_control() && c != '\n';
        // Bidi embeddings, overrides and isolates can make text read backwards.
        let bidi = matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
        if control || bidi || invisible(c) {
            return Err(Error::BadRequestText);
        }
    }
    Ok(s)
}

// Invisible format characters that can hide, pad or reorder text.
// U+200C and U+200D are kept: Persian, Indic scripts and emoji need them.
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' // soft hyphen
        | '\u{061C}' // Arabic letter mark
        | '\u{180E}' // Mongolian vowel separator
        | '\u{200B}' // zero-width space
        | '\u{200E}' | '\u{200F}' // left-to-right and right-to-left marks
        | '\u{2028}' | '\u{2029}' // line and paragraph separators
        | '\u{2060}'..='\u{2064}' // word joiner and invisible operators
        | '\u{206A}'..='\u{206F}' // deprecated format controls
        | '\u{FEFF}' // zero-width no-break space
        | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation
        | '\u{E0000}'..='\u{E007F}' // tag characters
    )
}

/// Requests waiting for the person to accept or decline.
#[derive(Default)]
pub struct Inbox {
    // (from, text, introduced by, sender's sealing key). Introduced requests sit
    // at the top. The sealing key came from inside the sender's
    // signed body, so a relay could not swap it.
    pending: Vec<(SenderKey, String, Option<SenderKey>, [u8; 65])>,
    // Last 128 declined keys, oldest first; the oldest falls off.
    declined: Vec<SenderKey>,
    // How many real requests were lost to a full inbox, so the person is told.
    // A sender repeating itself does not count: one key cannot bump this.
    dropped: u32,
}

impl Drop for Inbox {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl Inbox {
    /// Offer a stranger's request. `body` is the REQUEST body after the kind
    /// byte: the sender's sealing key (65), then the text. It must come from a
    /// Verified, so both are under the sender's signature. The caller has
    /// already checked that the sender is not a contact and not blocked.
    pub fn offer(&mut self, from: SenderKey, body: &[u8]) -> Result<(), Error> {
        self.offer_inner(from, body, None)
    }

    /// Offer a request that carried a valid intro from contact `by`. It still
    /// waits for the person's tap; it only goes to the top of the list.
    /// The caller has already run verify_intro, checked `by` is a current,
    /// unblocked contact, and passed the intro counter through `by`'s window.
    /// `vouched_seal` is `Intro::newcomer_seal`, the key C signed. It must equal
    /// the key in N's own body, or the person would reply to a key C never
    /// vouched for while the screen says "introduced by C".
    pub fn offer_introduced(&mut self, from: SenderKey, by: SenderKey, vouched_seal: &[u8; 65], body: &[u8]) -> Result<(), Error> {
        if body.len() >= 65 && body[..65] != vouched_seal[..] {
            return Err(Error::IntroKeyMismatch);
        }
        self.offer_inner(from, body, Some(by))
    }

    fn offer_inner(&mut self, from: SenderKey, body: &[u8], by: Option<SenderKey>) -> Result<(), Error> {
        if body.len() < 65 {
            return Err(Error::BadRequestKey);
        }
        let mut seal = [0u8; 65];
        seal.copy_from_slice(&body[..65]);
        // Must be a real P-256 point, or nobody could ever reply to it.
        SealPublicKey::from_bytes(&seal).map_err(|_| Error::BadRequestKey)?;
        let text = check_request_text(&body[65..])?;
        if self.declined.contains(&from) {
            return Err(Error::Declined); // stays quiet, nothing to show
        }
        if self.pending.iter().any(|(k, _, _, _)| *k == from) {
            return Err(Error::RequestPending);
        }
        if let Some(b) = by {
            let from_b = self.pending.iter().filter(|(_, _, x, _)| *x == Some(b)).count();
            let all = self.pending.iter().filter(|(_, _, x, _)| x.is_some()).count();
            if from_b >= MAX_INTRODUCED_PER_INTRODUCER || all >= MAX_INTRODUCED_TOTAL {
                return Err(Error::TooManyIntroduced);
            }
        }
        // 32 places for plain requests;
        // introduced requests have their own 16 (capped above), on top.
        let plain = self.pending.iter().filter(|(_, _, x, _)| x.is_none()).count();
        if by.is_none() && plain >= MAX_PENDING {
            self.dropped = self.dropped.saturating_add(1);
            return Err(Error::InboxFull); // earlier requests are never pushed out
        }
        if by.is_some() {
            // After any earlier introduced requests, before every plain one.
            let at = self.pending.iter().take_while(|(_, _, b, _)| b.is_some()).count();
            self.pending.insert(at, (from, text.to_owned(), by, seal));
        } else {
            self.pending.push((from, text.to_owned(), None, seal));
        }
        Ok(())
    }

    /// The person said no. Remember the key so a replayed request stays quiet.
    pub fn decline(&mut self, from: &SenderKey) {
        self.pending.retain(|(k, _, _, _)| k != from);
        if !self.declined.contains(from) {
            if self.declined.len() >= MAX_DECLINED {
                self.declined.remove(0); // forget the oldest
            }
            self.declined.push(*from);
        }
    }

    /// The person said yes. Returns the text and the sealing key to reply to;
    /// the app makes the contact with exactly this key, from nowhere else.
    pub fn accept(&mut self, from: &SenderKey) -> Option<(String, [u8; 65])> {
        let at = self.pending.iter().position(|(k, _, _, _)| k == from)?;
        let (_, text, _, seal) = self.pending.remove(at);
        Some((text, seal))
    }

    pub fn pending(&self) -> &[(SenderKey, String, Option<SenderKey>, [u8; 65])] {
        &self.pending
    }

    #[cfg(test)]
    pub(crate) fn wiped_all_zero(&self) -> bool {
        crate::wipe::all_zero(&self.pending) && crate::wipe::all_zero(&self.declined)
    }

    // Add to the declined ring without touching pending (test only).
    #[cfg(test)]
    pub(crate) fn decline_raw_for_test(&mut self, k: SenderKey) {
        self.declined.push(k);
    }

    pub(crate) fn is_declined(&self, k: &SenderKey) -> bool {
        self.declined.contains(k)
    }

    pub fn dropped(&self) -> u32 {
        self.dropped
    }
    /// Overwrite everything held, spare capacity included.
    pub(crate) fn wipe(&mut self) {
        use zeroize::Zeroize;
        for (_, text, _, _) in self.pending.iter_mut() {
            text.zeroize(); // the stranger's words, whole allocation
        }
        crate::wipe::wipe_vec(&mut self.pending);
        crate::wipe::wipe_vec(&mut self.declined);
        self.dropped = 0;
    }

    /// Local storage form (the app encrypts it at rest). Not an export format.
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.pending.len() as u16).to_be_bytes());
        for (from, text, by, seal) in &self.pending {
            out.extend_from_slice(from);
            out.extend_from_slice(seal);
            match by {
                Some(b) => {
                    out.push(1);
                    out.extend_from_slice(b);
                }
                None => {
                    out.push(0);
                    out.extend_from_slice(&[0u8; 33]);
                }
            }
            out.extend_from_slice(&(text.len() as u16).to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        out.extend_from_slice(&(self.declined.len() as u16).to_be_bytes());
        for k in &self.declined {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&self.dropped.to_be_bytes());
    }

    /// Read the local storage form back. Every request goes through the same
    /// checks as when it first arrived, so a damaged file cannot plant one.
    pub(crate) fn decode_from(r: &mut crate::export::Reader) -> Result<Self, Error> {
        let mut inbox = Inbox::default();
        let n = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
        if n > MAX_PENDING + MAX_INTRODUCED_TOTAL {
            return Err(Error::BadExport);
        }
        for _ in 0..n {
            let from = r.key()?;
            let seal = r.take(65)?;
            let flag = r.take(1)?[0];
            let by = r.key()?;
            let by = match flag {
                0 if by == [0u8; 33] => None,
                1 => Some(by),
                _ => return Err(Error::BadExport),
            };
            let len = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
            let body = [seal, r.take(len)?].concat();
            inbox.offer_inner(from, &body, by).map_err(|_| Error::BadExport)?;
        }
        let d = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
        if d > MAX_DECLINED {
            return Err(Error::BadExport);
        }
        for _ in 0..d {
            inbox.declined.push(r.key()?);
        }
        crate::export::no_duplicates(inbox.declined.iter().copied())?;
        inbox.dropped = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
        Ok(inbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SenderKey {
        [n; 33]
    }

    // One fixed valid sealing key for the tests (from the RFC 9180 A.3 vector).
    fn seal_key() -> [u8; 65] {
        let h = "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0";
        let mut out = [0u8; 65];
        for i in 0..65 {
            out[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    // A REQUEST body: the sender's sealing key, then the text.
    fn body(text: &[u8]) -> Vec<u8> {
        [&seal_key()[..], text].concat()
    }

    #[test]
    fn request_key_must_be_present_and_real() {
        let mut inbox = Inbox::default();
        assert_eq!(inbox.offer(key(1), &[4u8; 64]), Err(Error::BadRequestKey)); // too short
        let mut bad = body(b"hi");
        bad[10] ^= 1; // no longer on the curve
        assert_eq!(inbox.offer(key(1), &bad), Err(Error::BadRequestKey));
        assert!(inbox.offer(key(1), &body(b"")).is_ok()); // empty text is fine
    }

    #[test]
    fn text_rules() {
        assert!(check_request_text("salut, c'est Marie\nde l'école".as_bytes()).is_ok());
        assert!(check_request_text(&[b'a'; 280]).is_ok());
        assert_eq!(check_request_text(&[b'a'; 281]), Err(Error::BadRequestText));
        assert_eq!(check_request_text(&[0xff, 0xfe]), Err(Error::BadRequestText)); // not UTF-8
        assert_eq!(check_request_text(b"a\rb"), Err(Error::BadRequestText)); // C0
        assert_eq!(check_request_text("a\u{0085}b".as_bytes()), Err(Error::BadRequestText)); // C1
        assert_eq!(check_request_text(&body("a\u{202E}b".as_bytes())), Err(Error::BadRequestText)); // override
        assert_eq!(check_request_text("a\u{2066}b".as_bytes()), Err(Error::BadRequestText)); // isolate
        assert_eq!(check_request_text("a\u{2069}b".as_bytes()), Err(Error::BadRequestText)); // range end
        assert_eq!(check_request_text("a\u{202A}b".as_bytes()), Err(Error::BadRequestText)); // range start
    }

    #[test]
    fn invisible_characters_refused_at_every_edge() {
        for c in [
            '\u{00AD}', '\u{061C}', '\u{180E}', '\u{200B}', '\u{200E}', '\u{200F}', '\u{2028}', '\u{2029}',
            '\u{2060}', '\u{2064}', '\u{206A}', '\u{206F}', '\u{FEFF}', '\u{FFF9}', '\u{FFFB}', '\u{E0000}', '\u{E007F}',
        ] {
            let t = format!("a{c}b");
            assert_eq!(check_request_text(t.as_bytes()), Err(Error::BadRequestText), "U+{:04X}", c as u32);
        }
        // Just outside each range, and the two joiners, are allowed.
        for c in ['\u{200C}', '\u{200D}', '\u{2065}', '\u{FFFC}', '\u{E0080}', '\u{00AE}'] {
            let t = format!("a{c}b");
            assert!(check_request_text(t.as_bytes()).is_ok(), "U+{:04X}", c as u32);
        }
    }

    #[test]
    fn repeat_sender_does_not_bump_dropped() {
        let mut inbox = Inbox::default();
        inbox.offer(key(1), &body(b"a")).unwrap();
        for _ in 0..5 {
            assert_eq!(inbox.offer(key(1), &body(b"a")), Err(Error::RequestPending));
        }
        assert_eq!(inbox.dropped(), 0);
    }

    #[test]
    fn one_pending_per_key_and_cap() {
        let mut inbox = Inbox::default();
        inbox.offer(key(0), &body(b"hi")).unwrap();
        assert_eq!(inbox.offer(key(0), &body(b"hi again")), Err(Error::RequestPending));
        for n in 1..MAX_PENDING as u8 {
            inbox.offer(key(n), &body(b"hi")).unwrap();
        }
        assert_eq!(inbox.offer(key(200), &body(b"hi")), Err(Error::InboxFull));
        assert_eq!(inbox.pending().len(), MAX_PENDING);
        assert_eq!(inbox.pending()[0].0, key(0)); // the first was not pushed out
        assert_eq!(inbox.dropped(), 1); // only the InboxFull one
    }

    #[test]
    fn declined_stays_quiet_until_128_newer() {
        let mut inbox = Inbox::default();
        inbox.offer(key(0), &body(b"hi")).unwrap();
        inbox.decline(&key(0));
        assert!(inbox.pending().is_empty());
        assert_eq!(inbox.offer(key(0), &body(b"hi")), Err(Error::Declined)); // a replay
        for n in 1..=MAX_DECLINED as u8 {
            inbox.decline(&key(n));
        }
        assert!(inbox.offer(key(0), &body(b"hi")).is_ok()); // oldest forgotten
        assert_eq!(inbox.offer(key(1), &body(b"hi")), Err(Error::Declined)); // still held
    }

    #[test]
    fn introduced_go_to_the_top_in_order_and_still_wait() {
        let mut inbox = Inbox::default();
        inbox.offer(key(1), &body(b"plain")).unwrap();
        inbox.offer_introduced(key(2), key(9), &seal_key(), &body(b"via C")).unwrap();
        inbox.offer_introduced(key(3), key(9), &seal_key(), &body(b"via C too")).unwrap();
        inbox.offer(key(4), &body(b"plain 2")).unwrap();
        let order: Vec<u8> = inbox.pending().iter().map(|(k, _, _, _)| k[0]).collect();
        assert_eq!(order, [2, 3, 1, 4]);
        assert_eq!(inbox.pending()[0].2, Some(key(9)));
        // Still only a request: nothing is a contact until accept.
        assert_eq!(inbox.accept(&key(2)).unwrap().0, "via C");
    }

    #[test]
    fn introduced_obeys_the_same_rules() {
        let mut inbox = Inbox::default();
        inbox.decline(&key(5));
        assert_eq!(inbox.offer_introduced(key(5), key(9), &seal_key(), &body(b"hi")), Err(Error::Declined));
        assert_eq!(inbox.offer_introduced(key(6), key(9), &seal_key(), &body("a\u{202E}b".as_bytes())), Err(Error::BadRequestText));
    }

    #[test]
    fn intro_key_must_match_the_body_key() {
        let mut inbox = Inbox::default();
        let mut other = seal_key();
        other[64] ^= 1;
        assert_eq!(inbox.offer_introduced(key(1), key(9), &other, &body(b"hi")), Err(Error::IntroKeyMismatch));
        assert!(inbox.pending().is_empty());
        assert!(inbox.offer_introduced(key(1), key(9), &seal_key(), &body(b"hi")).is_ok());
    }

    #[test]
    fn introducer_caps() {
        let mut inbox = Inbox::default();
        for n in 0..4 {
            inbox.offer_introduced(key(n), key(100), &seal_key(), &body(b"x")).unwrap();
        }
        assert_eq!(inbox.offer_introduced(key(4), key(100), &seal_key(), &body(b"x")), Err(Error::TooManyIntroduced));
        // Other introducers fill the rest of the 16 introduced slots.
        for n in 4..16 {
            inbox.offer_introduced(key(n), key(101 + (n / 4)), &seal_key(), &body(b"x")).unwrap();
        }
        assert_eq!(inbox.offer_introduced(key(16), key(120), &seal_key(), &body(b"x")), Err(Error::TooManyIntroduced));
        // Plain strangers still get all 32 of their own places.
        for n in 17..17 + MAX_PENDING as u8 {
            inbox.offer(key(n), &body(b"x")).unwrap();
        }
        assert_eq!(inbox.offer(key(250), &body(b"x")), Err(Error::InboxFull));
        assert_eq!(inbox.pending().len(), MAX_PENDING + MAX_INTRODUCED_TOTAL);
    }

    #[test]
    fn accept_returns_text_once() {
        let mut inbox = Inbox::default();
        inbox.offer(key(7), &body(b"bonjour")).unwrap();
        let (text, seal) = inbox.accept(&key(7)).unwrap();
        assert_eq!(text, "bonjour");
        assert_eq!(seal, seal_key()); // the key from inside the signed body
        assert_eq!(inbox.accept(&key(7)), None);
    }

    #[test]
    fn dropped_saturates() {
        let mut inbox = Inbox::default();
        inbox.dropped = u32::MAX;
        for n in 0..=MAX_PENDING as u8 {
            let _ = inbox.offer(key(n), &body(b"a")); // the last one finds the inbox full
        }
        assert_eq!(inbox.dropped(), u32::MAX);
    }
}
