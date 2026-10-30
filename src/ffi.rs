//! The C surface the phone app calls.
//!
//! Every function: checks pointers and lengths before reading anything,
//! writes only into buffers the caller owns, never lets a panic cross into
//! the app, and refuses a second call on the same handle while one runs.

use crate::export::Key33;
use crate::*;
use hpke::{Deserializable, Serializable};
use std::cell::UnsafeCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const AM_OK: i32 = 0;
pub const AM_INTERNAL: i32 = -1; // a caught panic; the handle is now poisoned
pub const AM_BUSY: i32 = -2; // another call on this handle is running
pub const AM_BAD_ARG: i32 = -3; // null pointer, bad length, or overlapping buffers
pub const AM_TOO_SMALL: i32 = -4; // output buffer too small; *out_len holds the need
pub const AM_NO_KEY: i32 = -5; // no sealing key loaded
pub const AM_BAD_FRAGMENT: i32 = -6; // a radio fragment that is not well formed; drop it
/// Every crate Error is -100 minus its position, so the app can map it.
pub const AM_ERROR_BASE: i32 = -100;

// Largest input any function reads: one export, the biggest thing we take.
const MAX_INPUT: usize = export::MAX_EXPORT_LEN;

fn code(e: Error) -> i32 {
    AM_ERROR_BASE - e as i32
}

struct Inner {
    adm: Admission,
    seal_sk: Option<SealPrivateKey>,
    seal_pk: Option<SealPublicKey>,
}

struct AmHandle {
    busy: AtomicBool,
    poisoned: AtomicBool,
    inner: UnsafeCell<Inner>,
}

// SAFETY: `inner` is only ever touched by the one call that holds `busy`
// (with_handle), so sharing the handle between threads is sound.
unsafe impl Sync for AmHandle {}
unsafe impl Send for AmHandle {}

/// What the app holds instead of a pointer: low 32 bits are a
/// slot number, high 32 bits that slot's generation. A ticket from a freed
/// handle no longer matches, so a stale or double-freed ticket is refused
/// with AM_BAD_ARG instead of touching freed memory. 0 is never a ticket.
pub type AmId = u64;

struct Slot {
    generation: u32,
    handle: Option<Arc<AmHandle>>,
}

// The table of live handles. One lock, held only to find or change a slot,
// never while a call runs.
static TABLE: Mutex<Vec<Slot>> = Mutex::new(Vec::new());
const MAX_HANDLES: usize = 64;

fn table() -> std::sync::MutexGuard<'static, Vec<Slot>> {
    // A panic never happens while the lock is held, but if one did the table
    // itself is still consistent, so keep using it.
    TABLE.lock().unwrap_or_else(|p| p.into_inner())
}

// Reuse a free slot, or add one, up to the cap.
fn free_slot(t: &mut Vec<Slot>) -> Option<usize> {
    if let Some(i) = t.iter().position(|s| s.handle.is_none()) {
        return Some(i);
    }
    if t.len() >= MAX_HANDLES {
        return None;
    }
    t.push(Slot { generation: 1, handle: None });
    Some(t.len() - 1)
}

fn ticket(index: usize, generation: u32) -> AmId {
    ((generation as u64) << 32) | index as u64
}

fn lookup(id: AmId) -> Option<Arc<AmHandle>> {
    let (index, generation) = ((id & 0xffff_ffff) as usize, (id >> 32) as u32);
    let t = table();
    let slot = t.get(index)?;
    if slot.generation != generation {
        return None; // a freed handle's old ticket
    }
    slot.handle.clone()
}

// Run `f` on the handle: ticket check, poison check, one call at a time, and
// no panic escapes. A panic poisons the handle, because state may be half changed.
fn with_handle(id: AmId, f: impl FnOnce(&mut Inner) -> i32) -> i32 {
    let Some(handle) = lookup(id) else {
        return AM_BAD_ARG;
    };
    if handle.poisoned.load(Ordering::Acquire) {
        return AM_INTERNAL;
    }
    if handle.busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return AM_BUSY; // a second thread, or a callback calling back in
    }
    // Clears `busy` however this call ends, panics included.
    struct Release<'a>(&'a AtomicBool);
    impl Drop for Release<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _release = Release(&handle.busy);
    // SAFETY: the busy flag gives this call the only access to `inner`.
    let inner = unsafe { &mut *handle.inner.get() };
    match catch_unwind(AssertUnwindSafe(|| f(inner))) {
        Ok(code) => code,
        Err(_) => {
            handle.poisoned.store(true, Ordering::Release);
            AM_INTERNAL
        }
    }
}

// Write a value through a pointer the app gave us, which may not be aligned
// Null is refused before this is ever called.
fn put<T>(p: *mut T, v: T) {
    // SAFETY: the caller checked `p` is non-null; the app owns this slot.
    unsafe { p.write_unaligned(v) };
}

// Copy bytes into a buffer the app gave us. Null is refused before this is
// ever called, and the caller checks the buffer holds `src.len()` bytes.
fn put_bytes(dst: *mut u8, src: &[u8]) {
    // SAFETY: as above; the app owns `src.len()` writable bytes at `dst`.
    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
}

// Borrow an input buffer, after checking it. An empty input may be null.
fn input<'a>(p: *const u8, len: usize, max: usize) -> Option<&'a [u8]> {
    if len > max {
        return None;
    }
    if len == 0 {
        return Some(&[]);
    }
    if p.is_null() {
        return None;
    }
    // SAFETY: the app promises `len` readable bytes at `p` for this call.
    Some(unsafe { std::slice::from_raw_parts(p, len) })
}

fn key33(p: *const u8) -> Option<Key33> {
    input(p, 33, 33).map(|s| s.try_into().unwrap()) // exactly 33 bytes
}

// Do two byte ranges share any address?
fn overlaps(a: *const u8, a_len: usize, b: *const u8, b_len: usize) -> bool {
    let (a, b) = (a as usize, b as usize);
    a_len > 0 && b_len > 0 && a < b.saturating_add(b_len) && b < a.saturating_add(a_len)
}

// Copy `data` into the caller's buffer, or report the size it needs.
fn output(data: &[u8], out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    if out_len.is_null() {
        return AM_BAD_ARG;
    }
    put(out_len, data.len());
    if data.len() > cap {
        return AM_TOO_SMALL; // nothing written to `out`
    }
    if data.is_empty() {
        return AM_OK;
    }
    if out.is_null() {
        return AM_BAD_ARG;
    }
    // SAFETY: `cap` writable bytes at `out`, checked against the length.
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len()) };
    AM_OK
}

/// Make a new, empty handle; its ticket goes into `*out`. Free it with am_free.
#[unsafe(no_mangle)]
pub extern "C" fn am_new(out: *mut AmId) -> i32 {
    if out.is_null() {
        return AM_BAD_ARG;
    }
    let h = Arc::new(AmHandle {
        busy: AtomicBool::new(false),
        poisoned: AtomicBool::new(false),
        inner: UnsafeCell::new(Inner { adm: Admission::default(), seal_sk: None, seal_pk: None }),
    });
    let mut t = table();
    let Some(index) = free_slot(&mut t) else {
        return AM_BUSY; // too many open handles
    };
    t[index].handle = Some(h);
    put(out, ticket(index, t[index].generation));
    AM_OK
}

/// Free a handle. A ticket that is unknown, stale or already freed is refused
/// with AM_BAD_ARG; a handle with a call still running gets AM_BUSY. The
/// sealing key and all admission state wipe themselves as they are dropped.
#[unsafe(no_mangle)]
pub extern "C" fn am_free(id: AmId) -> i32 {
    let taken = {
        let mut t = table();
        let (index, generation) = ((id & 0xffff_ffff) as usize, (id >> 32) as u32);
        let Some(slot) = t.get_mut(index) else {
            return AM_BAD_ARG;
        };
        if slot.generation != generation || slot.handle.is_none() {
            return AM_BAD_ARG; // stale, or freed already
        }
        // A call is still running on it (perhaps the very callback freeing it).
        let h = slot.handle.as_ref().unwrap(); // checked just above
        if h.busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return AM_BUSY;
        }
        // From here the ticket is dead: a new handle in this slot gets a new one.
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.handle.take()
    };
    // Dropped outside the lock. Any other thread that looked it up already
    // finds `busy` set (it stays set) and gets AM_BUSY, then drops its copy;
    // the last copy dropped wipes everything.
    drop(taken);
    AM_OK
}

/// Give the handle the unwrapped sealing key (32 bytes) and its public key (65).
/// The app unwraps it with the hardware key for this session only.
#[unsafe(no_mangle)]
pub extern "C" fn am_set_seal_key(id: AmId, sk: *const u8, pk: *const u8) -> i32 {
    with_handle(id, |inner| {
        let (Some(sk), Some(pk)) = (input(sk, 32, 32), input(pk, 65, 65)) else {
            return AM_BAD_ARG;
        };
        let (Ok(sk), Ok(pk)) = (SealPrivateKey::from_bytes(sk), SealPublicKey::from_bytes(pk)) else {
            return AM_BAD_ARG;
        };
        // The pair must belong together, or nothing could ever be opened.
        if <DhP256HkdfSha256 as hpke::Kem>::sk_to_pk(&sk).to_bytes() != pk.to_bytes() {
            return AM_BAD_ARG;
        }
        inner.seal_sk = Some(sk);
        inner.seal_pk = Some(pk);
        AM_OK
    })
}

/// Load saved admission state (am_save's bytes). Replaces what is held.
/// A blob older than what this handle already holds is refused,
/// so neither the state nor the send counter can roll back.
#[unsafe(no_mangle)]
pub extern "C" fn am_load(id: AmId, p: *const u8, len: usize) -> i32 {
    with_handle(id, |inner| {
        let Some(b) = input(p, len, MAX_INPUT) else {
            return AM_BAD_ARG;
        };
        match Admission::from_local_bytes(b) {
            Ok(a) => {
                if a.generation < inner.adm.generation || a.state.own_counter < inner.adm.state.own_counter {
                    return code(Error::StaleEpoch); // `a` drops here and wipes itself
                }
                inner.adm = a; // the old one is dropped, and wipes itself
                AM_OK
            }
            Err(e) => code(e),
        }
    })
}

/// Save admission state: after every change, BEFORE showing anything, and
/// after am_seal BEFORE sending. Each save carries a higher generation.
/// The bytes are PLAINTEXT: encrypt them at rest, then wipe the buffer.
#[unsafe(no_mangle)]
pub extern "C" fn am_save(id: AmId, out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    with_handle(id, |inner| {
        let Some(next) = inner.adm.generation.checked_add(1) else {
            return code(Error::CounterExhausted);
        };
        let before = inner.adm.generation;
        inner.adm.generation = next;
        match inner.adm.to_local_bytes() {
            Ok(mut b) => {
                let rc = output(&b, out, cap, out_len);
                zeroize::Zeroize::zeroize(&mut b); // plaintext: never left behind
                if rc != AM_OK {
                    inner.adm.generation = before; // nothing was saved
                }
                rc
            }
            Err(e) => {
                inner.adm.generation = before;
                code(e)
            }
        }
    })
}

/// The signing callback: the app has its hardware sign `msg`, writes the
/// signature to `sig_out` (capacity `sig_cap`), sets `*sig_len`, and sets
/// `*format` to 0 for raw r||s or 1 for DER. Returns 0 on success.
pub type AmSignCb = extern "C" fn(ctx: *mut std::ffi::c_void, msg: *const u8, msg_len: usize, sig_out: *mut u8, sig_cap: usize, sig_len: *mut usize, format: *mut u8) -> i32;

struct CbSigner {
    cb: AmSignCb,
    ctx: *mut std::ffi::c_void,
    public: p256::ecdsa::VerifyingKey,
}

impl ExternalSigner for CbSigner {
    fn public_key(&self) -> p256::ecdsa::VerifyingKey {
        self.public
    }
    fn sign_bytes(&self, msg: &[u8]) -> Result<(Vec<u8>, SigFormat), Error> {
        let mut buf = [0u8; 80]; // DER for P-256 is at most 72 bytes
        let (mut len, mut fmt) = (0usize, 0u8);
        let rc = (self.cb)(self.ctx, msg.as_ptr(), msg.len(), buf.as_mut_ptr(), buf.len(), &mut len, &mut fmt);
        if rc != 0 || len > buf.len() {
            return Err(Error::BadSignature);
        }
        let format = match fmt {
            0 => SigFormat::Raw,
            1 => SigFormat::Der,
            _ => return Err(Error::BadSignature),
        };
        Ok((buf[..len].to_vec(), format))
    }
}

/// Seal `body` to `recipient` (65 bytes). The handle picks the counter itself
/// uses it, and writes it to `*counter_out`. The app must then
/// call am_save and store the result durably BEFORE sending the object, so a
/// crash can lose an unsent object but can never reuse a number.
/// `signer_pub` (33 bytes) is the hardware key's public half; the crate checks
/// the callback's signature against it before anything is sealed.
#[unsafe(no_mangle)]
pub extern "C" fn am_seal(
    id: AmId,
    recipient: *const u8,
    body: *const u8,
    body_len: usize,
    signer_pub: *const u8,
    cb: Option<AmSignCb>,
    ctx: *mut std::ffi::c_void,
    counter_out: *mut u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with_handle(id, |inner| {
        let (Some(rcp), Some(body_s), Some(spub), Some(cb)) = (input(recipient, 65, 65), input(body, body_len, MAX_BODY), key33(signer_pub), cb) else {
            return AM_BAD_ARG;
        };
        if counter_out.is_null() || out.is_null() || out_len.is_null() {
            return AM_BAD_ARG;
        }
        if overlaps(body, body_len, out, cap) || overlaps(recipient, 65, out, cap) {
            return AM_BAD_ARG;
        }
        // Check the output fits first, so a counter is never spent on an
        // object that then cannot be handed back.
        if cap < OBJECT_SIZE {
            put(out_len, OBJECT_SIZE);
            return AM_TOO_SMALL;
        }
        let (Ok(rcp), Ok(public)) = (SealPublicKey::from_bytes(rcp), p256::ecdsa::VerifyingKey::from_sec1_bytes(&spub)) else {
            return AM_BAD_ARG;
        };
        let Some(next) = inner.adm.state.own_counter.checked_add(1) else {
            return code(Error::CounterExhausted);
        };
        let signer = CbSigner { cb, ctx, public };
        match seal(&signer, &rcp, next, body_s) {
            Ok(obj) => {
                // Only a sealed object spends the number. If sealing failed,
                // nothing exists that could ever carry it.
                inner.adm.state.own_counter = next;
                put(counter_out, next);
                output(&obj, out, cap, out_len) // cannot fail: checked above
            }
            Err(e) => code(e),
        }
    })
}

/// Admit one sealed object. On success: `*kind` is 1 message, 2 new contact,
/// 3 request waiting; `from` (33 bytes) is the sender; `*counter` its counter;
/// the words go to `out`. Any error: drop it silently and never reply.
#[unsafe(no_mangle)]
pub extern "C" fn am_admit(
    id: AmId,
    obj: *const u8,
    obj_len: usize,
    kind: *mut u8,
    from: *mut u8,
    counter: *mut u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with_handle(id, |inner| {
        let Some(o) = input(obj, obj_len, OBJECT_SIZE) else {
            return AM_BAD_ARG;
        };
        // Every pointer is checked BEFORE admit: once admit runs, the counter
        // is marked or the invite burned, so nothing after it may fail.
        if kind.is_null() || from.is_null() || counter.is_null() || out_len.is_null() || out.is_null() {
            return AM_BAD_ARG;
        }
        if overlaps(obj, obj_len, out, cap) || overlaps(from, 33, out, cap) || overlaps(obj, obj_len, from, 33) {
            return AM_BAD_ARG;
        }
        let (Some(sk), Some(pk)) = (&inner.seal_sk, &inner.seal_pk) else {
            return AM_NO_KEY;
        };
        // Check the output fits BEFORE admitting: a message must never be
        // admitted (its counter marked) and then lost for want of a buffer.
        if cap < MAX_BODY {
            put(out_len, MAX_BODY);
            return AM_TOO_SMALL;
        }
        let (k, f, c, mut words) = match inner.adm.admit(o, sk, pk) {
            Ok(Admitted::Message { from, counter, body }) => (1u8, from, counter, body),
            Ok(Admitted::NewContact { from, first_message }) => (2, from, 0, first_message),
            Ok(Admitted::Requested { from }) => (3, from, 0, Vec::new()),
            Err(e) => return code(e),
        };
        put(kind, k);
        put(counter, c);
        put_bytes(from, &f); // checked non-null; `from` has 33 writable bytes
        let rc = output(&words, out, cap, out_len); // cannot fail: checked above
        zeroize::Zeroize::zeroize(&mut words); // the words, once copied out
        rc
    })
}

macro_rules! key_action {
    ($name:ident, $doc:literal, |$adm:ident, $k:ident| $body:expr) => {
        #[doc = $doc]
        #[unsafe(no_mangle)]
        pub extern "C" fn $name(id: AmId, key: *const u8) -> i32 {
            with_handle(id, |inner| {
                let Some($k) = key33(key) else {
                    return AM_BAD_ARG;
                };
                let $adm = &mut inner.adm;
                match $body {
                    Ok(()) => AM_OK,
                    Err(e) => code(e),
                }
            })
        }
    };
}

key_action!(am_accept, "He tapped accept on this key's request.", |a, k| a.accept_request(&k).map(|mut text| {
    zeroize::Zeroize::zeroize(&mut text); // the request text, never left in freed heap
}));
key_action!(am_decline, "He tapped decline on this key's request.", |a, k| {
    a.decline_request(&k);
    Ok::<(), Error>(())
});
key_action!(am_block, "Block this key.", |a, k| a.block(&k));
key_action!(am_remove, "Remove this contact.", |a, k| a.remove_contact(&k));

/// Was this key removed before? `*out` is 1 or 0.
#[unsafe(no_mangle)]
pub extern "C" fn am_was_removed(id: AmId, key: *const u8, out: *mut u8) -> i32 {
    with_handle(id, |inner| {
        let Some(k) = key33(key) else {
            return AM_BAD_ARG;
        };
        if out.is_null() {
            return AM_BAD_ARG;
        }
        // SAFETY: checked non-null.
        put(out, inner.adm.was_removed(&k) as u8);
        AM_OK
    })
}

/// A new one-time invite: 16 secret bytes into `out` for the QR code.
#[unsafe(no_mangle)]
pub extern "C" fn am_new_invite(id: AmId, out: *mut u8) -> i32 {
    with_handle(id, |inner| {
        if out.is_null() {
            return AM_BAD_ARG;
        }
        match inner.adm.new_invite() {
            Ok(mut code16) => {
                put_bytes(out, &code16); // checked non-null; 16 writable bytes
                zeroize::Zeroize::zeroize(&mut code16);
                AM_OK
            }
            Err(e) => code(e),
        }
    })
}

/// How many fragments one object takes on a link whose messages carry at
/// most `mtu` bytes (BLE: the negotiated ATT MTU less 3). No handle needed.
#[unsafe(no_mangle)]
pub extern "C" fn am_fragment_count(mtu: usize, count_out: *mut usize) -> i32 {
    if count_out.is_null() {
        return AM_BAD_ARG;
    }
    match frame::fragment(&[0u8; OBJECT_SIZE], mtu, 0) {
        Ok(f) => {
            put(count_out, f.len());
            AM_OK
        }
        Err(_) => AM_BAD_ARG, // mtu too small for 255 fragments
    }
}

/// Write fragment `index` of `object` for a link of message size `mtu`.
/// Send fragments 0..count with the same `frag_id`; pick a fresh random
/// `frag_id` per object. No handle needed.
#[unsafe(no_mangle)]
pub extern "C" fn am_fragment(object: *const u8, object_len: usize, mtu: usize, frag_id: u16, index: usize, out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    let Some(obj) = input(object, object_len, OBJECT_SIZE) else {
        return AM_BAD_ARG;
    };
    if out_len.is_null() || overlaps(object, object_len, out, cap) {
        return AM_BAD_ARG;
    }
    let Ok(frags) = frame::fragment(obj, mtu, frag_id) else {
        return AM_BAD_ARG; // wrong object size, or mtu too small
    };
    let Some(f) = frags.get(index) else {
        return AM_BAD_ARG;
    };
    output(f, out, cap, out_len)
}

/// A fresh random fragment id for one object, from the OS random source.
#[unsafe(no_mangle)]
pub extern "C" fn am_fragment_id(out: *mut u16) -> i32 {
    if out.is_null() {
        return AM_BAD_ARG;
    }
    let mut b = [0u8; 2];
    if getrandom::fill(&mut b).is_err() {
        return code(Error::RandomFailed);
    }
    put(out, u16::from_be_bytes(b));
    AM_OK
}

/// A reassembler ticket: one per radio link, apart from the key handles, so
/// one link's garbage never pushes out another link's fragments. Same shape
/// as AmId: slot in the low 32 bits, generation in the high 32. 0 is never one.
pub type AmReasm = u64;

struct ReasmSlot {
    generation: u32,
    reasm: Option<frame::Reassembler>,
}

// Pushing a fragment is short and calls nothing in the app, so holding this
// one lock for the whole call is fine.
static LINKS: Mutex<Vec<ReasmSlot>> = Mutex::new(Vec::new());
const MAX_LINKS: usize = 64;

fn links() -> std::sync::MutexGuard<'static, Vec<ReasmSlot>> {
    LINKS.lock().unwrap_or_else(|p| p.into_inner())
}

/// Open a reassembler for one radio link; its ticket goes into `*out`.
#[unsafe(no_mangle)]
pub extern "C" fn am_reasm_new(out: *mut AmReasm) -> i32 {
    if out.is_null() {
        return AM_BAD_ARG;
    }
    let mut t = links();
    let index = match t.iter().position(|s| s.reasm.is_none()) {
        Some(i) => i,
        None if t.len() < MAX_LINKS => {
            t.push(ReasmSlot { generation: 1, reasm: None });
            t.len() - 1
        }
        None => return AM_BUSY, // too many open links
    };
    t[index].reasm = Some(frame::Reassembler::default());
    put(out, ticket(index, t[index].generation));
    AM_OK
}

/// Close a link's reassembler. Unknown, stale or freed tickets: AM_BAD_ARG.
#[unsafe(no_mangle)]
pub extern "C" fn am_reasm_free(id: AmReasm) -> i32 {
    let mut t = links();
    let (index, generation) = ((id & 0xffff_ffff) as usize, (id >> 32) as u32);
    let Some(slot) = t.get_mut(index) else {
        return AM_BAD_ARG;
    };
    if slot.generation != generation || slot.reasm.is_none() {
        return AM_BAD_ARG;
    }
    slot.generation = slot.generation.wrapping_add(1).max(1);
    slot.reasm = None;
    AM_OK
}

/// Hand in one fragment received on this link. When it completes an object,
/// the object (OBJECT_SIZE bytes) is written to `out` and `*out_len` is set
/// to its size; otherwise `*out_len` is 0. Pass the object to am_admit.
/// `cap` must be at least OBJECT_SIZE on every call, so a completed object
/// is never lost to a short buffer. A malformed fragment is AM_BAD_FRAGMENT:
/// drop it and keep listening; anyone in radio range can send one.
#[unsafe(no_mangle)]
pub extern "C" fn am_reasm_push(id: AmReasm, frag: *const u8, frag_len: usize, out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    let Some(f) = input(frag, frag_len, OBJECT_SIZE + frame::FRAG_HEADER) else {
        return AM_BAD_ARG;
    };
    if out.is_null() || out_len.is_null() || overlaps(frag, frag_len, out, cap) {
        return AM_BAD_ARG;
    }
    let mut t = links();
    let (index, generation) = ((id & 0xffff_ffff) as usize, (id >> 32) as u32);
    let Some(slot) = t.get_mut(index).filter(|s| s.generation == generation) else {
        return AM_BAD_ARG;
    };
    let Some(r) = slot.reasm.as_mut() else {
        return AM_BAD_ARG;
    };
    if cap < OBJECT_SIZE {
        put(out_len, OBJECT_SIZE);
        return AM_TOO_SMALL;
    }
    match catch_unwind(AssertUnwindSafe(|| r.push(f))) {
        Ok(Ok(Some(obj))) => output(&obj, out, cap, out_len), // cannot fail: checked above
        Ok(Ok(None)) => {
            put(out_len, 0);
            AM_OK
        }
        Ok(Err(_)) => AM_BAD_FRAGMENT,
        Err(_) => {
            slot.reasm = Some(frame::Reassembler::default()); // start this link over
            AM_INTERNAL
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use std::ptr::{null, null_mut};

    fn handle() -> AmId {
        let mut h = 0;
        assert_eq!(am_new(&mut h), AM_OK);
        assert_ne!(h, 0);
        h
    }

    fn signer() -> SigningKey {
        use p256::elliptic_curve::Generate;
        SigningKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap()
    }

    fn ctx_of(k: &SigningKey) -> *mut std::ffi::c_void {
        k as *const SigningKey as *mut std::ffi::c_void
    }

    // The test "hardware": ctx points at a SigningKey; returns DER like a phone.
    extern "C" fn der_cb(ctx: *mut std::ffi::c_void, msg: *const u8, n: usize, out: *mut u8, cap: usize, len: *mut usize, fmt: *mut u8) -> i32 {
        let k = unsafe { &*(ctx as *const SigningKey) };
        let m = unsafe { std::slice::from_raw_parts(msg, n) };
        let sig: Signature = k.sign(m);
        let der = sig.to_der();
        let d = der.as_bytes();
        if d.len() > cap {
            return 1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(d.as_ptr(), out, d.len());
            *len = d.len();
            *fmt = 1;
        }
        0
    }

    extern "C" fn garbage_cb(_: *mut std::ffi::c_void, _: *const u8, _: usize, out: *mut u8, _: usize, len: *mut usize, fmt: *mut u8) -> i32 {
        unsafe {
            *out = 7;
            *len = 1;
            *fmt = 0;
        }
        0
    }

    extern "C" fn oversize_cb(_: *mut std::ffi::c_void, _: *const u8, _: usize, _: *mut u8, cap: usize, len: *mut usize, _: *mut u8) -> i32 {
        unsafe { *len = cap + 1 };
        0
    }

    // A callback that calls back into, or frees, the same handle.
    static REENTRY: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    static FREE_FROM_CB: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    extern "C" fn reentrant_cb(ctx: *mut std::ffi::c_void, _: *const u8, _: usize, _: *mut u8, _: usize, _: *mut usize, _: *mut u8) -> i32 {
        let id = ctx as usize as AmId;
        let mut n = 0usize;
        REENTRY.store(am_save(id, null_mut(), 0, &mut n), std::sync::atomic::Ordering::SeqCst);
        FREE_FROM_CB.store(am_free(id), std::sync::atomic::Ordering::SeqCst);
        1
    }

    fn keys_into(h: AmId) -> SealPublicKey {
        let (sk, pk) = new_seal_keypair();
        assert_eq!(am_set_seal_key(h, sk.to_bytes().as_ptr(), pk.to_bytes().as_ptr()), AM_OK);
        pk
    }

    fn pub33(k: &SigningKey) -> [u8; 33] {
        k.verifying_key().to_sec1_point(true).as_bytes().try_into().unwrap()
    }

    // Seal through the handle; returns (rc, counter used, object).
    fn seal_via(h: AmId, to: &[u8], body: &[u8], k: &SigningKey) -> (i32, u64, Vec<u8>) {
        let mut out = vec![0u8; OBJECT_SIZE];
        let (mut n, mut c) = (0usize, 0u64);
        let rc = am_seal(h, to.as_ptr(), body.as_ptr(), body.len(), pub33(k).as_ptr(), Some(der_cb), ctx_of(k), &mut c, out.as_mut_ptr(), out.len(), &mut n);
        (rc, c, out)
    }

    fn save(h: AmId) -> Vec<u8> {
        let mut need = 0;
        assert_eq!(am_save(h, null_mut(), 0, &mut need), AM_TOO_SMALL);
        let mut buf = vec![0u8; need];
        assert_eq!(am_save(h, buf.as_mut_ptr(), buf.len(), &mut need), AM_OK);
        buf
    }

    #[test]
    fn seal_with_der_callback_then_admit_end_to_end() {
        let bob = handle();
        let bob_pk = keys_into(bob);
        let alice = signer();
        let mut code16 = [0u8; 16];
        assert_eq!(am_new_invite(bob, code16.as_mut_ptr()), AM_OK);
        let invite_body = [&[KIND_INVITE][..], &new_seal_keypair().1.to_bytes(), &code16, b"salut"].concat();
        let sender = handle();
        let (rc, c, obj) = seal_via(sender, &bob_pk.to_bytes(), &invite_body, &alice);
        assert_eq!((rc, c), (AM_OK, 1)); // the handle picked counter 1
        let (mut kind, mut from, mut ctr, mut words, mut wl) = (0u8, [0u8; 33], 0u64, vec![0u8; MAX_BODY], 0usize);
        assert_eq!(am_admit(bob, obj.as_ptr(), obj.len(), &mut kind, from.as_mut_ptr(), &mut ctr, words.as_mut_ptr(), words.len(), &mut wl), AM_OK);
        assert_eq!((kind, from, &words[..wl]), (2, pub33(&alice), &b"salut"[..]));
        let rc = am_admit(bob, obj.as_ptr(), obj.len(), &mut kind, from.as_mut_ptr(), &mut ctr, words.as_mut_ptr(), words.len(), &mut wl);
        assert!(rc <= AM_ERROR_BASE); // the same object again: refused
        assert_eq!(am_free(bob), AM_OK);
        assert_eq!(am_free(sender), AM_OK);
    }

    // Send one object the way a phone does over BLE: fresh id, fragments
    // out, other end's link reassembler in, in reverse order to be unkind.
    fn over_ble(obj: &[u8], link: AmReasm) -> Vec<u8> {
        let mtu = 182;
        let (mut n, mut fid) = (0, 0);
        assert_eq!(am_fragment_count(mtu, &mut n), AM_OK);
        assert_eq!(am_fragment_id(&mut fid), AM_OK);
        let mut out = vec![0u8; OBJECT_SIZE];
        for i in (0..n).rev() {
            let (mut f, mut len, mut olen) = (vec![0u8; mtu], 0, 0);
            assert_eq!(am_fragment(obj.as_ptr(), obj.len(), mtu, fid, i, f.as_mut_ptr(), f.len(), &mut len), AM_OK);
            assert_eq!(am_reasm_push(link, f.as_ptr(), len, out.as_mut_ptr(), out.len(), &mut olen), AM_OK);
            if olen > 0 {
                assert_eq!(i, 0);
                return out;
            }
        }
        panic!("never whole");
    }

    #[test]
    fn two_phones_over_ble_c_calls_only() {
        // What the Sonim test does, start to finish, through the C surface:
        // invite by QR, new contact, then messages, each over a 182-byte link.
        let (alice, bob) = (handle(), handle());
        let alice_pk = keys_into(alice);
        let (bob_sk, bob_pk) = new_seal_keypair();
        let bob_keys = |h| assert_eq!(am_set_seal_key(h, bob_sk.to_bytes().as_ptr(), bob_pk.to_bytes().as_ptr()), AM_OK);
        bob_keys(bob);
        let (alice_hw, mut link) = (signer(), 0);
        assert_eq!(am_reasm_new(&mut link), AM_OK);
        let mut code16 = [0u8; 16];
        assert_eq!(am_new_invite(bob, code16.as_mut_ptr()), AM_OK); // bob shows the QR
        let body = [&[KIND_INVITE][..], &alice_pk.to_bytes(), &code16, b"salut"].concat();
        let (rc, _, obj) = seal_via(alice, &bob_pk.to_bytes(), &body, &alice_hw);
        assert_eq!(rc, AM_OK);
        let got = over_ble(&obj, link);
        let (mut kind, mut from, mut ctr, mut words, mut wl) = (0u8, [0u8; 33], 0u64, vec![0u8; MAX_BODY], 0usize);
        assert_eq!(am_admit(bob, got.as_ptr(), got.len(), &mut kind, from.as_mut_ptr(), &mut ctr, words.as_mut_ptr(), words.len(), &mut wl), AM_OK);
        assert_eq!((kind, from, &words[..wl]), (2, pub33(&alice_hw), &b"salut"[..]));
        // Bob's phone restarts between messages: saved state carries alice.
        let blob = save(bob);
        assert_eq!(am_free(bob), AM_OK);
        let bob = handle();
        assert_eq!(am_load(bob, blob.as_ptr(), blob.len()), AM_OK);
        bob_keys(bob);
        for (i, text) in [&b"one"[..], b"two"].into_iter().enumerate() {
            let body = [&[KIND_MESSAGE][..], text].concat();
            let (rc, c, obj) = seal_via(alice, &bob_pk.to_bytes(), &body, &alice_hw);
            assert_eq!((rc, c), (AM_OK, i as u64 + 2));
            let got = over_ble(&obj, link);
            assert_eq!(am_admit(bob, got.as_ptr(), got.len(), &mut kind, from.as_mut_ptr(), &mut ctr, words.as_mut_ptr(), words.len(), &mut wl), AM_OK);
            assert_eq!((kind, ctr, &words[..wl]), (1, c, text));
        }
        assert_eq!(am_reasm_free(link), AM_OK);
        assert_eq!(am_free(alice), AM_OK);
        assert_eq!(am_free(bob), AM_OK);
    }

    #[test]
    fn the_handle_picks_every_counter_and_never_reuses_one() {
        // 1, 2, 3, and after save and load into a new handle, 4.
        let h = handle();
        let k = signer();
        let to = new_seal_keypair().1.to_bytes();
        for want in 1..=3 {
            let (rc, c, _) = seal_via(h, &to, b"x", &k);
            assert_eq!((rc, c), (AM_OK, want));
        }
        let blob = save(h);
        let h2 = handle();
        assert_eq!(am_load(h2, blob.as_ptr(), blob.len()), AM_OK);
        assert_eq!(seal_via(h2, &to, b"x", &k).1, 4);
        // A failed seal (bad signer) spends no number.
        let mut out = vec![0u8; OBJECT_SIZE];
        let (mut n, mut c) = (0, 0);
        let rc = am_seal(h2, to.as_ptr(), b"x".as_ptr(), 1, pub33(&k).as_ptr(), Some(garbage_cb), null_mut(), &mut c, out.as_mut_ptr(), out.len(), &mut n);
        assert_eq!(rc, code(Error::BadSignature));
        assert_eq!(seal_via(h2, &to, b"x", &k).1, 5);
        am_free(h);
        am_free(h2);
    }

    #[test]
    fn an_older_blob_is_refused() {
        let h = handle();
        let k = signer();
        let to = new_seal_keypair().1.to_bytes();
        let old = save(h); // generation 1, counter 0
        seal_via(h, &to, b"x", &k);
        let newer = save(h); // generation 2, counter 1
        assert_eq!(am_load(h, old.as_ptr(), old.len()), code(Error::StaleEpoch));
        assert_eq!(am_load(h, newer.as_ptr(), newer.len()), AM_OK);
        // And the counter carries on from the newer blob.
        assert_eq!(seal_via(h, &to, b"x", &k).1, 2);
        am_free(h);
    }

    #[test]
    fn an_older_blob_with_the_same_counter_is_refused_by_generation() {
        // No seal in between, so only the generation can tell them apart:
        // the older blob lacks a block he made after it. Loading it would
        // un-block that key.
        let h = handle();
        let old = save(h);
        assert_eq!(am_block(h, [7u8; 33].as_ptr()), AM_OK);
        let newer = save(h);
        assert_eq!(am_load(h, old.as_ptr(), old.len()), code(Error::StaleEpoch));
        assert_eq!(am_load(h, newer.as_ptr(), newer.len()), AM_OK);
        am_free(h);
    }

    #[test]
    fn a_failed_save_does_not_move_the_generation() {
        let h = handle();
        let mut n = 0;
        let mut tiny = [0u8; 2];
        assert_eq!(am_save(h, tiny.as_mut_ptr(), tiny.len(), &mut n), AM_TOO_SMALL);
        let a = save(h);
        let b = save(h);
        // Generation is bytes 22..30 of the blob (after the 22-byte label).
        let generation_of = |v: &[u8]| u64::from_be_bytes(v[22..30].try_into().unwrap());
        assert_eq!((generation_of(&a), generation_of(&b)), (1, 2));
        am_free(h);
    }

    #[test]
    fn stale_and_double_freed_tickets_are_refused() {
        // no raw pointers, so a freed ticket is just a wrong number.
        let h = handle();
        assert_eq!(am_free(h), AM_OK);
        assert_eq!(am_free(h), AM_BAD_ARG); // double free
        let mut n = 0;
        assert_eq!(am_save(h, null_mut(), 0, &mut n), AM_BAD_ARG); // use after free
        // A new handle may reuse the slot, but never the ticket.
        let h2 = handle();
        assert_ne!(h2, h);
        assert_eq!(am_save(h, null_mut(), 0, &mut n), AM_BAD_ARG);
        assert_eq!(am_save(h2, null_mut(), 0, &mut n), AM_TOO_SMALL);
        assert_eq!(am_free(0), AM_BAD_ARG);
        assert_eq!(am_free(u64::MAX), AM_BAD_ARG);
        am_free(h2);
    }

    #[test]
    fn reentrant_callback_gets_busy_and_cannot_free() {
        let h = handle();
        let k = signer();
        let to = new_seal_keypair().1.to_bytes();
        let mut out = vec![0u8; OBJECT_SIZE];
        let (mut n, mut c) = (0, 0);
        let rc = am_seal(h, to.as_ptr(), b"x".as_ptr(), 1, pub33(&k).as_ptr(), Some(reentrant_cb), h as usize as *mut std::ffi::c_void, &mut c, out.as_mut_ptr(), out.len(), &mut n);
        assert_eq!(rc, code(Error::BadSignature)); // the callback failed
        assert_eq!(REENTRY.load(std::sync::atomic::Ordering::SeqCst), AM_BUSY);
        assert_eq!(FREE_FROM_CB.load(std::sync::atomic::Ordering::SeqCst), AM_BUSY);
        assert_eq!(seal_via(h, &to, b"x", &k).0, AM_OK); // still usable
        assert_eq!(am_free(h), AM_OK);
    }

    #[test]
    fn bad_callbacks_cannot_seal() {
        let h = handle();
        let pk = new_seal_keypair().1.to_bytes();
        let k = signer();
        let mut out = vec![0u8; OBJECT_SIZE];
        let (mut n, mut c) = (0, 0);
        for cb in [garbage_cb as AmSignCb, oversize_cb] {
            let rc = am_seal(h, pk.as_ptr(), b"x".as_ptr(), 1, pub33(&k).as_ptr(), Some(cb), null_mut(), &mut c, out.as_mut_ptr(), out.len(), &mut n);
            assert_eq!(rc, code(Error::BadSignature));
        }
        let other = signer();
        let rc = am_seal(h, pk.as_ptr(), b"x".as_ptr(), 1, pub33(&other).as_ptr(), Some(der_cb), ctx_of(&k), &mut c, out.as_mut_ptr(), out.len(), &mut n);
        assert_eq!(rc, code(Error::BadSignature));
        am_free(h);
    }

    #[test]
    fn null_and_bad_lengths_are_refused() {
        let h = handle();
        let mut n = 0usize;
        let mut c = 0u64;
        assert_eq!(am_new(null_mut()), AM_BAD_ARG);
        assert_eq!(am_load(h, null(), 5), AM_BAD_ARG);
        assert_eq!(am_load(h, [0u8].as_ptr(), MAX_INPUT + 1), AM_BAD_ARG);
        assert_eq!(am_save(h, null_mut(), 0, null_mut()), AM_BAD_ARG);
        assert_eq!(am_block(h, null()), AM_BAD_ARG);
        assert_eq!(am_set_seal_key(h, null(), null()), AM_BAD_ARG);
        let k = signer();
        let to = new_seal_keypair().1.to_bytes();
        let mut out = vec![0u8; OBJECT_SIZE];
        // A null counter_out is refused before anything is spent.
        let rc = am_seal(h, to.as_ptr(), b"x".as_ptr(), 1, pub33(&k).as_ptr(), Some(der_cb), ctx_of(&k), null_mut(), out.as_mut_ptr(), out.len(), &mut n);
        assert_eq!(rc, AM_BAD_ARG);
        assert_eq!(seal_via(h, &to, b"x", &k).1, 1); // still number 1
        let (mut kind, mut from, mut words) = (0u8, [0u8; 33], vec![0u8; MAX_BODY]);
        let big = vec![0u8; OBJECT_SIZE + 1];
        assert_eq!(am_admit(h, big.as_ptr(), big.len(), &mut kind, from.as_mut_ptr(), &mut c, words.as_mut_ptr(), words.len(), &mut n), AM_BAD_ARG);
        let obj = vec![0u8; OBJECT_SIZE];
        assert_eq!(am_admit(h, obj.as_ptr(), obj.len(), &mut kind, from.as_mut_ptr(), &mut c, words.as_mut_ptr(), words.len(), &mut n), AM_NO_KEY);
        am_free(h);
    }

    #[test]
    fn too_small_seal_output_spends_no_number() {
        let h = handle();
        let k = signer();
        let to = new_seal_keypair().1.to_bytes();
        let mut small = vec![0u8; OBJECT_SIZE - 1];
        let (mut n, mut c) = (0, 0);
        let rc = am_seal(h, to.as_ptr(), b"x".as_ptr(), 1, pub33(&k).as_ptr(), Some(der_cb), ctx_of(&k), &mut c, small.as_mut_ptr(), small.len(), &mut n);
        assert_eq!((rc, n), (AM_TOO_SMALL, OBJECT_SIZE));
        assert_eq!(seal_via(h, &to, b"x", &k).1, 1);
        am_free(h);
    }

    #[test]
    fn mismatched_seal_key_pair_refused() {
        let h = handle();
        let (sk, _) = new_seal_keypair();
        let (_, other_pk) = new_seal_keypair();
        assert_eq!(am_set_seal_key(h, sk.to_bytes().as_ptr(), other_pk.to_bytes().as_ptr()), AM_BAD_ARG);
        am_free(h);
    }

    #[test]
    fn too_small_output_writes_nothing_and_reports_the_need() {
        let h = handle();
        let mut need = 0usize;
        let mut small = [0xAAu8; 4];
        assert_eq!(am_save(h, small.as_mut_ptr(), small.len(), &mut need), AM_TOO_SMALL);
        assert_eq!(small, [0xAA; 4]);
        let blob = save(h);
        assert_eq!(am_load(h, blob.as_ptr(), blob.len()), AM_OK);
        keys_into(h);
        let obj = vec![0u8; OBJECT_SIZE];
        let (mut kind, mut from, mut c, mut n) = (0u8, [0u8; 33], 0u64, 0usize);
        let rc = am_admit(h, obj.as_ptr(), obj.len(), &mut kind, from.as_mut_ptr(), &mut c, small.as_mut_ptr(), small.len(), &mut n);
        assert_eq!((rc, n), (AM_TOO_SMALL, MAX_BODY));
        am_free(h);
    }

    #[test]
    fn overlap_on_body_recipient_and_object_refused() {
        let h = handle();
        keys_into(h);
        let k = signer();
        let mut buf = vec![0u8; OBJECT_SIZE + 128];
        let (mut n, mut c) = (0, 0);
        let rc = am_seal(h, new_seal_keypair().1.to_bytes().as_ptr(), buf.as_ptr(), 8, pub33(&k).as_ptr(), Some(der_cb), ctx_of(&k), &mut c, buf.as_mut_ptr(), buf.len(), &mut n);
        assert_eq!(rc, AM_BAD_ARG); // body inside output
        buf[..65].copy_from_slice(&new_seal_keypair().1.to_bytes());
        let rc = am_seal(h, buf.as_ptr(), b"x".as_ptr(), 1, pub33(&k).as_ptr(), Some(der_cb), ctx_of(&k), &mut c, buf.as_mut_ptr(), buf.len(), &mut n);
        assert_eq!(rc, AM_BAD_ARG); // a real recipient key inside output
        let (mut kind, mut from) = (0u8, [0u8; 33]);
        let mut words = vec![0u8; OBJECT_SIZE + MAX_BODY];
        let rc = am_admit(h, words.as_ptr(), OBJECT_SIZE, &mut kind, from.as_mut_ptr(), &mut c, words.as_mut_ptr(), words.len(), &mut n);
        assert_eq!(rc, AM_BAD_ARG); // object inside words
        assert_eq!(seal_via(h, &new_seal_keypair().1.to_bytes(), b"x", &k).1, 1); // nothing spent
        am_free(h);
    }

    #[test]
    fn a_panic_poisons_the_handle() {
        let h = handle();
        assert_eq!(with_handle(h, |_| panic!("test panic")), AM_INTERNAL);
        let mut n = 0;
        assert_eq!(am_save(h, null_mut(), 0, &mut n), AM_INTERNAL);
        assert_eq!(am_free(h), AM_OK); // a poisoned handle can still be freed
    }

    #[test]
    fn null_out_len_on_admit_loses_nothing() {
        let bob = handle();
        let bob_pk = keys_into(bob);
        let mut code16 = [0u8; 16];
        am_new_invite(bob, code16.as_mut_ptr());
        let body = [&[KIND_INVITE][..], &new_seal_keypair().1.to_bytes(), &code16].concat();
        let obj = seal(&signer(), &bob_pk, 1, &body).unwrap();
        let (mut kind, mut from, mut c, mut words, mut n) = (0u8, [0u8; 33], 0u64, vec![0u8; MAX_BODY], 0usize);
        assert_eq!(am_admit(bob, obj.as_ptr(), obj.len(), &mut kind, from.as_mut_ptr(), &mut c, words.as_mut_ptr(), words.len(), null_mut()), AM_BAD_ARG);
        assert_eq!(am_admit(bob, obj.as_ptr(), obj.len(), &mut kind, from.as_mut_ptr(), &mut c, null_mut(), words.len(), &mut n), AM_BAD_ARG);
        assert_eq!(am_admit(bob, obj.as_ptr(), obj.len(), &mut kind, from.as_mut_ptr(), &mut c, words.as_mut_ptr(), words.len(), &mut n), AM_OK);
        assert_eq!(kind, 2);
        am_free(bob);
    }

    #[test]
    fn every_cap_below_max_body_is_refused_before_admit() {
        let h = handle();
        keys_into(h);
        let obj = vec![0u8; OBJECT_SIZE];
        let (mut kind, mut from, mut c, mut n) = (0u8, [0u8; 33], 0u64, 0usize);
        let mut buf = vec![0u8; MAX_BODY];
        for cap in (MAX_BODY - 100)..MAX_BODY {
            let rc = am_admit(h, obj.as_ptr(), obj.len(), &mut kind, from.as_mut_ptr(), &mut c, buf.as_mut_ptr(), cap, &mut n);
            assert_eq!((rc, n), (AM_TOO_SMALL, MAX_BODY), "cap {cap}");
        }
        am_free(h);
    }

    #[test]
    fn misaligned_output_pointers_are_fine() {
        let h = handle();
        let k = signer();
        let to = new_seal_keypair().1.to_bytes();
        let mut raw = [0u8; 32];
        let odd = unsafe { raw.as_mut_ptr().add(1) };
        let mut out = vec![0u8; OBJECT_SIZE];
        let mut n = 0;
        assert_eq!(am_seal(h, to.as_ptr(), b"x".as_ptr(), 1, pub33(&k).as_ptr(), Some(der_cb), ctx_of(&k), odd as *mut u64, out.as_mut_ptr(), out.len(), &mut n), AM_OK);
        assert_eq!(unsafe { (odd as *const u64).read_unaligned() }, 1);
        assert_eq!(am_save(h, null_mut(), 0, odd as *mut usize), AM_TOO_SMALL);
        assert!(unsafe { (odd as *const usize).read_unaligned() } > 0);
        let mut id_raw = [0u8; 16];
        let odd_id = unsafe { id_raw.as_mut_ptr().add(1) } as *mut AmId;
        assert_eq!(am_new(odd_id), AM_OK);
        am_free(unsafe { odd_id.read_unaligned() });
        am_free(h);
    }

    #[test]
    fn counter_exhaustion_has_its_own_code() {
        let h = handle();
        with_handle(h, |inner| {
            inner.adm.state.own_counter = u64::MAX;
            AM_OK
        });
        let k = signer();
        let (rc, _, _) = seal_via(h, &new_seal_keypair().1.to_bytes(), b"x", &k);
        assert_eq!(rc, code(Error::CounterExhausted));
        am_free(h);
    }

    #[test]
    fn handles_are_capped() {
        // On a private table, so other tests running at the same time are not starved.
        let mut t: Vec<Slot> = Vec::new();
        let dummy = || Arc::new(AmHandle { busy: AtomicBool::new(false), poisoned: AtomicBool::new(false), inner: UnsafeCell::new(Inner { adm: Admission::default(), seal_sk: None, seal_pk: None }) });
        for _ in 0..MAX_HANDLES {
            let i = free_slot(&mut t).unwrap();
            t[i].handle = Some(dummy());
        }
        assert_eq!(free_slot(&mut t), None);
        t[5].handle = None; // freed: that slot is reused
        assert_eq!(free_slot(&mut t), Some(5));
    }

    #[test]
    fn error_codes_are_pinned() {
        use Error::*;
        let all = [
            BodyTooLong, WrongSize, WrongVersion, NotForMe, Decrypt, BadLayout, BadPadding, BadSenderKey,
            BadSignature, Replay, TooOld, JumpTooFar, BadRequestKey, BadRequestText, RequestPending, InboxFull,
            Declined, TooManyIntroduced, IntroKeyMismatch, BadIntro, Blocked, BadKind, AlreadyContact, Stranger,
            UnknownInvite, TooManyInvites, ContactsFull, BlockListFull, TombstonesFull, BadExport, StaleEpoch,
            NotPaired, WrongBackupKey, CounterExhausted, RandomFailed,
        ];
        for (i, e) in all.into_iter().enumerate() {
            assert_eq!(code(e), -100 - i as i32);
        }
    }

    #[test]
    fn object_over_a_small_radio_link() {
        let (sk, pk) = new_seal_keypair();
        let obj = seal(&signer(), &pk, 1, b"bonjour").unwrap();
        let mtu = 182; // a BLE ATT MTU of 185, less 3
        let mut n = 0;
        assert_eq!(am_fragment_count(mtu, &mut n), AM_OK);
        assert_eq!(n, OBJECT_SIZE.div_ceil(mtu - frame::FRAG_HEADER));
        let mut h = 0;
        assert_eq!(am_reasm_new(&mut h), AM_OK);
        let mut fid = 0;
        assert_eq!(am_fragment_id(&mut fid), AM_OK);
        let mut out = vec![0u8; OBJECT_SIZE];
        let mut got = None;
        for i in (0..n).rev() {
            let (mut f, mut len) = (vec![0u8; mtu], 0);
            assert_eq!(am_fragment(obj.as_ptr(), obj.len(), mtu, fid, i, f.as_mut_ptr(), f.len(), &mut len), AM_OK);
            assert!(len <= mtu);
            assert!(got.is_none());
            let mut olen = 99;
            assert_eq!(am_reasm_push(h, f.as_ptr(), len, out.as_mut_ptr(), out.len(), &mut olen), AM_OK);
            if olen > 0 {
                assert_eq!(olen, OBJECT_SIZE);
                got = Some(out.clone());
            }
        }
        assert_eq!(open(&got.unwrap(), &sk, &pk).unwrap().body(), b"bonjour");
        assert_eq!(am_reasm_free(h), AM_OK);
        assert_eq!(am_reasm_free(h), AM_BAD_ARG, "freed twice");
    }

    #[test]
    fn fragment_calls_refuse_bad_input() {
        let obj = vec![0u8; OBJECT_SIZE];
        let (mut f, mut len, mut n) = (vec![0u8; 64], 0, 0);
        assert_eq!(am_fragment_count(10, null_mut()), AM_BAD_ARG);
        assert_eq!(am_fragment_count(frame::FRAG_HEADER, &mut n), AM_BAD_ARG);
        assert_eq!(am_fragment(obj.as_ptr(), 10, 64, 1, 0, f.as_mut_ptr(), 64, &mut len), AM_BAD_ARG); // wrong size
        assert_eq!(am_fragment(obj.as_ptr(), OBJECT_SIZE, 64, 1, 99, f.as_mut_ptr(), 64, &mut len), AM_BAD_ARG); // index past count
        assert_eq!(am_fragment(obj.as_ptr(), OBJECT_SIZE, 64, 1, 0, f.as_mut_ptr(), 64, null_mut()), AM_BAD_ARG);
        assert_eq!(am_fragment(obj.as_ptr(), OBJECT_SIZE, 64, 1, 0, obj.as_ptr() as *mut u8, 64, &mut len), AM_BAD_ARG); // overlap
        assert_eq!(am_fragment(obj.as_ptr(), OBJECT_SIZE, 64, 1, 0, f.as_mut_ptr(), 10, &mut len), AM_TOO_SMALL);
        assert_eq!(len, 64);
        assert!(f.iter().all(|&b| b == 0), "nothing written when too small");
        assert_eq!(am_fragment(obj.as_ptr(), OBJECT_SIZE, 64, 1, 0, f.as_mut_ptr(), 64, &mut len), AM_OK);

        let mut h = 0;
        assert_eq!(am_reasm_new(null_mut()), AM_BAD_ARG);
        assert_eq!(am_fragment_id(null_mut()), AM_BAD_ARG);
        assert_eq!(am_reasm_new(&mut h), AM_OK);
        let mut out = vec![0u8; OBJECT_SIZE];
        let mut olen = 0;
        assert_eq!(am_reasm_push(h, f.as_ptr(), len, out.as_mut_ptr(), OBJECT_SIZE - 1, &mut olen), AM_TOO_SMALL);
        assert_eq!(olen, OBJECT_SIZE);
        assert_eq!(am_reasm_push(h, f.as_ptr(), len, null_mut(), OBJECT_SIZE, &mut olen), AM_BAD_ARG);
        assert_eq!(am_reasm_push(h, f.as_ptr(), len, out.as_mut_ptr(), OBJECT_SIZE, null_mut()), AM_BAD_ARG);
        assert_eq!(am_reasm_push(h, null(), 5, out.as_mut_ptr(), OBJECT_SIZE, &mut olen), AM_BAD_ARG);
        assert_eq!(am_reasm_push(h, f.as_ptr(), OBJECT_SIZE + frame::FRAG_HEADER + 1, out.as_mut_ptr(), OBJECT_SIZE, &mut olen), AM_BAD_ARG);
        assert_eq!(am_reasm_push(h, f.as_ptr(), 3, out.as_mut_ptr(), OBJECT_SIZE, &mut olen), AM_BAD_FRAGMENT);
        assert_eq!(am_reasm_push(0, f.as_ptr(), len, out.as_mut_ptr(), OBJECT_SIZE, &mut olen), AM_BAD_ARG);
        olen = 99;
        assert_eq!(am_reasm_push(h, f.as_ptr(), len, out.as_mut_ptr(), OBJECT_SIZE, &mut olen), AM_OK);
        assert_eq!(olen, 0, "one fragment of many completes nothing");
        assert_eq!(am_reasm_free(h), AM_OK);
        assert_eq!(am_reasm_push(h, f.as_ptr(), len, out.as_mut_ptr(), OBJECT_SIZE, &mut olen), AM_BAD_ARG, "stale ticket");
    }
}
