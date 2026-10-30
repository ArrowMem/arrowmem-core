//! Carrying one sealed object over a link that sends small messages
//! (Bluetooth LE, Wi-Fi Aware): split it into fragments, put it back together.
//!
//! This layer adds no security and needs none. Every object is sealed and
//! signed, so a forged, changed or mixed-up fragment only produces an object
//! that `open` refuses. What this layer must do is stay bounded: a peer
//! sending garbage can cost at most MAX_PENDING buffers of OBJECT_SIZE.
//!
//! Fragment: [FRAME_VERSION][id: 2 bytes][index][count][payload].
//! Every fragment but the last carries ceil(OBJECT_SIZE / count) bytes; the
//! last carries the rest. The id is random per object, so it links the
//! fragments of one object and nothing else.

use crate::OBJECT_SIZE;
use std::collections::VecDeque;
use std::sync::mpsc;

pub const FRAME_VERSION: u8 = 0x01;
pub const FRAG_HEADER: usize = 5;
/// Partly received objects held at once; the oldest is dropped past this.
pub const MAX_PENDING: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The object is not OBJECT_SIZE bytes.
    WrongSize,
    /// The link's message size cannot carry the object in 255 fragments.
    MtuTooSmall,
    /// Wrong version, bad index or count, or a payload of the wrong length.
    BadFragment,
}

fn chunk_len(count: usize) -> usize {
    OBJECT_SIZE.div_ceil(count)
}

/// Split `object` into fragments of at most `mtu` bytes each.
pub fn fragment(object: &[u8], mtu: usize, id: u16) -> Result<Vec<Vec<u8>>, FrameError> {
    if object.len() != OBJECT_SIZE {
        return Err(FrameError::WrongSize);
    }
    if mtu <= FRAG_HEADER {
        return Err(FrameError::MtuTooSmall);
    }
    let count = OBJECT_SIZE.div_ceil(mtu - FRAG_HEADER);
    if count > 255 {
        return Err(FrameError::MtuTooSmall);
    }
    // Recompute from the count, so the receiver derives the same split.
    let chunk = chunk_len(count);
    let id = id.to_be_bytes();
    Ok(object
        .chunks(chunk)
        .enumerate()
        .map(|(i, part)| {
            let mut f = Vec::with_capacity(FRAG_HEADER + part.len());
            f.extend_from_slice(&[FRAME_VERSION, id[0], id[1], i as u8, count as u8]);
            f.extend_from_slice(part);
            f
        })
        .collect())
}

struct Partial {
    id: u16,
    count: u8,
    have: Vec<bool>,
    left: usize,
    buf: Vec<u8>,
}

/// Puts objects back together. Fragments may arrive in any order and
/// interleaved across objects; duplicates are ignored (first one wins). A
/// duplicate arriving after its object completed starts a new partial, which
/// ages out; the replay window refuses a repeated object above this layer.
#[derive(Default)]
pub struct Reassembler {
    pending: VecDeque<Partial>,
}

impl Reassembler {
    /// Take one fragment. Returns a whole object once its last fragment is in.
    pub fn push(&mut self, frag: &[u8]) -> Result<Option<Vec<u8>>, FrameError> {
        // Check everything about the fragment before touching any state.
        let [v, id0, id1, index, count, ..] = *frag else {
            return Err(FrameError::BadFragment);
        };
        let (id, index, count_n) = (u16::from_be_bytes([id0, id1]), index as usize, count as usize);
        if v != FRAME_VERSION || count_n == 0 || index >= count_n {
            return Err(FrameError::BadFragment);
        }
        let chunk = chunk_len(count_n);
        let start = index * chunk;
        // A count whose split leaves this index past the end is not a real split.
        if start >= OBJECT_SIZE {
            return Err(FrameError::BadFragment);
        }
        let want = chunk.min(OBJECT_SIZE - start);
        let payload = &frag[FRAG_HEADER..];
        if payload.len() != want {
            return Err(FrameError::BadFragment);
        }
        let pos = match self.pending.iter().position(|p| p.id == id && p.count == count) {
            Some(pos) => pos,
            None => {
                if self.pending.len() == MAX_PENDING {
                    self.pending.pop_front();
                }
                // Only as many fragments as the object really splits into.
                let real = OBJECT_SIZE.div_ceil(chunk);
                self.pending.push_back(Partial { id, count, have: vec![false; count_n], left: real, buf: vec![0u8; OBJECT_SIZE] });
                self.pending.len() - 1
            }
        };
        let p = &mut self.pending[pos];
        if p.have[index] {
            return Ok(None);
        }
        p.have[index] = true;
        p.buf[start..start + want].copy_from_slice(payload);
        p.left -= 1;
        if p.left > 0 {
            return Ok(None);
        }
        Ok(self.pending.remove(pos).map(|p| p.buf))
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

/// A link that moves whole sealed objects. Each radio (Wi-Fi Direct, Wi-Fi
/// Aware, Bluetooth LE, LAN) is one of these, so the rest never knows which.
pub trait Transport {
    fn send(&mut self, object: &[u8]) -> Result<(), FrameError>;
    /// The next whole object, if one has arrived.
    fn recv(&mut self) -> Option<Vec<u8>>;
}

/// Two ends of an in-memory link with a small message size, for tests and
/// for proving the layers above without a radio.
pub struct MemoryLink {
    mtu: usize,
    next_id: u16,
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    reasm: Reassembler,
}

impl MemoryLink {
    pub fn pair(mtu: usize) -> (MemoryLink, MemoryLink) {
        let (a_tx, b_rx) = mpsc::channel();
        let (b_tx, a_rx) = mpsc::channel();
        let end = |tx, rx| MemoryLink { mtu, next_id: 0, tx, rx, reasm: Reassembler::default() };
        (end(a_tx, a_rx), end(b_tx, b_rx))
    }
}

impl Transport for MemoryLink {
    fn send(&mut self, object: &[u8]) -> Result<(), FrameError> {
        self.next_id = self.next_id.wrapping_add(1);
        for f in fragment(object, self.mtu, self.next_id)? {
            let _ = self.tx.send(f); // the other end gone is a lost object, as on a radio
        }
        Ok(())
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        while let Ok(f) = self.rx.try_recv() {
            if let Ok(Some(obj)) = self.reasm.push(&f) {
                return Some(obj);
            }
        }
        None
    }
}

/// A link that is a byte stream (a Wi-Fi Aware data path, Wi-Fi Direct, a
/// LAN socket): every object is exactly OBJECT_SIZE bytes, so no framing at
/// all. Reads may come in pieces or time out part way; the bytes so far are
/// kept, so the stream never slips out of step, and only a whole object is
/// ever handed back. Set a read timeout on the stream so `recv` returns.
pub struct StreamLink<S> {
    stream: S,
    buf: Vec<u8>,
    filled: usize,
    closed: bool,
}

impl<S: std::io::Read + std::io::Write> StreamLink<S> {
    pub fn new(stream: S) -> Self {
        StreamLink { stream, buf: vec![0u8; OBJECT_SIZE], filled: 0, closed: false }
    }

    /// The other end closed the stream, or it failed. Make a new link.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl<S: std::io::Read + std::io::Write> Transport for StreamLink<S> {
    fn send(&mut self, object: &[u8]) -> Result<(), FrameError> {
        if object.len() != OBJECT_SIZE {
            return Err(FrameError::WrongSize);
        }
        // A failed write is a lost object, as on a radio; the link is done.
        if self.stream.write_all(object).and_then(|_| self.stream.flush()).is_err() {
            self.closed = true;
        }
        Ok(())
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        use std::io::ErrorKind::{Interrupted, TimedOut, WouldBlock};
        while !self.closed && self.filled < OBJECT_SIZE {
            match self.stream.read(&mut self.buf[self.filled..]) {
                Ok(0) => self.closed = true,
                Ok(n) => self.filled += n,
                Err(e) if e.kind() == Interrupted => {}
                Err(e) if matches!(e.kind(), WouldBlock | TimedOut) => return None,
                Err(_) => self.closed = true,
            }
        }
        if self.filled < OBJECT_SIZE {
            return None; // closed part way: a half object is dropped
        }
        self.filled = 0;
        Some(std::mem::replace(&mut self.buf, vec![0u8; OBJECT_SIZE]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> Vec<u8> {
        (0..OBJECT_SIZE).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn round_trip_every_mtu() {
        let obj = object();
        for mtu in [FRAG_HEADER + 5, 20, 23, 185, 244, 255, 512, OBJECT_SIZE + FRAG_HEADER, 4096] {
            let frags = fragment(&obj, mtu, 9).unwrap();
            assert!(frags.iter().all(|f| f.len() <= mtu), "mtu {mtu}");
            let mut r = Reassembler::default();
            let mut out = None;
            for f in frags.iter().rev() {
                assert!(out.is_none());
                out = r.push(f).unwrap();
            }
            assert_eq!(out.unwrap(), obj, "mtu {mtu}");
            assert_eq!(r.pending(), 0);
        }
    }

    #[test]
    fn refuses_bad_input() {
        assert_eq!(fragment(&[0u8; 10], 100, 1), Err(FrameError::WrongSize));
        assert_eq!(fragment(&object(), FRAG_HEADER, 1), Err(FrameError::MtuTooSmall));
        assert_eq!(fragment(&object(), FRAG_HEADER + 4, 1), Err(FrameError::MtuTooSmall)); // 279 fragments
        let mut r = Reassembler::default();
        let good = fragment(&object(), 100, 1).unwrap();
        let mut f = good[0].clone();
        f[0] = 2;
        assert_eq!(r.push(&f), Err(FrameError::BadFragment)); // version
        let mut f = good[0].clone();
        f[3] = f[4];
        assert_eq!(r.push(&f), Err(FrameError::BadFragment)); // index == count
        let mut f = good[0].clone();
        f[4] = 0;
        assert_eq!(r.push(&f), Err(FrameError::BadFragment)); // count 0
        let mut f = good[0].clone();
        f.pop();
        assert_eq!(r.push(&f), Err(FrameError::BadFragment)); // short payload
        assert_eq!(r.push(&good[0][..4]), Err(FrameError::BadFragment)); // short header
        assert_eq!(r.pending(), 0, "nothing refused leaves state behind");
    }

    #[test]
    fn index_past_the_real_split_is_refused() {
        // count 255 splits OBJECT_SIZE into chunks of 5, so only 223 are real.
        let mut f = vec![FRAME_VERSION, 0, 1, 250, 255];
        f.extend_from_slice(&[0u8; 5]);
        assert_eq!(Reassembler::default().push(&f), Err(FrameError::BadFragment));
    }

    #[test]
    fn duplicates_and_interleaving() {
        let (a, b) = (object(), object().iter().map(|x| !x).collect::<Vec<u8>>());
        let fa = fragment(&a, 200, 1).unwrap();
        let fb = fragment(&b, 200, 2).unwrap();
        let mut r = Reassembler::default();
        let mut got = vec![];
        for (x, y) in fa.iter().zip(&fb) {
            for f in [x, x, y] {
                if let Some(o) = r.push(f).unwrap() {
                    got.push(o);
                }
            }
        }
        assert_eq!(got, vec![a, b]);
        // The repeat of a's last fragment came after a was whole, so it starts
        // a new partial. Harmless: bounded, evicted, and a repeated object
        // would be refused by the replay window anyway.
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn same_id_other_count_is_another_partial() {
        // A fragment claiming the same id with another count must never land
        // in the first partial's buffer at the first split's offsets.
        let mut r = Reassembler::default();
        let mut a = vec![FRAME_VERSION, 0, 9, 0, 3];
        a.extend_from_slice(&[1u8; 372]); // count 3: chunks of 372
        let mut b = vec![FRAME_VERSION, 0, 9, 150, 200];
        b.extend_from_slice(&[2u8; 6]); // count 200: chunks of 6, index 150 at 900
        assert_eq!(r.push(&a), Ok(None));
        assert_eq!(r.push(&b), Ok(None));
        assert_eq!(r.pending(), 2);
    }

    #[test]
    fn bounded_under_garbage() {
        let mut r = Reassembler::default();
        for id in 0..1000u16 {
            let f = &fragment(&object(), 100, id).unwrap()[0];
            assert_eq!(r.push(f), Ok(None));
            assert!(r.pending() <= MAX_PENDING);
        }
        assert_eq!(r.pending(), MAX_PENDING);
    }

    // A stream that hands out its bytes a few at a time, with a timeout
    // between every piece, like a slow radio.
    struct Trickle {
        data: Vec<u8>,
        pos: usize,
        step: usize,
        tick: bool,
        sent: Vec<u8>,
    }

    impl std::io::Read for Trickle {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.tick = !self.tick;
            if self.tick {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let n = self.step.min(out.len()).min(self.data.len() - self.pos);
            out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n) // 0 once the data runs out: the other end closed
        }
    }

    impl std::io::Write for Trickle {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stream_link_keeps_step_through_timeouts_and_drops_a_half_object() {
        let (a, b) = (object(), object().iter().map(|x| !x).collect::<Vec<u8>>());
        let data = [&a[..], &b[..], &a[..100]].concat(); // two whole, then half of one
        let mut link = StreamLink::new(Trickle { data, pos: 0, step: 97, tick: false, sent: vec![] });
        let mut got = vec![];
        for _ in 0..200 {
            if let Some(o) = link.recv() {
                got.push(o);
            }
        }
        assert_eq!(got, vec![a.clone(), b]);
        assert!(link.is_closed());
        assert_eq!(link.send(&a[..10]), Err(FrameError::WrongSize));
        assert_eq!(link.send(&a), Ok(()));
        assert_eq!(link.stream.sent, a);
    }

    #[test]
    fn sealed_object_over_a_real_socket() {
        use std::net::{TcpListener, TcpStream};
        let (sk, pk) = crate::new_seal_keypair();
        let me = {
            use p256::elliptic_curve::Generate;
            p256::ecdsa::SigningKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap()
        };
        let obj = crate::seal(&me, &pk, 1, b"salut").unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut tx = StreamLink::new(TcpStream::connect(l.local_addr().unwrap()).unwrap());
        let s = l.accept().unwrap().0;
        s.set_read_timeout(Some(std::time::Duration::from_millis(50))).unwrap();
        let mut rx = StreamLink::new(s);
        assert!(rx.recv().is_none()); // nothing yet: times out, not stuck
        tx.send(&obj).unwrap();
        let got = (0..100).find_map(|_| rx.recv()).unwrap();
        assert_eq!(crate::open(&got, &sk, &pk).unwrap().body(), b"salut");
    }

    #[test]
    fn sealed_object_over_memory_link() {
        use p256::elliptic_curve::Generate;
        let (sk, pk) = crate::new_seal_keypair();
        let me = p256::ecdsa::SigningKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap();
        let obj = crate::seal(&me, &pk, 1, b"bonjour").unwrap();
        let (mut a, mut b) = MemoryLink::pair(185);
        assert!(b.recv().is_none());
        a.send(&obj).unwrap();
        let got = b.recv().unwrap();
        assert_eq!(crate::open(&got, &sk, &pk).unwrap().body(), b"bonjour");
        assert!(b.recv().is_none());
    }
}
