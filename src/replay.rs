//! Replay window: refuses an object seen before, accepts late ones once.
//! 128 wide, one u128 bitmap per sender.

use crate::Error;

/// Bit i set means counter (highest - i) was already accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayWindow {
    highest: u64,
    seen: u128,
}

const WIDTH: u64 = 128;
// Largest forward leap accepted. A bigger one is a forged far-future counter
// or a sender that lost its state; either way the app asks to re-pair.
const MAX_JUMP: u64 = 1 << 20;

impl ReplayWindow {
    /// A new contact's window starts at the counter of its first object.
    pub fn starting_at(counter: u64) -> Self {
        ReplayWindow { highest: counter, seen: 1 }
    }

    /// Accept `counter` once, or say why not. Call only AFTER `open` succeeded,
    /// so a forged object can never move the window.
    pub fn check_and_mark(&mut self, counter: u64) -> Result<(), Error> {
        if counter > self.highest {
            let gap = counter - self.highest;
            if gap > MAX_JUMP {
                return Err(Error::JumpTooFar); // window left unchanged
            }
            // Shift old bits along; a jump of 128 or more forgets them all.
            self.seen = if gap >= WIDTH { 0 } else { self.seen << gap };
            self.seen |= 1; // bit 0 is the new highest
            self.highest = counter;
            return Ok(());
        }
        let back = self.highest - counter; // how far below the highest
        if back >= WIDTH {
            return Err(Error::TooOld);
        }
        let bit = 1u128 << back;
        if self.seen & bit != 0 {
            return Err(Error::Replay);
        }
        self.seen |= bit; // a late carried object, accepted once
        Ok(())
    }

    pub fn highest(&self) -> u64 {
        self.highest
    }

    /// A real window always has bit 0 set (its own highest was accepted).
    pub fn has_highest(&self) -> bool {
        self.seen & 1 == 1
    }

    /// After a restore: every counter at or below `highest` counts as seen,
    /// so nothing from before the backup can replay.
    pub fn all_seen_up_to(highest: u64) -> Self {
        ReplayWindow { highest, seen: u128::MAX }
    }

    /// 24 bytes for the app to store: highest (8) then seen (16), big-endian.
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[..8].copy_from_slice(&self.highest.to_be_bytes());
        out[8..].copy_from_slice(&self.seen.to_be_bytes());
        out
    }

    pub fn from_bytes(b: &[u8; 24]) -> Self {
        let mut h = [0u8; 8];
        let mut s = [0u8; 16];
        h.copy_from_slice(&b[..8]);
        s.copy_from_slice(&b[8..]);
        ReplayWindow { highest: u64::from_be_bytes(h), seen: u128::from_be_bytes(s) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_then_replay_refused() {
        let mut w = ReplayWindow::starting_at(1);
        assert_eq!(w.check_and_mark(1), Err(Error::Replay));
        assert_eq!(w.check_and_mark(2), Ok(()));
        assert_eq!(w.check_and_mark(2), Err(Error::Replay));
    }

    #[test]
    fn late_arrival_accepted_once() {
        let mut w = ReplayWindow::starting_at(10);
        w.check_and_mark(20).unwrap();
        assert_eq!(w.check_and_mark(15), Ok(())); // carried, arrives late
        assert_eq!(w.check_and_mark(15), Err(Error::Replay));
    }

    #[test]
    fn edge_of_the_window() {
        let mut w = ReplayWindow::starting_at(0);
        w.check_and_mark(200).unwrap();
        assert_eq!(w.check_and_mark(200 - 127), Ok(())); // last slot inside
        assert_eq!(w.check_and_mark(200 - 128), Err(Error::TooOld)); // first slot outside
    }

    #[test]
    fn big_jump_forgets_old_bits() {
        let mut w = ReplayWindow::starting_at(5);
        w.check_and_mark(5 + 200).unwrap();
        // 5 is now far outside, so it is too old, not a replay.
        assert_eq!(w.check_and_mark(5), Err(Error::TooOld));
        // Slots that were never seen inside the new window are open.
        assert_eq!(w.check_and_mark(5 + 199), Ok(()));
    }

    #[test]
    fn gap_of_exactly_127_keeps_the_old_bit() {
        let mut w = ReplayWindow::starting_at(0);
        w.check_and_mark(127).unwrap();
        assert_eq!(w.check_and_mark(0), Err(Error::Replay));
    }

    #[test]
    fn jump_of_exactly_128_clears_everything() {
        let mut w = ReplayWindow::starting_at(0);
        w.check_and_mark(128).unwrap();
        assert_eq!(w.check_and_mark(0), Err(Error::TooOld));
        assert_eq!(w.check_and_mark(1), Ok(())); // never seen, inside the window
    }

    #[test]
    fn jump_of_129_clears_everything() {
        let mut w = ReplayWindow::starting_at(0);
        w.check_and_mark(129).unwrap();
        assert_eq!(w.check_and_mark(1), Err(Error::TooOld));
        assert_eq!(w.check_and_mark(2), Ok(()));
    }

    // Two bits set before each jump, so a wrong shift cannot hide behind
    // `|= 1` (the release build masks a shift of 128 to 0).
    fn two_bits() -> ReplayWindow {
        let mut w = ReplayWindow::starting_at(0);
        w.check_and_mark(1).unwrap(); // bits for counters 0 and 1
        w
    }

    #[test]
    fn two_bits_then_gap_127_keeps_counter_1() {
        let mut w = two_bits();
        w.check_and_mark(128).unwrap(); // gap 127
        assert_eq!(w.check_and_mark(1), Err(Error::Replay)); // now 127 back, still seen
        assert_eq!(w.check_and_mark(2), Ok(()));
        assert_eq!(w.check_and_mark(0), Err(Error::TooOld));
    }

    #[test]
    fn two_bits_then_gap_128_clears() {
        let mut w = two_bits();
        w.check_and_mark(129).unwrap(); // gap exactly 128
        assert_eq!(w.check_and_mark(128), Ok(())); // never seen
        assert_eq!(w.check_and_mark(1), Err(Error::TooOld));
    }

    #[test]
    fn two_bits_then_gap_129_clears() {
        let mut w = two_bits();
        w.check_and_mark(130).unwrap(); // gap 129
        assert_eq!(w.check_and_mark(129), Ok(()));
        assert_eq!(w.check_and_mark(3), Ok(()));
        assert_eq!(w.check_and_mark(2), Err(Error::TooOld));
    }

    #[test]
    fn forward_jump_cap() {
        let mut w = ReplayWindow::starting_at(10);
        let before = w;
        assert_eq!(w.check_and_mark(10 + MAX_JUMP + 1), Err(Error::JumpTooFar));
        assert_eq!(w, before); // a refused jump moves nothing
        assert_eq!(w.check_and_mark(u64::MAX), Err(Error::JumpTooFar));
        assert_eq!(w.check_and_mark(10 + MAX_JUMP), Ok(())); // exactly the cap is fine
    }

    #[test]
    fn bytes_round_trip() {
        let mut w = ReplayWindow::starting_at(3);
        w.check_and_mark(9).unwrap();
        assert_eq!(ReplayWindow::from_bytes(&w.to_bytes()), w);
    }
}
