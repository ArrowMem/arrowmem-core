//! Overwriting memory we are done with, including the spare room at the end
//! of a Vec that still holds old entries after `retain` or `remove`.

use std::sync::atomic::{Ordering, compiler_fence};

/// Drop every element, then overwrite the WHOLE allocation with zeros, not
/// only the part in use. Callers wipe heap data inside elements (such as a
/// String's text) first; this then clears what the elements themselves held.
pub(crate) fn wipe_vec<T>(v: &mut Vec<T>) {
    v.clear();
    let bytes = v.capacity() * std::mem::size_of::<T>();
    let p = v.as_mut_ptr() as *mut u8;
    for i in 0..bytes {
        // SAFETY: `p` points at our own allocation of `bytes` bytes, which now
        // holds no live values. Volatile so the compiler cannot skip the writes.
        unsafe { p.add(i).write_volatile(0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read back the whole allocation (test only): every byte must be zero.
#[cfg(test)]
pub(crate) fn all_zero<T>(v: &Vec<T>) -> bool {
    let bytes = v.capacity() * std::mem::size_of::<T>();
    let p = v.as_ptr() as *const u8;
    // SAFETY: wipe_vec wrote every one of these bytes, so they are initialised.
    (0..bytes).all(|i| unsafe { p.add(i).read_volatile() } == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spare_capacity_is_wiped_too() {
        let mut v: Vec<[u8; 33]> = vec![[0xcc; 33]; 8];
        v.truncate(2); // six old entries now sit in spare capacity
        wipe_vec(&mut v);
        assert!(v.is_empty() && v.capacity() >= 8);
        assert!(all_zero(&v));
    }
}
