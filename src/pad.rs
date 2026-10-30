//! Padding: every inner block is the same size, so length tells a relay nothing.

use crate::INNER_SIZE;

/// Fill with zero bytes up to the one fixed inner size.
pub(crate) fn pad_to_inner(inner: &mut Vec<u8>) {
    inner.resize(INNER_SIZE, 0);
}

/// Padding must be all zero, so no hidden bytes can ride along.
pub(crate) fn padding_is_zero(padding: &[u8]) -> bool {
    padding.iter().all(|&b| b == 0)
}
