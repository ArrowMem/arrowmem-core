// Throw any bytes at all at `open`. It must return an error, never crash.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// One receiver for the whole run, so each input costs only the open.
fn me() -> &'static (arrowmem_core::SealPrivateKey, arrowmem_core::SealPublicKey) {
    static ME: OnceLock<(arrowmem_core::SealPrivateKey, arrowmem_core::SealPublicKey)> = OnceLock::new();
    ME.get_or_init(arrowmem_core::new_seal_keypair)
}

fuzz_target!(|data: &[u8]| {
    let (sk, pk) = me();
    // Random bytes cannot carry a valid signature, so anything accepted is a bug.
    assert!(arrowmem_core::open(data, sk, pk).is_err());
});
