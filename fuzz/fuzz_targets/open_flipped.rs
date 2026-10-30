// Start from one REAL sealed object and change it with the fuzzer's bytes.
// This reaches deeper than random bytes: right size, right version, right hint.
#![no_main]

use arrowmem_core::{OBJECT_SIZE, SealPrivateKey, SealPublicKey};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

struct Setup {
    sk: SealPrivateKey,
    pk: SealPublicKey,
    good: Vec<u8>,
}

fn setup() -> &'static Setup {
    static S: OnceLock<Setup> = OnceLock::new();
    S.get_or_init(|| {
        use p256::elliptic_curve::Generate;
        let sender = p256::ecdsa::SigningKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap();
        let (sk, pk) = arrowmem_core::new_seal_keypair();
        let good = arrowmem_core::seal(&sender, &pk, 1, b"fuzz").unwrap();
        Setup { sk, pk, good }
    })
}

fuzz_target!(|data: &[u8]| {
    let s = setup();
    let mut obj = s.good.clone();
    // XOR the input over the object; extra input bytes wrap around.
    for (i, b) in data.iter().enumerate() {
        obj[i % OBJECT_SIZE] ^= b;
    }
    let changed = obj != s.good;
    let result = arrowmem_core::open(&obj, &s.sk, &s.pk);
    // Any change at all must be refused; no change must still open.
    assert_eq!(result.is_err(), changed);
});
