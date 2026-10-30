//! For the vault (the home companion): check one export without decrypting it.
//!
//!   arrowmem-verify-export <registered backup key, 66 hex chars> < export.bin
//!
//! Prints exactly one line and exits 0 or 1:
//!   OK epoch=<n> stamp=<n> bucket=<n> vault=<64 hex>
//!   ERR <reason>
//! The companion then compares the epoch and stores the bytes. Nothing else.

use std::io::Read;

fn main() {
    let line = run();
    let ok = line.starts_with("OK ");
    println!("{line}");
    std::process::exit(if ok { 0 } else { 1 });
}

fn run() -> String {
    let args: Vec<String> = std::env::args().collect();
    let Some(key) = args.get(1).and_then(|h| from_hex(h)).and_then(|k| <[u8; 33]>::try_from(k).ok()) else {
        return "ERR BadKeyArgument".into();
    };
    // Read at most one byte past the cap, so an oversized input is refused unread.
    let mut bytes = Vec::new();
    let cap = arrowmem_core::MAX_EXPORT_LEN as u64 + 1;
    if std::io::stdin().take(cap).read_to_end(&mut bytes).is_err() {
        return "ERR ReadFailed".into();
    }
    if bytes.len() > arrowmem_core::MAX_EXPORT_LEN {
        return "ERR TooLarge".into();
    }
    match arrowmem_core::verify_export(&bytes, &key) {
        Ok(h) => format!("OK epoch={} stamp={} bucket={} vault={}", h.epoch, h.stamp, h.bucket, to_hex(&h.vault_id)),
        Err(e) => format!("ERR {e:?}"),
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}
