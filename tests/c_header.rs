//! include/arrowmem.h is written by hand, so this keeps it honest: every C
//! function in src/ffi.rs is declared there, nothing extra is, every number
//! matches the crate, and a C compiler accepts it.

use arrowmem_core::ffi::*;
use arrowmem_core::{MAX_BODY, OBJECT_SIZE};

const HEADER: &str = include_str!("../include/arrowmem.h");
const FFI: &str = include_str!("../src/ffi.rs");

fn define(name: &str) -> i64 {
    let line = HEADER.lines().find(|l| l.split_whitespace().nth(1) == Some(name)).unwrap_or_else(|| panic!("{name} missing"));
    let v = line.split_whitespace().nth(2).unwrap().trim_matches(|c| c == '(' || c == ')');
    match v.strip_prefix("0x") {
        Some(h) => i64::from_str_radix(h, 16).unwrap(),
        None => v.parse().unwrap(),
    }
}

#[test]
fn numbers_match() {
    for (name, v) in [
        ("AM_OK", AM_OK),
        ("AM_INTERNAL", AM_INTERNAL),
        ("AM_BUSY", AM_BUSY),
        ("AM_BAD_ARG", AM_BAD_ARG),
        ("AM_TOO_SMALL", AM_TOO_SMALL),
        ("AM_NO_KEY", AM_NO_KEY),
        ("AM_BAD_FRAGMENT", AM_BAD_FRAGMENT),
        ("AM_ERROR_BASE", AM_ERROR_BASE),
    ] {
        assert_eq!(define(name), v as i64, "{name}");
    }
    assert_eq!(define("AM_OBJECT_SIZE"), OBJECT_SIZE as i64);
    assert_eq!(define("AM_MAX_BODY"), MAX_BODY as i64);
    use arrowmem_core::{KIND_INTRO, KIND_INVITE, KIND_MESSAGE, KIND_REQUEST};
    for (name, v) in [("AM_KIND_MESSAGE", KIND_MESSAGE), ("AM_KIND_INVITE", KIND_INVITE), ("AM_KIND_INTRO", KIND_INTRO), ("AM_KIND_REQUEST", KIND_REQUEST)] {
        assert_eq!(define(name), v as i64, "{name}");
    }
}

#[test]
fn same_functions() {
    let mut in_rust: Vec<String> = FFI
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub extern \"C\" fn ").map(|r| r.split('(').next().unwrap().to_string()))
        .filter(|n| n != "$name")
        .collect();
    in_rust.extend(FFI.lines().filter_map(|l| l.strip_prefix("key_action!(").map(|r| r.split(',').next().unwrap().to_string())));
    in_rust.sort();
    let mut in_c: Vec<String> = HEADER
        .lines()
        .filter_map(|l| l.strip_prefix("int32_t am_").map(|r| format!("am_{}", r.split('(').next().unwrap())))
        .collect();
    in_c.sort();
    assert_eq!(in_rust, in_c);
}

#[test]
fn a_c_compiler_accepts_it() {
    let Ok(cc) = std::process::Command::new("cc")
        .args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-fsyntax-only", "-x", "c", concat!(env!("CARGO_MANIFEST_DIR"), "/include/arrowmem.h")])
        .status()
    else {
        eprintln!("no cc here: header not compiled");
        return;
    };
    assert!(cc.success());
}
