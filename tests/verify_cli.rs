// Runs the vault's verify tool as a real process, the way the companion will.
use arrowmem_core::{BackupKeys, State, export};
use std::io::Write;
use std::process::{Command, Stdio};

fn run(key_hex: &str, input: &[u8]) -> (bool, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_arrowmem-verify-export"))
        .arg(key_hex)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.success(), String::from_utf8(out.stdout).unwrap().trim().to_string())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn verify_tool_shapes() {
    let ks = BackupKeys::from_root(b"test root, never a real recovery phrase");
    let bytes = export(&State::default(), &ks, [7; 32], 4, 99).unwrap();
    let key = hex(&ks.sign_public());

    let (ok, line) = run(&key, &bytes);
    assert!(ok);
    assert_eq!(line, format!("OK epoch=4 stamp=99 bucket=16384 vault={}", "07".repeat(32)));

    let mut bad = bytes.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(run(&key, &bad), (false, "ERR BadSignature".into()));
    assert_eq!(run("zz", &bytes), (false, "ERR BadKeyArgument".into()));
    assert_eq!(run(&key, &vec![0u8; arrowmem_core::MAX_EXPORT_LEN + 1]), (false, "ERR TooLarge".into()));
    assert_eq!(run(&key, b"short"), (false, "ERR BadExport".into()));
}
