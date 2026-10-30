// Runs the `lan` example as two real processes over loopback TCP.
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

// The example binary, built by cargo before this test runs.
fn lan() -> Command {
    let mut exe = std::env::current_exe().unwrap();
    exe.pop(); // deps/
    exe.pop(); // debug/
    exe.push("examples/lan");
    Command::new(exe)
}

#[test]
fn two_processes_over_tcp() {
    let addr = "127.0.0.1:47411";
    let mut recv = lan().args(["recv", addr]).stdout(Stdio::piped()).spawn().unwrap();
    let mut out = BufReader::new(recv.stdout.take().unwrap()).lines();
    let key = out.next().unwrap().unwrap(); // first line: the receiver's key

    let sent = lan().args(["send", addr, &key, "bonjour, ça va?"]).output().unwrap();
    assert!(String::from_utf8_lossy(&sent.stdout).contains("SENT 1114 bytes"));

    let line = out.next().unwrap().unwrap();
    recv.wait().unwrap();
    assert_eq!(line, "OPENED counter=1 body=bonjour, ça va?");
}
