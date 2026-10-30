//! Two programs, one sealed object over plain TCP.
//!
//! Terminal 1:  cargo run --example lan -- recv 127.0.0.1:7411
//!              (prints its sealing key as hex, then waits)
//! Terminal 2:  cargo run --example lan -- send 127.0.0.1:7411 <key hex> "bonjour"
//!
//! Loopback by default. Use a LAN address only on a network you trust:
//! the object is sealed, but the port is open to that network while it waits.

use arrowmem_core::{OBJECT_SIZE, SealPublicKey, open, seal};
use hpke::{Deserializable, Serializable};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("recv") => recv(args.get(2).map_or("127.0.0.1:7411", String::as_str)),
        Some("send") if args.len() == 5 => send(&args[2], &args[3], &args[4]),
        _ => eprintln!("usage: lan recv [addr]  |  lan send <addr> <key hex> <message>"),
    }
}

fn recv(addr: &str) {
    let (sk, pk) = arrowmem_core::new_seal_keypair();
    let listener = TcpListener::bind(addr).expect("bind");
    println!("{}", to_hex(&pk.to_bytes()));
    let (mut conn, _) = listener.accept().expect("accept");
    // Every object is the same size, so we read exactly that many bytes.
    let mut object = vec![0u8; OBJECT_SIZE];
    conn.read_exact(&mut object).expect("read");
    match open(&object, &sk, &pk) {
        Ok(v) => println!("OPENED counter={} body={}", v.counter(), String::from_utf8_lossy(v.body())),
        Err(e) => println!("REFUSED {e:?}"),
    }
}

fn send(addr: &str, key_hex: &str, message: &str) {
    let recipient = SealPublicKey::from_bytes(&from_hex(key_hex)).expect("bad key hex");
    use p256::elliptic_curve::Generate;
    let me = p256::ecdsa::SigningKey::try_generate_from_rng(&mut getrandom::SysRng).expect("random");
    let object = seal(&me, &recipient, 1, message.as_bytes()).expect("seal");
    TcpStream::connect(addr).expect("connect").write_all(&object).expect("write");
    println!("SENT {} bytes", object.len());
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
}
