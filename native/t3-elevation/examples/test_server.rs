//! VM test fixture, never shipped: plays T3's side of the socket with the
//! public test-vector keys.
//!
//!   test-server serve --socket PATH --mode-file FILE --log FILE
//!   test-server enrollment [--key enrolled|newDevice] [--label L] [--challenge B64URL]
//!
//! `serve` reads the mode (approve, deny, expire, bad_signature, wrong_payload,
//! cancel, close, not_mine, garbage) from the mode file for each connection
//! and appends one JSON line per connection to the log.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use t3_elevation::fixture_server::{self, Mode};
use t3_elevation::{b64, sys};

fn option(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|pair| pair[0] == name).map(|pair| pair[1].clone())
}

fn serve(args: &[String]) {
    let socket = option(args, "--socket").expect("--socket");
    let mode_file = option(args, "--mode-file").expect("--mode-file");
    let log = option(args, "--log").expect("--log");
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("bind");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    eprintln!("test-server listening on {socket}");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let text = std::fs::read_to_string(&mode_file).unwrap_or_else(|_| "approve".into());
        let mode = Mode::parse(&text).unwrap_or(Mode::Approve);
        let exchange = fixture_server::handle(stream, mode);
        let mut line = exchange.to_json();
        line["time"] = sys::now().into();
        line["mode"] = format!("{mode:?}").into();
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&log).expect("log");
        let _ = writeln!(file, "{line}");
    }
}

fn enrollment(args: &[String]) {
    let key = option(args, "--key").unwrap_or_else(|| "enrolled".into());
    let label = option(args, "--label").unwrap_or_else(|| "Test Pixel".into());
    let challenge: [u8; 32] = match option(args, "--challenge") {
        Some(text) => b64::decode(&text).and_then(|bytes| bytes.try_into().ok()).expect("32-byte challenge"),
        None => {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).expect("random");
            bytes
        }
    };
    let enrollment = fixture_server::enrollment(&key, &label, &challenge, sys::now());
    let value = serde_json::json!({
        "label": enrollment.label,
        "publicKey": enrollment.public_key,
        "challenge": enrollment.challenge,
        "attestationChain": enrollment.attestation_chain,
    });
    println!("{value}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve(&args[1..]),
        Some("enrollment") => enrollment(&args[1..]),
        _ => {
            eprintln!("usage: test-server serve|enrollment ...");
            std::process::exit(2);
        }
    }
}
