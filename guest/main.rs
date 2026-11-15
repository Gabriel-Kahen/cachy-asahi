// SPDX-License-Identifier: MIT
// Untested under the selected Rust 1.98.0 / emulated ARM16K runtime.
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::thread;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let directory = PathBuf::from(args.next().ok_or("private work directory required")?);
    if args.next().is_some() {
        return Err("one private directory argument required".into());
    }
    let text = directory.to_str().ok_or("literal private directory required")?;
    let nonce = text
        .strip_prefix("/home/builder/.cache/arm16k-rust-stage0-")
        .ok_or("fixed private directory required")?;
    if nonce.len() != 32
        || !nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !fs::symlink_metadata(&directory)?.is_dir()
    {
        return Err("ordinary nonce-bound private directory required".into());
    }
    let handles: Vec<_> = (1_u64..=4)
        .map(|factor| thread::spawn(move || (1_u64..=10_000).map(|n| n * factor).sum::<u64>()))
        .collect();
    let mut sum = 0_u64;
    for handle in handles {
        sum += handle.join().map_err(|_| "arithmetic thread failed")?;
    }
    if sum != 500_050_000 {
        return Err("thread arithmetic differed".into());
    }
    let payload = directory.join("rust-stage0-correctness-payload");
    let expected = format!("threads=4 arithmetic={sum}\n");
    let mut file = OpenOptions::new().write(true).create_new(true).open(&payload)?;
    file.write_all(expected.as_bytes())?;
    file.sync_all()?;
    drop(file);
    if fs::read(&payload)? != expected.as_bytes() {
        return Err("private payload readback differed".into());
    }
    fs::remove_file(&payload)?;
    println!("RUST_CORRECTNESS=PASS threads=4 arithmetic=500050000 files=ok");
    Ok(())
}
