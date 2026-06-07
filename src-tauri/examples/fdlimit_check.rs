//! Verifies `raise_fd_limit()`: under a low inherited soft FD limit, it should bump
//! the soft limit to the hard limit so we can open far more than 1024 descriptors.
//!
//!   cargo build --example fdlimit_check
//!   bash -c 'ulimit -Sn 1024; <target-dir>/debug/examples/fdlimit_check'

use std::net::{TcpListener, UdpSocket};

#[cfg(unix)]
fn soft_limit() -> u64 {
    unsafe {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
        lim.rlim_cur
    }
}

fn main() {
    println!("soft FD limit BEFORE: {}", soft_limit());
    super_ip_scanner_lib::raise_fd_limit();
    println!("soft FD limit AFTER:  {}", soft_limit());

    // Open 2000 sockets — would fail with EMFILE under the original 1024 soft limit.
    let mut held: Vec<UdpSocket> = Vec::new();
    for i in 0..2000 {
        match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => held.push(s),
            Err(e) => {
                eprintln!("FAILED at socket #{i}: {e}");
                std::process::exit(1);
            }
        }
    }
    // Also prove a listener still works while holding 2000 sockets.
    let _l = TcpListener::bind("127.0.0.1:0").expect("listener");
    println!("OK: opened {} sockets after raising the limit", held.len());
}
