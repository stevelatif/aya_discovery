use anyhow::Context;
// use aya::{include_bytes_aligned, Bpf};
// use aya_log::BpfLogger;
// use aya::programs::XdpFlags;
// use aya::programs::Xdp;
use log::{info, warn, debug};
use std::process::Command;

pub fn load(interface: &str) -> Result<(), anyhow::Error> {
    
    let output = Command::new("../target/debug/xdp-firewall")
	.env("RUST_LOG", "info")
	.arg("-i")
	.arg("lo")
	.spawn()
	.expect("Failed to execute command");

    Ok(())
}
