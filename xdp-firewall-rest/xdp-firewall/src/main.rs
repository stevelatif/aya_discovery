use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use aya::maps::lpm_trie::{LpmTrie, Key};
//use std::collections::HashMap;
//use aya::maps::HashMap as ayaHashMap;
//use aya::maps::PerCpuValues;
//use aya::maps::PerCpuArray;
//use aya::util::nr_cpus;

use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use core::net::Ipv4Addr;


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short='i', long="if", default_value = "eth0")]
    iface: String,
    #[clap(short='n', long="ip", default_value = "127.0.0.1")]
    ip: String,
}

//#[tokio::main]
fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    //load(&opt.iface).await;
    let _ = load(&opt.iface, &opt.ip);
    Ok(())
}

#[tokio::main]
async fn load(iface: &str, ip: &str) -> Result<(), anyhow::Error> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    info!("loading xdp-firewall BPF if:{},  ip:{}", iface, ip);
    
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    info!("BPF load 00");
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-firewall"
    ))?;
    info!("BPF load 01");
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-firewall"
    ))?;
    info!("BPF logger init");
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    info!("unwrapping xdp-firewall BPF");
    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
        info!("loading xdp-firewall BPF");
    program.load()?;
        info!("attaching xdp-firewall BPF");
    let link_id = program.attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    info!("link_id: {:?}", link_id);
    
    let mut routes : LpmTrie<_, u32, u8> =
     	LpmTrie::try_from(bpf.map_mut("BLOCKED_IPS").unwrap())?;

    let ipaddr : Ipv4Addr = ip.parse().expect("parse failed") ;
    //let ipaddr = Ipv4Addr::new(10, 0, 0, 0);

    let key = Key::new(8, u32::from(ipaddr).to_be());  // <--- removed call to_be() need to talk about big endian here
    println!("key {}", key.data());
    routes.insert(&key, 1, 0)?;
    
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
