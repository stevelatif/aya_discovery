use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use aya::maps::lpm_trie::{LpmTrie, Key};
//use std::collections::HashMap;
//2use aya::maps::HashMap as ayaHashMap;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use core::net::Ipv4Addr;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-firewall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-firewall"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut routes : LpmTrie<_, u32, u8> =
     	LpmTrie::try_from(bpf.map_mut("ROUTES").unwrap())?;
    //let mut routes : ayaHashMap<_, u32, u8> =
     //	ayaHashMap::try_from(bpf.map_mut("ROUTES").unwrap())?;
    

    let ipaddr = Ipv4Addr::new(10, 11, 1, 1);
    //let key = Key::new(24, u32::from(ipaddr).to_be());


    let key = Key::new(24, u32::from(ipaddr));  // <--- removed call to_be() need to talk about big endian here
    println!("key {}", key.data());
    routes.insert(&key, 1, 0)?;
    //routes.insert(u32::from(ipaddr), 1, 0);
    //let kk = routes.keys();
      
    // let lookup = Key::new(32, u32::from(ipaddr).to_be());
    // let value = routes.get(&lookup, 0)?;
    // println!(" 1: {:?} " , assert_eq!(value, 1));

    // // If we were to insert a key with longer 'prefix_len'
    // // our trie should match against it.
    // let longer_key = Key::new(24, u32::from(ipaddr).to_be());
    // routes.insert(&longer_key, 2, 0)?;
    // let value = routes.get(&lookup, 0)?;
    // println!(" 2: {:?} " , assert_eq!(value, 2));

    
    //let route_local = Key::new(u32::from(Ipv4Addr::new(10,11,0,1)), 8);
    //routes.insert(&route_local, 1, 0)?;
    
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    
    info!("Exiting...");

    Ok(())
}
