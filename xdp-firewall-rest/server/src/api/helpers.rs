use std::process::Command;
//use anyhow::Context as _;


 use aya;
 use aya::maps::loaded_maps;
// use anyhow::Context;
// use aya::programs::{Xdp, XdpFlags};
// use aya::{include_bytes_aligned, Bpf};
// use aya_log::BpfLogger;
// use aya::maps::lpm_trie::{LpmTrie, Key};



//use std::collections::HashMap;
//use aya::maps::HashMap as ayaHashMap;
//use aya::maps::PerCpuValues;
//use aya::maps::PerCpuArray;
//use aya::util::nr_cpus;

//use log::{info, warn, debug};
use log::{info};
//use tokio::signal;
//use core::net::Ipv4Addr;


pub async fn load(interface: &str, ip: &str) -> Result<(), anyhow::Error> {
    let _output = Command::new("sudo")
	//.env("RUST_LOG", "info")
	.arg("-E")
	.arg("/home/steve/git/aya_discovery/xdp-firewall-rest/target/debug/xdp-firewall")
	.arg("-i")
	.arg(interface)
	.arg("-n")
	.arg(ip)
	.spawn()
	.expect("Failed to execute command");
    Ok(())
}

// pub async fn load(iface: &str, ip: &str) -> Result<(), anyhow::Error> {
//     info!("loading debug target 00");
//     let rlim = libc::rlimit {
//         rlim_cur: libc::RLIM_INFINITY,
//         rlim_max: libc::RLIM_INFINITY,
//     };
//     info!("loading debug target 01");
//     let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
//     if ret != 0 {
//         debug!("remove limit on locked memory failed, ret is: {}", ret);
//     }
//     info!("loading debug target 03");
//     // This will include your eBPF object file as raw bytes at compile-time and load it at
//     // runtime. This approach is recommended for most real-world use cases. If you would
//     // like to specify the eBPF program at runtime rather than at compile-time, you can
//     // reach for `Bpf::load_file` instead.
//     #[cfg(debug_assertions)]
//     let mut bpf = Bpf::load(include_bytes_aligned!(
//         "../../../target/bpfel-unknown-none/debug/xdp-firewall"
//     ))?;
//     info!("loading debug target 04");
//     info!("loading debug target");
//     #[cfg(not(debug_assertions))]
//     let mut bpf = Bpf::load(include_bytes_aligned!(
//         "../../target/bpfel-unknown-none/release/xdp-firewall"
//     ))?;
//     if let Err(e) = BpfLogger::init(&mut bpf) {
//         // This can happen if you remove all log statements from your eBPF program.
//         warn!("failed to initialize eBPF logger: {}", e);
//     }

//     let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
//     info!("loading ...");
//     program.load()?;
//         info!("attaching ...");
//     let link_id = program.attach(iface, XdpFlags::default())
//         .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
//     info!("link_id: {:?}", link_id);
    
//     let mut routes : LpmTrie<_, u32, u8> =
//      	LpmTrie::try_from(bpf.map_mut("BLOCKED_IPS").unwrap())?;

//     //let ipaddr = Ipv4Addr::new(10, 0, 0, 0);
//     let ipaddr : Ipv4Addr = ip.parse().expect("parse failed") ;
//     //let ipaddr = ip.parse::<Ipv4Addr>();

//     info!("loading ip address {}", ip);
	
//     let key = Key::new(8, u32::from(ipaddr).to_be());  // <--- removed call to_be() need to talk about big endian here
//     println!("key {}", key.data());
//     routes.insert(&key, 1, 0)?;
    
//     info!("Waiting for Ctrl-C...");
//     signal::ctrl_c().await?;
//     info!("Exiting...");

//     Ok(())
// }


pub fn unload_by_interface(_interface: &str) -> Result<(), anyhow::Error> {
    // let _output = Command::new("../target/debug/xdp-firewall")
    // 	.env("RUST_LOG", "info")
    // 	.arg("-i")
    // 	.arg(interface)
    // 	.spawn()
    // 	.expect("Failed to execute command");
    info!("Trying to unload interface!");
    Ok(())
}

fn _get_loaded_maps() -> Result<(), anyhow::Error> {
    for m in loaded_maps() {
    match m {
        Ok(map) => println!("{:?}", map.name_as_str()),
        Err(e) => println!("Error iterating maps: {:?}", e),
    }
}
    Ok(())
}
    
// pub fn get_mut_maps() -> Result<(), anyhow::Error> {
//     for (_, map) in aya::bpf::maps_mut() {
// 	map.pin(pin_path)?;
//     }
//     Ok(())    
// }


// pub fn get_maps() -> Result<(), anyhow::Error> {
//     for (name, map) in aya::bpf::maps() {
// 	println!(
//             "found map `{}`",
//             name,
// 	);
//     }
//     Ok(())
// }
