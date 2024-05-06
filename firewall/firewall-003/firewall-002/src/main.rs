use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use std::collections::HashMap;
use aya::maps::HashMap as ayaHashMap;
use std::net::Ipv4Addr;
//use figment::{Figment, providers::{Serialized, Yaml, Env, Format}};
use figment::{Figment, providers::{Yaml, Format}};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct Config {
    source: Vec<IpPort>,
    destination: Vec<IpPort>,
}

#[derive(Deserialize, Debug)]
struct IpPort {
    ip_list: Vec<HashMap<String, String>>
}


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let config: IpPort  = Figment::new()
	.merge(Yaml::file("config.yaml"))
	.extract()?;

    println!("Config: {:?}", config);


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
        "../../target/bpfel-unknown-none/debug/firewall-002"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/firewall-002"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("firewall_002").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    


    // Create a map
    let mut src_ip_filter : ayaHashMap<_,  u32, u8> =
	ayaHashMap::try_from( bpf.map_mut("SRC_IP_FILTER").unwrap())?;

    // end map

    // Create map to filter destination ports
    let mut dst_port_filter : ayaHashMap<_, u32, u8> =
	ayaHashMap::try_from( bpf.map_mut("DST_PORT_FILTER").unwrap())?;

    // load the config from file and upload 
    //for (k, v)  in config {
    //println!("k : {:?} v: {:?} ", k, v);
	// for ( ip, action ) in v {
	//     if action  == "block" {
	// 	let addr : Ipv4Addr  = ip.parse().unwrap();
	// 	println!("addr {:?}" , addr);
	// 	let _ = src_ip_filter.insert(u32::from(addr), 1, 0);
	//     }
	// }
    //}

    
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
