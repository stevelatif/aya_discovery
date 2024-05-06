use anyhow::Context;
use aya::programs::{Xdp, XdpFlags, links::FdLink};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use std::collections::HashMap;
use aya::maps::HashMap as ayaHashMap;
use std::net::Ipv4Addr;
use figment::{Figment, providers::{Yaml, Format}};
use std::path::Path;
use aya::{BpfLoader, Btf};


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let config: HashMap<String,String> = Figment::new()
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
    // #[cfg(debug_assertions)]
    // let mut bpf = Bpf::load(include_bytes_aligned!(
    //     "../../target/bpfel-unknown-none/debug/firewall-002"
    // ))?;
    // #[cfg(not(debug_assertions))]
    // let mut bpf = Bpf::load(include_bytes_aligned!(
    //     "../../target/bpfel-unknown-none/release/firewall-002"
    // ))?;

    // Use the bpfloader to load the map
    let mut bpf = BpfLoader::new()
    // load the BTF data from /sys/kernel/btf/vmlinux
    .btf(Btf::from_sys_fs().ok().as_ref())
    // load pinned maps from /sys/fs/bpf/my-program
    .map_pin_path("/sys/fs/bpf/xdp/firewal-000")
    // finally load the code
    //.load_file("/home/steve/git/aya_discovery/firewall/firewall-pin/target/bpfel-unknown-none/debug/firewall-002")?;
	.load_file("../../firewall/firewall-pin/target/bpfel-unknown-none/debug/firewall-002")?;



    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("firewall_002").unwrap().try_into()?;
    program.load()?;
    //program.attach(&opt.iface, XdpFlags::default())
    //    .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;


    //let p = Path::new("/sys/fs/bpf/xdp/firewall-000");
    // Check if pinned link exists 
    println!("pre link id");
    let link_id = program.attach(&opt.iface, XdpFlags::default())?;
    println!("post link id");
    if Path::new("/sys/fs/bpf/xdp/firewall-000").exists() {
	println!("/sys/fs/bpf/xdp/firewall-000 exists");
	let owned_link = program.take_link(link_id)?;
	let fd_link: FdLink = owned_link.try_into().unwrap();
	let pinned_link = fd_link.pin("/sys/fs/bpf/xdp/firewall-000")?;
    } else {
	println!("/sys/fs/bpf/xdp/firewall-000 exists does not exist, setting up pinned map");
	let link = program.take_link(link_id).unwrap();
	let fd_link: FdLink = link.try_into().unwrap();
	fd_link.pin("/sys/fs/bpf/xdp/firewall-000").unwrap();
    }


    if Path::new("/sys/fs/bpf/xdp/firewall-000.map").exists() {
	println!("want to load map from /sys/fs/bpf/xdp/firewall-000.map");
	//Map::from_pin("/sys/fs/bpf/xdp/firewall-000.map")?;
    } else {
	let mut src_ip_filter : ayaHashMap<_,  u32, u8> =
	    ayaHashMap::try_from( bpf.map_mut("SRC_IP_FILTER").unwrap())?;
	for (k, v)  in config {
	    //let addr: Ipv4Addr ;
	    if v == "block" {
		let addr : Ipv4Addr  = k.parse().unwrap();
		println!("addr {:?}" , addr);
		let _ = src_ip_filter.insert(u32::from(addr), 1, 0);
	    }
	}
	//pin the map
	println!("pinning the map");
	let p = Path::new("/sys/fs/bpf/xdp/firewall-000-map");
	let _  = src_ip_filter.pin(&p,);
    }
    
    // end map
    
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
