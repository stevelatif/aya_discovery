#![no_std]
#![no_main]
use aya_ebpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    programs::XdpContext,
    maps::{HashMap, LruPerCpuHashMap, lpm_trie::{LpmTrie, Key},
    }
};
use aya_log_ebpf::info;
//use aya_ebpf::helpers::gen::bpf_map_lookup_elem;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

const CPU_CORES: u32 = 16;

#[map(name="STATUS_COUNTER")]
static mut STATUS_COUNTER: LruPerCpuHashMap<u64, u64> =
    LruPerCpuHashMap::with_max_entries(CPU_CORES, 0);
// #[map(name="PKT_CNT_ARRAY")]
// static mut PACKETS: PerCpuArray<u32> = PerCpuArray::with_max_entries(CPU_CORES , 0);

#[map(name = "BLOCKED_IPS")]
static mut BLOCKED_IPS: LpmTrie<u32, u8> =
    LpmTrie::<u32, u8>::with_max_entries(1024, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// #[inline(always)]
// fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<(*const T, usize), ()> {
//     let start = ctx.data();
//     let end = ctx.data_end();
//     let len = mem::size_of::<T>();
    
//     if start + offset + len > end {
//         return Err(());
//     }
//      Ok ( ((start + offset) as *const T, end - start))
// }

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let p1 = ptr_at(&ctx, 0)?;
    let ethhdr : EthHdr = unsafe { *p1 } ;
    //info!(&ctx, "packet size: {}", pkt_size);
    match ethhdr.ether_type {
        EtherType::Ipv4 => {
	    // Do nothing
	}
        EtherType::Ipv6 => {
	    //info!(&ctx, "received IPv6 packet");
	    return Ok(xdp_action::XDP_DROP);
	}

        _ => return Ok(xdp_action::XDP_PASS),
    }

    // parse the IP header
    let ipv4hdr : *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let total_length = u16::from_be(unsafe { (*ipv4hdr).tot_len });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    
    
    info!(&ctx, "src addr: {:i} destination {:i} length {}", src_addr, dest_addr, total_length);
    let add = unsafe {  BLOCKED_IPS.get(&Key::new(8, u32::from(src_addr).to_be()))} ;
    match add {
	None => {
	    info!(&ctx, "not matched {:i}", src_addr);
	    return Ok(xdp_action::XDP_PASS);
	}
	Some(v)  => {
	    info!(&ctx, "matched {:i} : {}" , src_addr, *v);
	    unsafe {
		let counter = STATUS_COUNTER
		    .get_ptr_mut(&0)
     		    .ok_or(())? ;
		*counter += 1;
		info!(&ctx, "count: {}", *counter);
	    }
	    //return(Ok(xdp_action::XDP_DROP));
	}
	_ => return Ok(xdp_action::XDP_PASS),
    }

    // parse the TCP header
        let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => return Err(()),
    };

    let destination_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).dest })
        }
        _ => return Err(()),
    };

    info!(&ctx, "source port {} dest_port {}", source_port, destination_port);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
