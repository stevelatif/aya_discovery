#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action,
	       macros::{xdp, map},
	       programs::XdpContext,
	       maps::HashMap};
use aya_log_ebpf::info;
use core::mem;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map(name = "BLOCKED_IPS")]
static mut BLOCKED_IPS: HashMap<u32, u8> =
    HashMap::<u32, u8>::with_max_entries(1024, 0);

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

#[xdp]
pub fn firewall_002(ctx: XdpContext) -> u32 {
    match try_firewall_002(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_firewall_002(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // 
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
	    info!(&ctx, "received IPv4 packet");
	}
        EtherType::Ipv6 => {
	    info!(&ctx, "received IPv6 packet");
	    return Ok(xdp_action::XDP_DROP);
	}

        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    //info!(&ctx, "source addr: {:i}", source_addr); 
    //info!(&ctx, "received a packet");

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

    // Check if match the IP address in the BLOCKED_IPS hash
    if unsafe { BLOCKED_IPS.get(&source_addr).is_some() } {
	info!(&ctx, "dropping packet ...");
	return Ok(xdp_action::XDP_DROP);
    }

    info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);

    
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
