#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action,
	       macros::{xdp, map},
	       programs::XdpContext,
	       cty::c_void,
	       helpers::{bpf_map_lookup_percpu_elem,
			 bpf_get_smp_processor_id,
			 bpf_map_update_elem,
	       },
	       maps::PerCpuArray,
};
use aya_log_ebpf::info;


use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use core::ptr::addr_of_mut;

const CPU_CORES: u32 = 16;

#[map(name="ARRAY")]
static mut COUNTER: PerCpuArray<u32> = PerCpuArray::with_max_entries(CPU_CORES , 0);


#[xdp]
pub fn xdp_map_counter(ctx: XdpContext) -> u32 {
    match try_xdp_map_counter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
#[inline(always)] // 

// function to parse packets
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}


fn try_xdp_map_counter(ctx: XdpContext) -> Result<u32, ()> {
    //Ok(xdp_action::XDP_PASS)
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // 

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let _source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let _dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let _source_port = match unsafe { (*ipv4hdr).proto } {
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


    let total = get_total_cpu_counter(CPU_CORES );
    unsafe {
	let counter = COUNTER
            .get_ptr_mut(0)
     	    .ok_or(())? ;
	*counter += 1;

        // Get a mutable pointer to our packet counter
	let cpu = bpf_get_smp_processor_id();
	info!(&ctx,
	      "CPU: {} total: {} counter: {}",
	      cpu,
	      total,
	      *counter
	);
	let ret = bpf_map_update_elem( addr_of_mut!(COUNTER) as *mut _ as *mut c_void,
			     &cpu as *const _ as *const c_void,
			     &counter as *const _ as  *const c_void,
			     aya_ebpf::bindings::BPF_ANY as u64);
	info!(&ctx, "ret: {}" , ret);

    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn get_total_cpu_counter(cpu_cores: u32) -> u32 {
    let mut sum: u32 = 0;
    for cpu in 0..cpu_cores {
        let c = unsafe {
            bpf_map_lookup_percpu_elem(
                 addr_of_mut!(COUNTER) as *mut _ as *mut c_void,
                &0 as *const _ as *const c_void,
                cpu,
            )
        };
        
        if !c.is_null() {
            unsafe {
                let counter = &mut *(c as *mut u32);
                sum += *counter;
            }
        }
    }
    
    sum
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

