---
layout: post
title: First Steps with XDP 
subtitle: Part One
tags: [ebpf, rust, linux]
---

Welcome to the running Hello World.


# Running the first XDP Program

Now that we can build and run an XDP program on the loopback interface, lets
build a hello world XDP program that prints a message everytime it sees a packet
on the interface. This will involve only a few more lines of code and 
will follow the same build and deployment process in the previous chapter.


# Generating the code

Assuming that we have cargo and the generate extension have been installed, we
can generate the code, at the prompt select hello-world as the project name

Using the template, generate the code in directory \`hello-world\`, select the xdp option.

    $ cargo generate https://github.com/aya-rs/aya-template  
    ⚠️   Favorite `https://github.com/aya-rs/aya-template` not found in config, using it as a git repository: https://github.com/aya-rs/aya-template
    🤷   Project Name: hello-world
    🔧   Destination: /home/steve/articles/learning_ebpf_with_rust/xdp-tutorial/basic01-hello-world/hello-world ...
    🔧   project-name: hello-world ...
    🔧   Generating template ...
    ? 🤷   Which type of eBPF program? ›
      cgroup_skb
      cgroup_sockopt
      cgroup_sysctl
      classifier
      fentry
      fexit
      kprobe
      kretprobe
      lsm
      perf_event
      raw_tracepoint
      sk_msg
      sock_ops
      socket_filter
      tp_btf
      tracepoint
      uprobe
      uretprobe
    ❯ xdp

The generated files:

    $ tree hello-world/
    hello-world/
    ├── Cargo.toml
    ├── README.md
    ├── hello-world
    │   ├── Cargo.toml
    │   └── src
    │       └── main.rs
    ├── hello-world-common
    │   ├── Cargo.toml
    │   └── src
    │       └── lib.rs
    ├── hello-world-ebpf
    │   ├── Cargo.toml
    │   ├── rust-toolchain.toml
    │   └── src
    │       └── main.rs
    └── xtask
        ├── Cargo.toml
        └── src
            ├── build_ebpf.rs
            ├── main.rs
            └── run.rs
    
    8 directories, 13 files

Look at the file: <hello-world/hello-world-ebpf/src/main.rs> 
We can leave the default generated code as it is as it already 
does what we want.

    #![no_std]
    #![no_main]
    
    use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
    use aya_log_ebpf::info;
    
    #[xdp]
    pub fn hello_world(ctx: XdpContext) -> u32 {
        match try_hello_world(ctx) {
    	Ok(ret) => ret,
    	Err(_) => xdp_action::XDP_ABORTED,
        }
    }
    
    fn try_hello_world(ctx: XdpContext) -> Result<u32, u32> {
        info!(&ctx, "received a packet");
        Ok(xdp_action::XDP_PASS)
    }
    
    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        unsafe { core::hint::unreachable_unchecked() }
    }

The templated code will run and return \`XDP\_PASS\` 


## Compile the code

    cargo xtask build-ebpf
    cargo build 


## Looking into the BPF-ELF object

As we did in the previous section, lets look at the generated eBPF bytecode

    $ llvm-readelf --sections target/bpfel-unknown-none/debug/hello-world
    There are 8 section headers, starting at offset 0x9a8:
    
    Section Headers:
      [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
      [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
      [ 1] .strtab           STRTAB          0000000000000000 000890 000113 00      0   0  1
      [ 2] .text             PROGBITS        0000000000000000 000040 000098 00  AX  0   0  8
      [ 3] xdp               PROGBITS        0000000000000000 0000d8 000588 00  AX  0   0  8
      [ 4] .relxdp           REL             0000000000000000 000840 000050 10   I  7   3  8
      [ 5] .rodata           PROGBITS        0000000000000000 000660 000027 00   A  0   0  1
      [ 6] maps              PROGBITS        0000000000000000 000688 000038 00  WA  0   0  4
      [ 7] .symtab           SYMTAB          0000000000000000 0006c0 000180 18      1  11  8
    Key to Flags:
      W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
      L (link order), O (extra OS processing required), G (group), T (TLS),
      C (compressed), x (unknown), o (OS specific), E (exclude),
      R (retain), p (processor specific)

As before we have an xdp section, lets disassemble that:

    
    target/bpfel-unknown-none/debug/hello-world:	file format elf64-bpf
    
    Disassembly of section xdp:
    
    0000000000000000 <hello_world>:
           0:	r6 = r1
           1:	r7 = 0
           2:	*(u32 *)(r10 - 4) = r7
           3:	r2 = r10
           4:	r2 += -4
           5:	r1 = 0 ll
           7:	call 1
           8:	if r0 == 0 goto +166 <LBB0_2>
           9:	*(u8 *)(r0 + 2) = r7
          10:	r2 = 11
          11:	*(u8 *)(r0 + 1) = r2
          12:	r1 = 1
          13:	*(u8 *)(r0 + 0) = r1
          14:	r3 = r0
          15:	r3 += 3
          16:	r4 = 0 ll
          18:	r5 = *(u8 *)(r4 + 0)
          19:	*(u8 *)(r3 + 0) = r5
          20:	r5 = *(u8 *)(r4 + 1)
          21:	*(u8 *)(r3 + 1) = r5
          22:	r5 = *(u8 *)(r4 + 2)
          23:	*(u8 *)(r3 + 2) = r5
          24:	r5 = *(u8 *)(r4 + 3)
          25:	*(u8 *)(r3 + 3) = r5
          26:	r5 = *(u8 *)(r4 + 4)
          27:	*(u8 *)(r3 + 4) = r5
          28:	r5 = *(u8 *)(r4 + 5)
          29:	*(u8 *)(r3 + 5) = r5
          30:	r5 = *(u8 *)(r4 + 6)
          31:	*(u8 *)(r3 + 6) = r5
          32:	r5 = *(u8 *)(r4 + 7)
          33:	*(u8 *)(r3 + 7) = r5
          34:	r5 = *(u8 *)(r4 + 8)
          35:	*(u8 *)(r3 + 8) = r5
          36:	r5 = *(u8 *)(r4 + 9)
          37:	*(u8 *)(r3 + 9) = r5
          38:	r5 = *(u8 *)(r4 + 10)
          39:	*(u8 *)(r3 + 10) = r5
          40:	r3 = 3
          41:	*(u8 *)(r0 + 18) = r3
          42:	*(u8 *)(r0 + 17) = r3
          43:	r3 = 2
          44:	*(u8 *)(r0 + 14) = r3
          45:	*(u8 *)(r0 + 20) = r7
          46:	*(u8 *)(r0 + 19) = r2
          47:	*(u8 *)(r0 + 16) = r7
          48:	*(u8 *)(r0 + 15) = r1
          49:	r3 = r0
          50:	r3 += 21
          51:	r5 = *(u8 *)(r4 + 0)
          52:	*(u8 *)(r3 + 0) = r5
          53:	r5 = *(u8 *)(r4 + 1)
          54:	*(u8 *)(r3 + 1) = r5
          55:	r5 = *(u8 *)(r4 + 2)
          56:	*(u8 *)(r3 + 2) = r5
          57:	r5 = *(u8 *)(r4 + 3)
          58:	*(u8 *)(r3 + 3) = r5
          59:	r5 = *(u8 *)(r4 + 4)
          60:	*(u8 *)(r3 + 4) = r5
          61:	r5 = *(u8 *)(r4 + 5)
          62:	*(u8 *)(r3 + 5) = r5
          63:	r5 = *(u8 *)(r4 + 6)
          64:	*(u8 *)(r3 + 6) = r5
          65:	r5 = *(u8 *)(r4 + 7)
          66:	*(u8 *)(r3 + 7) = r5
          67:	r5 = *(u8 *)(r4 + 8)
          68:	*(u8 *)(r3 + 8) = r5
          69:	r5 = *(u8 *)(r4 + 9)
          70:	*(u8 *)(r3 + 9) = r5
          71:	r5 = *(u8 *)(r4 + 10)
          72:	*(u8 *)(r3 + 10) = r5
          73:	*(u8 *)(r0 + 33) = r2
          74:	*(u8 *)(r0 + 34) = r7
          75:	r2 = 4
          76:	*(u8 *)(r0 + 32) = r2
          77:	r3 = r0
          78:	r3 += 35
          79:	r4 = 11 ll
          81:	r5 = *(u8 *)(r4 + 0)
          82:	*(u8 *)(r3 + 0) = r5
          83:	r5 = *(u8 *)(r4 + 1)
          84:	*(u8 *)(r3 + 1) = r5
          85:	r5 = *(u8 *)(r4 + 2)
          86:	*(u8 *)(r3 + 2) = r5
          87:	r5 = *(u8 *)(r4 + 3)
          88:	*(u8 *)(r3 + 3) = r5
          89:	r5 = *(u8 *)(r4 + 4)
          90:	*(u8 *)(r3 + 4) = r5
          91:	r5 = *(u8 *)(r4 + 5)
          92:	*(u8 *)(r3 + 5) = r5
          93:	r5 = *(u8 *)(r4 + 6)
          94:	*(u8 *)(r3 + 6) = r5
          95:	r5 = *(u8 *)(r4 + 7)
          96:	*(u8 *)(r3 + 7) = r5
          97:	r5 = *(u8 *)(r4 + 8)
          98:	*(u8 *)(r3 + 8) = r5
          99:	r5 = *(u8 *)(r4 + 9)
         100:	*(u8 *)(r3 + 9) = r5
         101:	r5 = *(u8 *)(r4 + 10)
         102:	*(u8 *)(r3 + 10) = r5
         103:	*(u8 *)(r0 + 56) = r1
         104:	r1 = 8
         105:	*(u8 *)(r0 + 54) = r1
         106:	r1 = 16
         107:	*(u8 *)(r0 + 49) = r1
         108:	*(u8 *)(r0 + 66) = r7
         109:	*(u8 *)(r0 + 63) = r7
         110:	*(u8 *)(r0 + 62) = r7
         111:	*(u8 *)(r0 + 61) = r7
         112:	*(u8 *)(r0 + 60) = r7
         113:	*(u8 *)(r0 + 59) = r7
         114:	*(u8 *)(r0 + 58) = r7
         115:	*(u8 *)(r0 + 57) = r7
         116:	*(u8 *)(r0 + 55) = r7
         117:	*(u8 *)(r0 + 52) = r7
         118:	*(u8 *)(r0 + 51) = r7
         119:	*(u8 *)(r0 + 50) = r7
         120:	*(u8 *)(r0 + 48) = r7
         121:	*(u8 *)(r0 + 47) = r2
         122:	r1 = 17
         123:	*(u8 *)(r0 + 65) = r1
         124:	*(u8 *)(r0 + 64) = r1
         125:	r1 = 6
         126:	*(u8 *)(r0 + 53) = r1
         127:	r1 = 5
         128:	*(u8 *)(r0 + 46) = r1
         129:	r1 = r0
         130:	r1 += 67
         131:	r2 = 22 ll
         133:	r3 = *(u8 *)(r2 + 0)
         134:	*(u8 *)(r1 + 0) = r3
         135:	r3 = *(u8 *)(r2 + 1)
         136:	*(u8 *)(r1 + 1) = r3
         137:	r3 = *(u8 *)(r2 + 2)
         138:	*(u8 *)(r1 + 2) = r3
         139:	r3 = *(u8 *)(r2 + 3)
         140:	*(u8 *)(r1 + 3) = r3
         141:	r3 = *(u8 *)(r2 + 4)
         142:	*(u8 *)(r1 + 4) = r3
         143:	r3 = *(u8 *)(r2 + 5)
         144:	*(u8 *)(r1 + 5) = r3
         145:	r3 = *(u8 *)(r2 + 6)
         146:	*(u8 *)(r1 + 6) = r3
         147:	r3 = *(u8 *)(r2 + 7)
         148:	*(u8 *)(r1 + 7) = r3
         149:	r3 = *(u8 *)(r2 + 8)
         150:	*(u8 *)(r1 + 8) = r3
         151:	r3 = *(u8 *)(r2 + 9)
         152:	*(u8 *)(r1 + 9) = r3
         153:	r3 = *(u8 *)(r2 + 10)
         154:	*(u8 *)(r1 + 10) = r3
         155:	r3 = *(u8 *)(r2 + 11)
         156:	*(u8 *)(r1 + 11) = r3
         157:	r3 = *(u8 *)(r2 + 12)
         158:	*(u8 *)(r1 + 12) = r3
         159:	r3 = *(u8 *)(r2 + 13)
         160:	*(u8 *)(r1 + 13) = r3
         161:	r3 = *(u8 *)(r2 + 14)
         162:	*(u8 *)(r1 + 14) = r3
         163:	r3 = *(u8 *)(r2 + 15)
         164:	*(u8 *)(r1 + 15) = r3
         165:	r3 = *(u8 *)(r2 + 16)
         166:	*(u8 *)(r1 + 16) = r3
         167:	r1 = r6
         168:	r2 = 0 ll
         170:	r3 = 4294967295 ll
         172:	r4 = r0
         173:	r5 = 84
         174:	call 25
    
    0000000000000578 <LBB0_2>:
         175:	r0 = 2
         176:	exit

We can run this using ip link, but to get the output, we will instead deploy it using 
cargo

    RUST_LOG=info cargo xtask run -- -i lo

In another terminal start a nc server listening on port 9090

    $ nc -l 9090

Then connect to it from another terminal

    echo "the quick brown fox jumped over the lazy dog" |  nc 127.0.0.1 9090

 you should then see output on your terminal where 
cargo had loaded the eBPF program:

    RUST_LOG=info cargo xtask run -- -i lo
        Finished dev [unoptimized + debuginfo] target(s) in 0.02s
         Running `target/debug/xtask run -- -i lo`
    [2024-04-28T22:25:52Z INFO  hello_world] Waiting for Ctrl-C...
    [2024-04-28T22:31:04Z INFO  hello_world] received a packet
    [2024-04-28T22:31:04Z INFO  hello_world] received a packet
    [2024-04-28T22:31:04Z INFO  hello_world] received a packet
    [2024-04-28T22:31:04Z INFO  hello_world] received a packet
    [2024-04-28T22:31:04Z INFO  hello_world] received a packet


# Summary

One small step from the previous version to 

-   print out a message when a packet is received

