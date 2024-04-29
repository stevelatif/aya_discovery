
# Table of Contents

1.  [Table of Contents](#orgc319f27):TOC:
2.  [Running the first XDP Program](#org24ccc0b)
3.  [Generating the code](#org9dc8b69)
    1.  [Compile the code](#orgc9c60cc)
    2.  [Looking into the BPF-ELF object](#org55d61a4)

Welcome to the first step in this XDP tutorial.


<a id="orgc319f27"></a>

# Table of Contents     :TOC:


<a id="org24ccc0b"></a>

# Running the first XDP Program

The first Ebpf  XDP program will be an exercise in generating and building,
loading and examining the running programs. This assumes that you have
already set up the pre requesists !!!INSERT\_HERE!!!
Going through these steps will ensure that you can build an XDP program
using the Clang compiler, load it into the running linux kernel. The Ebpf
program will load into the running kernel where it will be verified. 

The Ebpf program will run in a virtual machine that is built into the Linux
kerenel. This virtual machine has nine general purpose registers and one 
read only register R10 that functions as a frame pointer. Clearly running anything
that can be loaded dyamically in the kernel with elevated privileges can 
be potentially serious security issue. The Ebpf virtual machine contains 
a verifier see <https://docs.kernel.org/bpf/verifier.html>
The verifier will check and reject if the program that contains:

-   loops
-   any type of pointer arithmetic
-   bounds or alignment violations
-   unreachable instructions

&#x2026;

If you have worked with rust code with cargo before, you will have cycled 
through iterations of 

    cargo build
    cargo run

Where the source tree of a simple application would like:

    $ tree
    .
    ├── Cargo.toml
    └── src
        └── main.rs
    
    1 directory, 2 files

and after the application had been compiled:

    $ cargo build
       Compiling hello v0.1.0 (/tmp/hello)
        Finished dev [unoptimized + debuginfo] target(s) in 1.07s
    $ tree
    .
    ├── Cargo.lock
    ├── Cargo.toml
    ├── src
    │   └── main.rs
    └── target
        ├── CACHEDIR.TAG
        └── debug
            ├── build
            ├── deps
            │   ├── hello-20e1cfc616fb61ac
            │   └── hello-20e1cfc616fb61ac.d
            ├── examples
            ├── hello
            ├── hello.d
            └── incremental
                └── hello-3iozzekpyrysr
                    ├── s-gvk87j1cfi-6yflog-9nq5zq3lt8rcg1slvtqhu2l92
                    │   ├── 1cwggjlit3xor5e4.o
                    │   ├── 3nmgwmthvx9ijli.o
                    │   ├── 3qweoew2z2q7s3nh.o
                    │   ├── 4j2x83e2uqqcjw4i.o
                    │   ├── 4pluyvgu1vsjgq2o.o
                    │   ├── 54dgri4zf1sqnocs.o
                    │   ├── dep-graph.bin
                    │   ├── query-cache.bin
                    │   └── work-products.bin
                    └── s-gvk87j1cfi-6yflog.lock
    
    9 directories, 18 files

The compiled binary can be found in target/debug/hello and can be run 
directly from that location or by using cargo

    $ cargo run
        Finished dev [unoptimized + debuginfo] target(s) in 0.02s
         Running `target/debug/hello`
    Hello, world!

The aya framework creates two programs, an eBPF program that will 
be loaded into the kernel and userspace program that will be load the
eBPF program, and can also pass and receive data with the eBPF program.

Setting up the code framework will be set up using a template, this will 
set up a the eBPF code and the userspace program. 
The eBPF program will be compiled and run using a cargo 
workflow extension:

    cargo xtask build-ebpf

Compilation is a two stage process:

    cargo xtask build-ebpf
    cargo build


<a id="org9dc8b69"></a>

# Generating the code

Assuming that we have cargo and the generate extension have been installed, we
can generate the code, at the prompt select xdp-pass as the project name

Using the template, generate the code in directory \`xdp-pass\`, select the xdp option.

    $ cargo generate https://github.com/aya-rs/aya-template  
    ⚠️   Favorite `https://github.com/aya-rs/aya-template` not found in config, using it as a git repository: https://github.com/aya-rs/aya-template
    🤷   Project Name: xdp-pass
    🔧   Destination: /home/steve/articles/learning_ebpf_with_rust/xdp-tutorial/basic01-xdp-pass/xdp-pass ...
    🔧   project-name: xdp-pass ...
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

    $ tree xdp-pass/
    xdp-pass/
    ├── Cargo.toml
    ├── README.md
    ├── xdp-pass
    │   ├── Cargo.toml
    │   └── src
    │       └── main.rs
    ├── xdp-pass-common
    │   ├── Cargo.toml
    │   └── src
    │       └── lib.rs
    ├── xdp-pass-ebpf
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

Look at the file: <xdp-pass/xdp-pass-ebpf/src/main.rs>

    #![no_std]
    #![no_main]
    
    use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
    use aya_log_ebpf::info;
    
    #[xdp]
    pub fn xdp_pass(ctx: XdpContext) -> u32 {
        match try_xdp_pass(ctx) {
    	Ok(ret) => ret,
    	Err(_) => xdp_action::XDP_ABORTED,
        }
    }
    
    fn try_xdp_pass(ctx: XdpContext) -> Result<u32, u32> {
        info!(&ctx, "received a packet");
        Ok(xdp_action::XDP_PASS)
    }
    
    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        unsafe { core::hint::unreachable_unchecked() }
    }

The templated code will run and return \`XDP\_PASS\` 


<a id="orgc9c60cc"></a>

## Compile the code

    cargo xtask build-ebpf
    cargo build 

Compile in this order else the \`cargo build\` will fail.

The xtask step will generate the eBPF object file:
<./target/bpfel-unknown-none/debug/xdp-pass>


<a id="org55d61a4"></a>

## Looking into the BPF-ELF object

    $ llvm-objdump -S target/bpfel-unknown-none/debug/xdp-pass

    target/bpfel-unknown-none/debug/xdp-pass:       file format elf64-bpf
    
    Disassembly of section .text:
    
    0000000000000000 <memset>:
           0:       15 03 06 00 00 00 00 00 if r3 == 0 goto +6 <LBB1_3>
           1:       b7 04 00 00 00 00 00 00 r4 = 0
    
    0000000000000010 <LBB1_2>:
           2:       bf 15 00 00 00 00 00 00 r5 = r1
           3:       0f 45 00 00 00 00 00 00 r5 += r4
           4:       73 25 00 00 00 00 00 00 *(u8 *)(r5 + 0) = r2
           5:       07 04 00 00 01 00 00 00 r4 += 1
           6:       2d 43 fb ff 00 00 00 00 if r3 > r4 goto -5 <LBB1_2>
    
    0000000000000038 <LBB1_3>:
           7:       95 00 00 00 00 00 00 00 exit
    
    0000000000000040 <memcpy>:
           8:       15 03 09 00 00 00 00 00 if r3 == 0 goto +9 <LBB2_3>
           9:       b7 04 00 00 00 00 00 00 r4 = 0
    
    0000000000000050 <LBB2_2>:
          10:       bf 15 00 00 00 00 00 00 r5 = r1
          11:       0f 45 00 00 00 00 00 00 r5 += r4
          12:       bf 20 00 00 00 00 00 00 r0 = r2
          13:       0f 40 00 00 00 00 00 00 r0 += r4
          14:       71 00 00 00 00 00 00 00 r0 = *(u8 *)(r0 + 0)
          15:       73 05 00 00 00 00 00 00 *(u8 *)(r5 + 0) = r0
          16:       07 04 00 00 01 00 00 00 r4 += 1
          17:       2d 43 f8 ff 00 00 00 00 if r3 > r4 goto -8 <LBB2_2>
    
    0000000000000090 <LBB2_3>:
          18:       95 00 00 00 00 00 00 00 exit
    
    Disassembly of section xdp:
    
    0000000000000000 <xdp_pass>:
           0:       bf 16 00 00 00 00 00 00 r6 = r1
           1:       b7 07 00 00 00 00 00 00 r7 = 0
           2:       63 7a fc ff 00 00 00 00 *(u32 *)(r10 - 4) = r7
           3:       bf a2 00 00 00 00 00 00 r2 = r10
           4:       07 02 00 00 fc ff ff ff r2 += -4
           5:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0 ll
           7:       85 00 00 00 01 00 00 00 call 1

Use the IOvisor documentation of the opcodes from here <https://github.com/iovisor/bpf-docs/blob/master/eBPF.md>

RUST\_LOG=info cargo xtask run

We can also load eBPF prograns using iproute2

    sudo ip link set dev lo xdpgeneric obj   ./target/bpfel-unknown-none/debug/xdp-pass sec xdp

Running this command will fail due to license issues more about this later.

    $ sudo ip link set dev lo xdpgeneric obj   ./target/bpfel-unknown-none/debug/xdp-pass sec xdp                                                                                              
    [sudo] password for steve:                                                                                                                                                                                                                                                         
    libbpf: load bpf program failed: Invalid argument                                                                                                                                                                                                                                  
    libbpf: -- BEGIN DUMP LOG ---                                                                                                                                                                                                                                                      
    libbpf:                                                                                                                                                                                                                                                                            
    0: R1=ctx(off=0,imm=0) R10=fp0                                                                                                                                                                                                                                                     
    0: (bf) r6 = r1                       ; R1=ctx(off=0,imm=0) R6_w=ctx(off=0,imm=0)                                                                                                                                                                                                  
    1: (b7) r7 = 0                        ; R7_w=0                                                                                                                                                                                                                                     
    2: (63) *(u32 *)(r10 -4) = r7         ; R7_w=0 R10=fp0 fp-8=0000????                                                                                                                                                                                                               
    3: (bf) r2 = r10                      ; R2_w=fp0 R10=fp0                                                                                                                                                                                                                           
    4: (07) r2 += -4                      ; R2_w=fp-4                                                                                                                                                                                                                                  
    5: (18) r1 = 0xffffa02cd9835c00       ; R1_w=map_ptr(off=0,ks=4,vs=8192,imm=0)                                                                                                                                                                                                     
    7: (85) call bpf_map_lookup_elem#1    ; R0_w=map_value_or_null(id=1,off=0,ks=4,vs=8192,imm=0)                                                                                                                                                                                      
    8: (15) if r0 == 0x0 goto pc+138      ; R0_w=map_value(off=0,ks=4,vs=8192,imm=0)                                                                                                                                                                                                   
    9: (b7) r1 = 11                       ; R1_w=11                                                 
    ...
    
    cannot call GPL-restricted function from non-GPL compatible program
    processed 142 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
    
    libbpf: -- END LOG --
    libbpf: failed to load program 'xdp_pass'
    libbpf: failed to load object './target/bpfel-unknown-none/debug/xdp-pass'

We can see the loaded program using bpftool

    $ sudo bpftool prog
    ...
    112: xdp  name xdp_pass  tag 59a8831dc643b73e  gpl
            loaded_at 2024-04-24T17:06:30-0700  uid 0
            xlated 1192B  jited 655B  memlock 4096B  map_ids 16,15,17

We can generate a dot file using bpftool:

    112: xdp  name xdp_pass  tag 59a8831dc643b73e  gpl
            loaded_at 2024-04-24T17:06:30-0700  uid 0
            xlated 1192B  jited 655B  memlock 4096B  map_ids 16,15,17

Using the ide 112

    $ sudo bpftool prog dump xlated id 112 visual &> /tmp/112.dot

Generate the image file with graphviz

    $ dot -Tpng /tmp/112.dot -o ~/112_graph.png

