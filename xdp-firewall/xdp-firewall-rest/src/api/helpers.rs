use aya;
use aya::maps::loaded_maps;

use log::{info};
use std::process::Command;

pub fn load(interface: &str) -> Result<(), anyhow::Error> {
    let _output = Command::new("../target/debug/xdp-firewall")
	.env("RUST_LOG", "info")
	.arg("-i")
	.arg(interface)
	.spawn()
	.expect("Failed to execute command");
    Ok(())
}

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
