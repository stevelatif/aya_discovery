//use std::process::Command;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, Result};
use serde::{Serialize};
//use aya::{include_bytes_aligned, Bpf};
use log::{info, warn};
use clap::Parser;
    
use std::net::IpAddr;
use std::str::FromStr;
use std::process;

mod api;
mod models;
mod repository;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "127.0.0.1")]
    ip_address: String,
}


#[derive(Serialize)]
pub struct Response {
    pub message: String,
}

#[get("/health")]
async fn healthcheck() -> impl Responder {
    let response = Response {
        message: "Everything is working fine".to_string(),
    };
    HttpResponse::Ok().json(response)
}


async fn not_found() -> Result<HttpResponse> {
    let response = Response {
        message: "Resource not found".to_string(),
    };
    Ok(HttpResponse::NotFound().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let fw_db = repository::database::Database::new();
    let app_data = web::Data::new(fw_db);
    let opt = Opt::parse();
    let unverified_ip = opt.ip_address ;

    // Check if we contain control characters
    match unverified_ip.chars().all(|x| x.is_ascii_control()) {
	true => { warn!("ip address contains control characters") ;
		  process::exit(1);
	} 
	false => { }
    } ;
	
    // Check that we can parse the Ip address
    let ip =  match IpAddr::from_str(&unverified_ip) {
	Ok(v) => {
	    match v.is_ipv4() {
		true => { v },
		false => {
		    info!("non ipv4 addresses not supported" ) ;
		    process::exit(2) ;
		}
	    } 
	},
	Err(e) => { info! ("failed to parse ip address parameter: {}", e); process::exit(1) }
    };
    
    HttpServer::new(move ||
        App::new()
            .app_data(app_data.clone())
            .configure(api::api::config)
            .service(healthcheck)
            .default_service(web::route().to(not_found))
            .wrap(actix_web::middleware::Logger::default())
    )
        .bind((ip, 8080))?
        .run()
        .await
}


// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     HttpServer::new(|| App::new().service(healthcheck).default_service(web::route().to(not_found)))
//         .bind(("127.0.0.1", 8080))?
//         .run()
//         .await
// }
