use std::process::Command;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, Result};
use serde::{Serialize};
use aya::{include_bytes_aligned, Bpf};
use log::{info, warn, debug};

mod api;
mod models;
mod repository;


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

    HttpServer::new(move ||
        App::new()
            .app_data(app_data.clone())
            .configure(api::api::config)
            .service(healthcheck)
            .default_service(web::route().to(not_found))
            .wrap(actix_web::middleware::Logger::default())
    )
        .bind(("127.0.0.1", 8080))?
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
