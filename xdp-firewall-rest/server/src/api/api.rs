use actix_web::web;
use actix_web::get;
use actix_web::delete;
use crate::api::helpers;
use actix_web::{web::{
    Data,
    Json,
}, post, HttpResponse};
use crate::{models::fw::Fw, repository::database::Database};
use log::info;

//curl -XPOST 127.0.0.1:8080/api/load -H "Content-Type: application/json" -d '{"interface":"lo", "mode":"", "ip_address":"127.0.0.1"}'
#[post("/load")]
pub async fn load_fw(db: Data<Database>, new_fw: Json<Fw>) -> HttpResponse {
    match helpers::load(&(new_fw.interface), &(new_fw.ip_address)).await {
	Ok(_v) => {info!("loaded ...")},
	Err(e) => { info!("failed to load : {}", e)}
    }
    let fw = db.create_fw(new_fw.into_inner());
    match fw {
        Ok(load) => HttpResponse::Ok().json(load),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

// curl 127.0.0.1:8080/api/fw
#[get("/fw")]
pub async fn get_fws(db: web::Data<Database>) -> HttpResponse {
    let fws = db.get_fws();
    HttpResponse::Ok().json(fws)
}

#[get("/fw/{id}")]
pub async fn get_fw_by_id(db: web::Data<Database>, id: web::Path<String>) -> HttpResponse {
    let fw = db.get_fw_by_id(&id);
    match fw {
        Some(fw) => HttpResponse::Ok().json(fw),
        None => HttpResponse::NotFound().body("Fw not found"),
    }
}

#[get("/fw/unload/{interface}")]
pub async fn unload_by_interface(db: web::Data<Database>, interface: web::Path<String>) -> HttpResponse {
    info!("unloading : {:?} ...", interface );
    let _ = helpers::unload_by_interface(&interface);
    let fw = db.get_fw_by_interface(&interface);
    match fw {
        Some(fw) => HttpResponse::Ok().json(fw),
	None => HttpResponse::NotFound().body("Fw not found from interface"),
    }
    //HttpResponse::Ok().json("ok")
}

// #[put("/todos/{id}")]
// pub async fn update_todo_by_id(db: web::Data<Database>, id: web::Path<String>, updated_todo: web::Json<Todo>) -> HttpResponse {
//     let todo = db.update_todo_by_id(&id, updated_todo.into_inner());
//     match todo {
//         Some(todo) => HttpResponse::Ok().json(todo),
//         None => HttpResponse::NotFound().body("Todo not found"),
//     }
// }

#[delete("/fw/{id}")]
pub async fn delete_fw_by_id(db: web::Data<Database>, id: web::Path<String>) -> HttpResponse {
    let fw = db.delete_fw_by_id(&id);
    match fw {
        Some(fw) => HttpResponse::Ok().json(fw),
        None => HttpResponse::NotFound().body("Fw not found"),
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(load_fw)
	    .service(get_fws)
	    .service(unload_by_interface)
	// .service(update_fw_by_id)
	    .service(delete_fw_by_id)
    );
}

