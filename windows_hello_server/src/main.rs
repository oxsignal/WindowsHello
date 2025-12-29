mod types;
mod auth;
mod handlers;

use actix_web::{web, App, HttpServer};
use std::sync::Mutex;
use std::collections::HashMap;
use crate::types::AppState;

pub const SERVER_ADDR: &str = "127.0.0.1:8080";
// TODO.
// 현재 사용자 key 저장하고, Key_name을 확인하는 로직 없음. DB로 만들어서 검증하는 루틴 추가할것

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_data = web::Data::new(AppState {
        users: Mutex::new(HashMap::new()),
    });

    println!("Server starting at http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .service(handlers::get_challenge)
            .service(handlers::authenticate)
    })
    .bind(SERVER_ADDR)?
    .run()
    .await
}