use std::time::Duration;

use actix::prelude::*;
use actix_files::{Files, NamedFile};
use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer, Responder, get, guard, middleware::Logger,
    web,
};
use actix_web_actors::ws;
use sea_orm::{ConnectOptions, Database};

use crate::user_service::{AuthUser, refresh, sign_in, sign_up};

pub mod game_server;
pub mod user_service;
pub mod ws_session;

#[get("/")]
async fn index_page(req: HttpRequest, auth_user: Option<AuthUser>) -> impl Responder {
    if auth_user.is_none() {
        return HttpResponse::TemporaryRedirect()
            .append_header((actix_web::http::header::LOCATION, "/login"))
            .finish();
    }

    NamedFile::open_async("./static/index.html")
        .await
        .unwrap()
        .into_response(&req)
}

#[get("/login")]
async fn login_page() -> impl Responder {
    NamedFile::open_async("./static/login.html").await.unwrap()
}

#[get("/registration")]
async fn registration_page() -> impl Responder {
    NamedFile::open_async("./static/registration.html")
        .await
        .unwrap()
}

/// Entry point for our websocket route
#[get("/ws")]
async fn game_route(
    req: HttpRequest,
    // INFO: only for verify JWT, making the request valid and secure
    _auth_user: AuthUser,
    stream: web::Payload,
    srv: web::Data<Addr<game_server::GameServer>>,
) -> Result<HttpResponse, Error> {
    ws::start(
        ws_session::WsGameSession::new(srv.get_ref().clone()),
        &req,
        stream,
    )
}

#[actix::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let mut opt = ConnectOptions::new("sqlite://users.db");
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .set_schema_search_path("my_schema");

    let db = web::Data::new(Database::connect(opt).await?);

    // start chat server actor
    let server = game_server::GameServer::new().start();

    log::info!("starting HTTP server at http://localhost:8080");

    Ok(HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(server.clone()))
            .app_data(db.clone())
            .service(index_page)
            .service(login_page)
            .service(registration_page)
            .service(
                web::scope("")
                    .guard(guard::Header("upgrade", "websocket"))
                    .service(game_route),
            )
            .service(
                web::scope("")
                    .service(sign_in)
                    .service(sign_up)
                    .service(refresh),
            )
            .service(Files::new("/static", "./static"))
            .wrap(Logger::default())
    })
    .workers(2)
    .bind(("0.0.0.0", 8080))?
    .run()
    .await?)
}
