use actix::prelude::*;
use actix_files::{Files, NamedFile};
use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer, Responder, get, middleware::Logger, web,
};
use actix_web_actors::ws;

pub mod game_server;
pub mod ws_session;

#[get("/")]
async fn index() -> impl Responder {
    NamedFile::open_async("./static/index.html").await.unwrap()
}

/// Entry point for our websocket route
#[get("/ws")]
async fn chat_route(
    req: HttpRequest,
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

    // start chat server actor
    let server = game_server::GameServer::new().start();

    log::info!("starting HTTP server at http://localhost:8080");

    Ok(HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(server.clone()))
            .service(index)
            .service(chat_route)
            .service(Files::new("/static", "./static"))
            .wrap(Logger::default())
    })
    .workers(2)
    .bind(("0.0.0.0", 8080))?
    .run()
    .await?)
}
