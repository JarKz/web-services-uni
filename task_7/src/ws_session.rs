use std::time::{Duration, Instant};

use actix::prelude::*;
use actix_web_actors::ws;
use serde::{Deserialize, Serialize};

use crate::game_server::{self, EndGameReason, GameInfo, GameServer, MatchId};

/// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum ClientMessage {
    StartGame,
    StopGame,
    Move(PlayerMove),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
struct PlayerMove {
    x: u8,
    y: u8,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum Response {
    GameStarted(GameInfo),
    GameEnded {
        reason: EndGameReason,
    },
    GameUpdated(GameInfo),
    /// Generic information for client that doesn't contains important information. Like 'The game
    /// is finding...'.
    Info {
        message: String,
    },
    BadRequest {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum ErrorCode {
    InMatch,
    NotInMatch,
}

#[derive(Debug)]
pub struct WsGameSession {
    /// unique session id
    pub id: u64,

    /// Client must send ping at least once per 10 seconds (CLIENT_TIMEOUT),
    /// otherwise we drop connection.
    pub hb: Instant,

    /// joined match
    pub match_id: Option<MatchId>,

    /// Game server
    pub addr: Addr<game_server::GameServer>,
}

impl WsGameSession {
    pub fn new(addr: Addr<GameServer>) -> Self {
        Self {
            id: 0,
            hb: Instant::now(),
            match_id: None,
            addr,
        }
    }

    /// helper method that sends ping to client every 5 seconds (HEARTBEAT_INTERVAL).
    ///
    /// also this method checks heartbeats from client
    fn hb(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // heartbeat timed out
                println!("Websocket Client heartbeat failed, disconnecting!");

                // notify chat server
                act.addr.do_send(game_server::Disconnect { id: act.id });

                // stop actor
                ctx.stop();

                // don't try to send a ping
                return;
            }

            ctx.ping(b"");
        });
    }

    fn handle_client_message(
        &self,
        client_message: ClientMessage,
        ctx: &mut ws::WebsocketContext<Self>,
    ) {
        match client_message {
            ClientMessage::StartGame => match self.match_id {
                None => self.addr.do_send(game_server::FindGame {
                    player_session_id: self.id,
                }),
                Some(_) => ctx.text(
                    serde_json::to_string(&Response::BadRequest {
                        code: ErrorCode::InMatch,
                        message: "You are in a match.".to_string(),
                    })
                    .unwrap(),
                ),
            },
            ClientMessage::StopGame => self.addr.do_send(game_server::LeaveGame {
                player_session_id: self.id,
            }),
            ClientMessage::Move(PlayerMove { x, y }) => match self.match_id {
                Some(match_id) => self.addr.do_send(game_server::PlayerMove {
                    player_session_id: self.id,
                    match_id,
                    x,
                    y,
                }),
                None => ctx.text(
                    serde_json::to_string(&Response::BadRequest {
                        code: ErrorCode::NotInMatch,
                        message: "You're not in a match.".to_string(),
                    })
                    .unwrap(),
                ),
            },
        }
    }
}

impl Actor for WsGameSession {
    type Context = ws::WebsocketContext<Self>;

    /// Method is called on actor start.
    /// We register ws session with ChatServer
    fn started(&mut self, ctx: &mut Self::Context) {
        // we'll start heartbeat process on session start.
        self.hb(ctx);

        // register self in chat server. `AsyncContext::wait` register
        // future within context, but context waits until this future resolves
        // before processing any other events.
        // HttpContext::state() is instance of WsChatSessionState, state is shared
        // across all routes within application
        let addr = ctx.address();
        self.addr
            .send(game_server::Connect {
                addr: addr.recipient(),
            })
            .into_actor(self)
            .then(|res, act, ctx| {
                match res {
                    Ok(res) => act.id = res,
                    // something is wrong with chat server
                    _ => ctx.stop(),
                }
                fut::ready(())
            })
            .wait(ctx);
    }

    fn stopping(&mut self, _: &mut Self::Context) -> Running {
        self.addr.do_send(game_server::Disconnect { id: self.id });
        Running::Stop
    }
}

/// Handle messages from chat server, we simply send it to peer websocket
impl Handler<game_server::Message> for WsGameSession {
    type Result = ();

    fn handle(&mut self, msg: game_server::Message, ctx: &mut Self::Context) {
        match msg {
            game_server::Message::StartGame(match_id, game_info) => {
                self.match_id = Some(match_id);

                ctx.text(serde_json::to_string(&Response::GameStarted(game_info)).unwrap());
            }
            game_server::Message::EndGame { reason } => {
                self.match_id = None;

                ctx.text(serde_json::to_string(&Response::GameEnded { reason }).unwrap());
            }
            game_server::Message::UpdateGame(game_info) => {
                ctx.text(serde_json::to_string(&Response::GameUpdated(game_info)).unwrap());
            }
            game_server::Message::SendInformation { message } => {
                ctx.text(serde_json::to_string(&Response::Info { message }).unwrap())
            }
        }
    }
}

/// WebSocket message handler
impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WsGameSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        let msg = match msg {
            Err(_) => {
                ctx.stop();
                return;
            }
            Ok(msg) => msg,
        };

        log::debug!("WEBSOCKET MESSAGE: {msg:?}");
        match msg {
            ws::Message::Ping(msg) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            ws::Message::Pong(_) => {
                self.hb = Instant::now();
            }
            ws::Message::Text(text) => {
                let client_message = match serde_json::from_str::<ClientMessage>(text.trim()) {
                    Ok(message) => message,
                    Err(err) => {
                        log::error!("Received an invalid message: {err}");
                        ctx.text(format!("Ivalid message. Error: {err}"));
                        return;
                    }
                };

                self.handle_client_message(client_message, ctx)
            }
            ws::Message::Binary(_) => println!("Unexpected binary"),
            ws::Message::Close(reason) => {
                ctx.close(reason);
                ctx.stop();
            }
            ws::Message::Continuation(_) => {
                ctx.stop();
            }
            ws::Message::Nop => (),
        }
    }
}
