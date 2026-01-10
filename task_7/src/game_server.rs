use std::collections::{HashMap, VecDeque};

use actix::prelude::*;
use rand::Rng as _;
use serde::{Deserialize, Serialize};

/// Chat server sends this messages to session
#[derive(Message)]
#[rtype(result = "()")]
pub enum Message {
    StartGame(MatchId, GameInfo),
    EndGame { reason: EndGameReason },
    UpdateGame(GameInfo),
    SendInformation { message: String },
}

#[derive(Hash, Debug, PartialEq, Eq, Clone, Copy)]
pub struct MatchId(u64);

impl MatchId {
    fn new_random() -> Self {
        Self(rand::rng().random())
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EndGameReason {
    OpponentLeft,
    YouLeft,
    Win,
    Lose,
    Draw,
    // Do we really need this?
    // Oh, I can use it for 'stopped' method of Actor for GameState. Fine.
    ServerShutdown,
}

/// Message for chat server communications
///
/// New chat session is created
#[derive(Message)]
#[rtype(u64)]
pub struct Connect {
    pub addr: Recipient<Message>,
}

/// Session is disconnected
#[derive(Message)]
#[rtype(result = "()")]
pub struct Disconnect {
    pub id: u64,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct FindGame {
    pub player_session_id: u64,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct LeaveGame {
    pub player_session_id: u64,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct PlayerMove {
    pub player_session_id: u64,
    pub match_id: MatchId,
    pub x: u8,
    pub y: u8,
}

#[derive(Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
enum Player {
    X,
    O,
}

impl Player {
    fn take_and_inverse(&mut self) -> Self {
        let taken = *self;
        self.inverse();
        taken
    }
    fn inverse(&mut self) {
        *self = match self {
            Player::X => Player::O,
            Player::O => Player::X,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "snake_case")]
enum Cell {
    #[default]
    Empty,
    Filled(Player),
}

#[derive(Clone)]
struct GameState {
    board: [[Cell; 3]; 3],
    player_x: u64,
    player_o: u64,
    turn: Player,
}

enum BoardState {
    Win(Player),
    Draw,
    Incomplete,
}

impl GameState {
    fn to_info(&self, for_player: Player) -> GameInfo {
        GameInfo {
            board: self.board,
            you: for_player,
            turn_of: self.turn,
        }
    }

    fn check_board(&self) -> BoardState {
        for index in 0..3 {
            let first_cell = &self.board[index][0];
            let Cell::Filled(player) = *first_cell else {
                continue;
            };

            if self.board[index].iter().all(|cell| cell == first_cell) {
                return BoardState::Win(player);
            }
        }

        for index in 0..3 {
            let first_cell = &self.board[0][index];
            let Cell::Filled(player) = *first_cell else {
                continue;
            };

            if self.board.iter().all(|row| &row[index] == first_cell) {
                return BoardState::Win(player);
            }
        }

        'left_diagonal: {
            let first_cell = &self.board[0][0];
            let Cell::Filled(player) = *first_cell else {
                break 'left_diagonal;
            };

            if first_cell == &self.board[1][1] && first_cell == &self.board[2][2] {
                return BoardState::Win(player);
            }
        }

        'right_diagonal: {
            let first_cell = &self.board[0][2];
            let Cell::Filled(player) = *first_cell else {
                break 'right_diagonal;
            };

            if first_cell == &self.board[1][1] && first_cell == &self.board[2][0] {
                return BoardState::Win(player);
            }
        }

        if self
            .board
            .iter()
            .flat_map(|row| row.iter())
            .any(|cell| *cell == Cell::Empty)
        {
            BoardState::Incomplete
        } else {
            BoardState::Draw
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct GameInfo {
    board: [[Cell; 3]; 3],
    you: Player,
    turn_of: Player,
}

pub struct GameServer {
    sessions: HashMap<u64, Recipient<Message>>,
    matches: HashMap<MatchId, GameState>,
    awaiting_players: VecDeque<u64>,
}

impl GameServer {
    pub fn new() -> Self {
        GameServer {
            sessions: HashMap::new(),
            matches: HashMap::new(),
            awaiting_players: VecDeque::new(),
        }
    }
}

impl Default for GameServer {
    fn default() -> Self {
        Self::new()
    }
}

impl Actor for GameServer {
    type Context = Context<Self>;
}

impl Handler<Connect> for GameServer {
    type Result = u64;

    fn handle(&mut self, msg: Connect, _: &mut Self::Context) -> Self::Result {
        // register session with random id
        let mut id = rand::rng().random::<u64>();
        while self.sessions.contains_key(&id) {
            id = rand::rng().random::<u64>();
        }
        self.sessions.insert(id, msg.addr);

        // send id back
        id
    }
}

impl Handler<Disconnect> for GameServer {
    type Result = ();

    fn handle(&mut self, msg: Disconnect, _: &mut Self::Context) -> Self::Result {
        if self.sessions.remove(&msg.id).is_none() {
            return;
        }

        let Some((match_id, state)) = self.matches.iter().find_map(|(match_id, game_state)| {
            if game_state.player_x == msg.id || game_state.player_o == msg.id {
                Some((*match_id, game_state.clone()))
            } else {
                None
            }
        }) else {
            // INFO: If there's no match with this player, then nothing to do.
            return;
        };

        if let Some(index) = self.awaiting_players.iter().position(|id| id == &msg.id) {
            self.awaiting_players.remove(index);
        }

        self.matches.remove(&match_id);

        let remaining_player = if state.player_x == msg.id {
            state.player_o
        } else {
            state.player_x
        };

        if let Some(recipient) = self.sessions.get(&remaining_player) {
            recipient.do_send(Message::EndGame {
                reason: EndGameReason::OpponentLeft,
            });
        }
    }
}

impl Handler<FindGame> for GameServer {
    type Result = ();

    fn handle(&mut self, msg: FindGame, _: &mut Self::Context) -> Self::Result {
        self.awaiting_players.push_back(msg.player_session_id);

        if let Some(recipient) = self.sessions.get(&msg.player_session_id) {
            recipient.do_send(Message::SendInformation {
                message: "The game is finding...".to_string(),
            });
        }

        if self.awaiting_players.len() >= 2 {
            // WARN: are you sure that these players are not disconnected?
            let mut player_x = self.awaiting_players.pop_front().unwrap();
            let mut player_o = self.awaiting_players.pop_back().unwrap();

            let mut rng = rand::rng();
            if rng.random_bool(0.5) {
                (player_o, player_x) = (player_x, player_o);
            }

            let game_state = GameState {
                board: Default::default(),
                player_x,
                player_o,
                turn: Player::X,
            };

            let mut match_id = MatchId::new_random();
            while self.matches.contains_key(&match_id) {
                match_id = MatchId::new_random();
            }

            self.matches.insert(match_id, game_state.clone());

            let info_for_player_x = game_state.to_info(Player::X);
            let info_for_player_o = game_state.to_info(Player::O);

            match self.sessions.get(&player_x) {
                Some(recepient) => {
                    recepient.do_send(Message::StartGame(match_id, info_for_player_x))
                }
                None => {
                    todo!("Need to handle this")
                }
            }

            match self.sessions.get(&player_o) {
                Some(recepient) => {
                    recepient.do_send(Message::StartGame(match_id, info_for_player_o))
                }
                None => {
                    todo!("Need to handle this")
                }
            }
        }
    }
}

impl Handler<LeaveGame> for GameServer {
    type Result = ();

    fn handle(&mut self, msg: LeaveGame, _: &mut Self::Context) -> Self::Result {
        let Some((&match_id, _)) = self.matches.iter().find(|(_, game_state)| {
            game_state.player_x == msg.player_session_id
                || game_state.player_o == msg.player_session_id
        }) else {
            return;
        };

        let game_state = self.matches.remove(&match_id).unwrap();

        let (leaver, opponent) = if msg.player_session_id == game_state.player_x {
            (game_state.player_x, game_state.player_o)
        } else {
            (game_state.player_o, game_state.player_x)
        };

        if let Some(recepient) = self.sessions.get(&leaver) {
            recepient.do_send(Message::EndGame {
                reason: EndGameReason::YouLeft,
            })
        }

        if let Some(recepient) = self.sessions.get(&opponent) {
            recepient.do_send(Message::EndGame {
                reason: EndGameReason::OpponentLeft,
            })
        }
    }
}

impl Handler<PlayerMove> for GameServer {
    type Result = ();

    fn handle(&mut self, msg: PlayerMove, _: &mut Self::Context) -> Self::Result {
        let Some(game_state) = self.matches.get_mut(&msg.match_id) else {
            return;
        };

        // INFO: ignore if player is trying to trun move that not belongs to him
        if (game_state.player_x == msg.player_session_id && game_state.turn == Player::O)
            || (game_state.player_o == msg.player_session_id && game_state.turn == Player::X)
        {
            return;
        }

        // INFO: ignore when indices are out of bound
        if msg.x > 2 || msg.y > 2 {
            return;
        }

        if game_state.board[msg.x as usize][msg.y as usize] != Cell::Empty {
            return;
        }

        game_state.board[msg.x as usize][msg.y as usize] =
            Cell::Filled(game_state.turn.take_and_inverse());
        let info_for_player_x = game_state.to_info(Player::X);
        let info_for_player_o = game_state.to_info(Player::O);

        match self.sessions.get(&game_state.player_x) {
            Some(recepient) => recepient.do_send(Message::UpdateGame(info_for_player_x)),
            None => {
                todo!("Need to handle this")
            }
        }

        match self.sessions.get(&game_state.player_o) {
            Some(recepient) => recepient.do_send(Message::UpdateGame(info_for_player_o)),
            None => {
                todo!("Need to handle this")
            }
        }

        let (message_for_player_x, message_for_player_o) = match game_state.check_board() {
            BoardState::Incomplete => {
                return;
            }
            BoardState::Draw => (
                Message::EndGame {
                    reason: EndGameReason::Draw,
                },
                Message::EndGame {
                    reason: EndGameReason::Draw,
                },
            ),
            BoardState::Win(player) => {
                if player == Player::X {
                    (
                        Message::EndGame {
                            reason: EndGameReason::Win,
                        },
                        Message::EndGame {
                            reason: EndGameReason::Lose,
                        },
                    )
                } else {
                    (
                        Message::EndGame {
                            reason: EndGameReason::Lose,
                        },
                        Message::EndGame {
                            reason: EndGameReason::Win,
                        },
                    )
                }
            }
        };

        match self.sessions.get(&game_state.player_x) {
            Some(recepient) => recepient.do_send(message_for_player_x),
            None => {
                todo!("Need to handle this")
            }
        }

        match self.sessions.get(&game_state.player_o) {
            Some(recepient) => recepient.do_send(message_for_player_o),
            None => {
                todo!("Need to handle this")
            }
        }
    }
}
