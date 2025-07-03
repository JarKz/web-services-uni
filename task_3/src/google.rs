use actix_web::ResponseError;
use derive_more::{Display, Error};

pub mod api;
pub mod oauth2;

type Result<T> = std::result::Result<T, GoogleApiError>;

#[derive(Debug, Display, Error)]
pub enum GoogleApiError {
    #[display("Invalid scope: {scope}")]
    InvalidScope { scope: String },
    #[display("Received JSON that differs from application's. Message: {message}")]
    InvalidJson { message: String },
    #[display("Detected request error to acquire access token. Message: {message}")]
    RequestError { message: String },
}

impl ResponseError for GoogleApiError{}
