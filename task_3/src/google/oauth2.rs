use super::{GoogleApiError, Result};
use derive_more::Display;
use serde::Deserialize;

pub struct GoogleOauth {
    pub redirect_uri: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct GoogleOauthToken {
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: String,
    pub scope: String,
    #[serde(skip_deserializing, default)]
    pub refresh_token: String,
    #[serde(skip_deserializing, default)]
    pub refresh_token_expires_in: String,
    #[serde(skip_deserializing, default)]
    pub id_token: String,
}

impl GoogleOauth {
    pub fn make_redirect_url(&self, scope: Vec<String>, state: String) -> String {
        format!(
            "https://accounts.google.com/o/oauth2/v2/auth\
                ?scope={}\
                &response_type=code\
                &client_id={}\
                &redirect_uri={}\
                &state={state}",
            scope.join(" "),
            self.client_id,
            self.redirect_uri
        )
    }

    pub async fn make_token(&self, code: &str) -> Result<GoogleOauthToken> {
        reqwest::Client::new()
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("client_id", &*self.client_id),
                ("client_secret", &*self.client_secret),
                ("code", code),
                ("grant_type", "authorization_code"),
                ("redirect_uri", &*self.redirect_uri),
            ])
            .send()
            .await
            .map_err(|err| GoogleApiError::RequestError {
                message: err.to_string(),
            })?
            .json::<GoogleOauthToken>()
            .await
            .map_err(|err| GoogleApiError::InvalidJson {
                message: err.to_string(),
            })
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum GoogleOauthResult {
    Success { code: String },
    Error { error: String },
}

#[derive(Display)]
pub enum UserInfoScope {
    #[display("{}", Self::PROFILE_URL)]
    Profile,
    #[display("{}", Self::EMAIL_URL)]
    Email,
}

impl UserInfoScope {
    const PROFILE_URL: &str = "https://www.googleapis.com/auth/userinfo.profile";
    const EMAIL_URL: &str = "https://www.googleapis.com/auth/userinfo.email";
}

impl TryFrom<&str> for UserInfoScope {
    type Error = GoogleApiError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            Self::EMAIL_URL => Self::Email,
            Self::PROFILE_URL => Self::Profile,
            other => Err(GoogleApiError::InvalidScope {
                scope: other.to_string(),
            })?,
        })
    }
}
