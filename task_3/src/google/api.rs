use serde::Deserialize;

use super::{GoogleApiError, Result};

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct UserInfo {
    pub id: Option<String>,
    pub email: Option<String>,
    pub verified_email: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    /// The picture is URL
    pub picture: Option<String>,
}

pub struct GoogleApi;

impl GoogleApi {
    pub async fn get_userinfo(access_token: String) -> Result<UserInfo> {
        reqwest::Client::new()
            .get("https://www.googleapis.com/oauth2/v1/userinfo")
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|err| GoogleApiError::RequestError {
                message: err.to_string(),
            })?
            .json::<UserInfo>()
            .await
            .map_err(|err| GoogleApiError::InvalidJson {
                message: err.to_string(),
            })
    }
}
