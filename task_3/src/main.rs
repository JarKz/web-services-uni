use actix_web::{
    App, FromRequest, HttpResponse, HttpServer, Responder, ResponseError, cookie::Cookie, get,
    http::header, middleware::Logger, web,
};
use derive_more::{Display, Error};
use google::{
    api::GoogleApi,
    oauth2::{GoogleOauth, GoogleOauthResult, UserInfoScope},
};
use log::error;
use serde::Deserialize;

mod google;

const DEFAULT_STATE: &str = "bebraaa2134";

struct AuthToken {
    token: String,
}

#[derive(Debug, Display, Error)]
#[display("Missing \"access_token\" in cookie.")]
struct MissingAccessToken;

impl ResponseError for MissingAccessToken {}

impl FromRequest for AuthToken {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let access_token = req.cookie("access_token");
        Box::pin(async move {
            Ok(AuthToken {
                token: access_token
                    .and_then(|cookie| {
                        if !cookie.value().is_empty() {
                            Some(cookie.value().to_owned())
                        } else {
                            None
                        }
                    })
                    .ok_or(MissingAccessToken)?,
            })
        })
    }
}

#[derive(Debug, Deserialize)]
struct State {
    state: String,
}
fn permanent_redirect_to(location: String) -> HttpResponse {
    HttpResponse::PermanentRedirect()
        .append_header((header::LOCATION, location))
        .finish()
}

#[get("/home")]
async fn homepage(auth: Option<AuthToken>, google_oauth: web::Data<GoogleOauth>) -> impl Responder {
    match auth {
        None => permanent_redirect_to(
            google_oauth.make_redirect_url(
                [UserInfoScope::Email, UserInfoScope::Profile]
                    .iter()
                    .map(UserInfoScope::to_string)
                    .collect(),
                DEFAULT_STATE.to_string(),
            ),
        ),
        Some(AuthToken { token }) => {
            let user_info = match GoogleApi::get_userinfo(token).await {
                Ok(user_info) => user_info,
                Err(err) => {
                    error!("{err}");

                    return HttpResponse::InternalServerError()
                        .body("Failed to get data from Google.");
                }
            };

            HttpResponse::Ok().body(format!(
                "Hello, {}",
                user_info
                    .name
                    .expect("The 'profile' scope of user info is providen")
            ))
        }
    }
}

#[get("/oauth/google")]
async fn oauth_google(
    web::Query(shared_state): web::Query<State>,
    web::Query(google_oauth_result): web::Query<GoogleOauthResult>,
    google_oauth: web::Data<GoogleOauth>,
) -> impl Responder {
    if shared_state.state != DEFAULT_STATE {
        return permanent_redirect_to(format!("/oauth/failed?message=Invalid state"));
    }

    match google_oauth_result {
        GoogleOauthResult::Success { code } => match google_oauth.make_token(&code).await {
            Ok(token) => HttpResponse::PermanentRedirect()
                .cookie(
                    Cookie::build("access_token", token.access_token)
                        .secure(true)
                        .http_only(true)
                        .same_site(actix_web::cookie::SameSite::Lax)
                        .path("/")
                        .finish(),
                )
                .append_header((header::LOCATION, "/home"))
                .finish(),
            Err(error) => permanent_redirect_to(format!("/oauth/failed?message={error}")),
        },
        GoogleOauthResult::Error { error } => {
            permanent_redirect_to(format!("/oauth/failed?message={error}"))
        }
    }
}

#[derive(Debug, Deserialize)]
struct OauthFailed {
    message: String,
}

#[get("/oauth/failed")]
async fn oauth_failed(message: web::Query<OauthFailed>) -> impl Responder {
    format!("OAuth failed. Reason: {}", &message.0.message)
}

#[get("/oauth/logout")]
async fn oauth_logout() -> impl Responder {
    HttpResponse::Ok()
        .cookie(
            Cookie::build("access_token", "")
                .secure(true)
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Lax)
                .path("/")
                .finish(),
        )
        .body("Successful logout!")
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let google_oauth = web::Data::new(GoogleOauth {
        redirect_uri: "http://localhost:8000/oauth/google".to_string(),
        client_id: std::env::var("CLIENT_ID")?,
        client_secret: std::env::var("CLIENT_SECRET")?,
    });

    Ok(HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(google_oauth.clone())
            .service(homepage)
            .service(oauth_google)
            .service(oauth_failed)
            .service(oauth_logout)
    })
    .bind(("localhost", 8000))?
    .run()
    .await?)
}
