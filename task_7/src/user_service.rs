use std::{sync::LazyLock, time::Duration};

use actix_web::{
    FromRequest, HttpResponse, Responder,
    cookie::Cookie,
    post,
    web::{Data, Json},
};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::TryRngCore;
use sea_orm::{IntoActiveModel, TransactionTrait, prelude::*};
use serde::{Deserialize, Serialize};

use entity::{
    refresh_token::{self, ActiveModel as MutableRefreshTokenModel, Entity as RefreshToken},
    user::{self, ActiveModel as MutableUserModel, Entity as User, Model as UserModel},
};

static JWT_SECRET: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let mut key = [0; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut key).unwrap();
    key
});

#[derive(Deserialize, Debug)]
struct UserData {
    username: String,
    password: String,
    email: String,
}

#[derive(Deserialize, Debug)]
struct LoginUserData {
    username: String,
    password: String,
}

#[derive(Deserialize, Debug)]
struct RefreshTokenData {
    refresh_token: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: i32,
    iat: usize,
    exp: usize,
}

pub struct AuthUser {
    pub user_id: i32,
}

impl FromRequest for AuthUser {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn Future<Output = Result<AuthUser, Self::Error>>>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let cookie = req.cookie("access_token");
        Box::pin(async move {
            let Some(cookie_token) = cookie else {
                return Err(actix_web::error::ErrorUnauthorized(
                    "Missing access token. Sign in at /sign-in",
                ));
            };

            let token = cookie_token.value().trim();
            if token.is_empty() {
                return Err(actix_web::error::ErrorUnauthorized(
                    "Missing access token. Sign in at /sign-in",
                ));
            }

            let Ok(verified_token) = decode::<Claims>(
                token,
                &DecodingKey::from_secret(&*JWT_SECRET),
                &Validation::new(Algorithm::HS256),
            ) else {
                return Err(actix_web::error::ErrorUnauthorized(
                    "Invalid authorization token",
                ));
            };

            Ok(AuthUser {
                user_id: verified_token.claims.sub,
            })
        })
    }
}

impl FromRequest for RefreshTokenData {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn Future<Output = Result<RefreshTokenData, Self::Error>>>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let cookie = req.cookie("refresh_token");
        Box::pin(async move {
            let Some(cookie_token) = cookie else {
                return Err(actix_web::error::ErrorUnauthorized(
                    "Missing refresh token. Sign in at /sign-in",
                ));
            };

            let refresh_token = cookie_token.value().trim().to_owned();
            if refresh_token.is_empty() {
                return Err(actix_web::error::ErrorUnauthorized(
                    "Missing refresh token. Sign in at /sign-in",
                ));
            }

            Ok(RefreshTokenData { refresh_token })
        })
    }
}

fn server_internal_error() -> HttpResponse {
    HttpResponse::InternalServerError().body("")
}

fn invalid_credintals() -> HttpResponse {
    HttpResponse::Unauthorized().body("Invalid username or password.")
}

fn generate_jwt_token(user_model: &UserModel) -> anyhow::Result<String> {
    let claims = Claims {
        sub: user_model.id,
        iat: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as usize,
        exp: std::time::SystemTime::now()
            .checked_add(Duration::from_mins(10))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as usize,
    };

    Ok(encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&*JWT_SECRET),
    )?)
}

async fn generate_refresh_token<Db: ConnectionTrait>(db: &Db) -> String {
    let mut token = [0; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut token).unwrap();

    let mut token_string = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(token);

    let mut result = RefreshToken::find()
        .filter(refresh_token::Column::Token.eq(token_string.clone()))
        .one(db)
        .await
        .unwrap();

    while result.is_some() {
        token = [0; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut token).unwrap();

        token_string = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(token);

        result = RefreshToken::find()
            .filter(refresh_token::Column::Token.eq(token_string.clone()))
            .one(db)
            .await
            .unwrap();
    }

    token_string
}

async fn save_refresh_token_for<Db: ConnectionTrait>(
    user_model: UserModel,
    refresh_token: String,
    db: &Db,
) {
    let mutable_rt_model = MutableRefreshTokenModel {
        id: sea_orm::ActiveValue::NotSet,
        token: sea_orm::ActiveValue::Set(refresh_token),
        user_id: sea_orm::ActiveValue::Set(user_model.id),
        expires_at: sea_orm::ActiveValue::Set(
            chrono::Utc::now()
                .checked_add_days(chrono::Days::new(7))
                .unwrap(),
        ),
        revoked_at: sea_orm::ActiveValue::NotSet,
    };

    RefreshToken::insert(mutable_rt_model)
        .exec(db)
        .await
        .unwrap();
}

#[post("/sign-up")]
async fn sign_up(user: Json<UserData>, db: Data<DatabaseConnection>) -> impl Responder {
    let Ok(model) = User::find()
        .filter(user::Column::Username.eq(&user.username))
        .one(&**db)
        .await
    else {
        return server_internal_error();
    };

    if model.is_some() {
        return HttpResponse::Conflict()
            .body("Unfortunately, the username is occupied. Try another, please..");
    }

    let hashed_password = match bcrypt::hash(user.password.clone(), 12) {
        Ok(result) => result,
        Err(err) => {
            dbg!(err);
            return server_internal_error();
        }
    };

    let new_model = MutableUserModel {
        id: sea_orm::ActiveValue::NotSet,
        username: sea_orm::ActiveValue::Set(user.username.clone()),
        password: sea_orm::ActiveValue::Set(hashed_password),
        email: sea_orm::ActiveValue::set(user.email.clone()),
    };

    if User::insert(new_model).exec(&**db).await.is_err() {
        return server_internal_error();
    }

    HttpResponse::Created().body("New user is registered!")
}

#[post("/sign-in")]
async fn sign_in(user: Json<LoginUserData>, db: Data<DatabaseConnection>) -> impl Responder {
    let Ok(model) = User::find()
        .filter(user::Column::Username.eq(&user.username))
        .one(&**db)
        .await
    else {
        return server_internal_error();
    };

    let Some(user_model) = model else {
        return invalid_credintals();
    };

    let is_matched_password = match bcrypt::verify(user.password.clone(), &user_model.password) {
        Ok(result) => result,
        Err(err) => {
            dbg!(err);
            return server_internal_error();
        }
    };

    if is_matched_password {
        let access_token = generate_jwt_token(&user_model).unwrap();
        let refresh_token = generate_refresh_token(&**db).await;
        save_refresh_token_for(user_model, refresh_token.clone(), &**db).await;

        HttpResponse::MovedPermanently()
            .append_header((actix_web::http::header::LOCATION, "/"))
            .cookie(
                Cookie::build("access_token", access_token)
                    .http_only(true)
                    .secure(true)
                    .same_site(actix_web::cookie::SameSite::Lax)
                    .path("/")
                    .finish(),
            )
            .cookie(
                Cookie::build("refresh_token", refresh_token)
                    .http_only(true)
                    .secure(true)
                    .same_site(actix_web::cookie::SameSite::Lax)
                    .path("/")
                    .finish(),
            )
            .finish()
    } else {
        invalid_credintals()
    }
}

#[post("/refresh")]
async fn refresh(request_data: RefreshTokenData, db: Data<DatabaseConnection>) -> impl Responder {
    let Ok(rt_model) = RefreshToken::find()
        .filter(refresh_token::Column::Token.eq(request_data.refresh_token.clone()))
        .one(&**db)
        .await
    else {
        return server_internal_error();
    };

    let Some(rt_model) = rt_model else {
        return HttpResponse::Unauthorized()
            .body("Refresh token is invalid or expired. Please sign in again.");
    };

    if rt_model.revoked_at.is_some() || rt_model.expires_at < chrono::Utc::now() {
        return HttpResponse::Unauthorized()
            .body("Refresh token is invalid or expired. Please sign in again.");
    }

    let Ok(user_model) = rt_model.find_related(User).one(&**db).await else {
        return server_internal_error();
    };

    let Some(user_model) = user_model else {
        return server_internal_error();
    };

    let Ok(txn) = db.begin().await else {
        return server_internal_error();
    };

    let mut mut_rt_model = rt_model.into_active_model();
    mut_rt_model.revoked_at = sea_orm::ActiveValue::Set(Some(chrono::Utc::now()));

    RefreshToken::update(mut_rt_model).exec(&txn).await.unwrap();

    let access_token = generate_jwt_token(&user_model).unwrap();
    let refresh_token = generate_refresh_token(&txn).await;
    save_refresh_token_for(user_model, refresh_token.clone(), &txn).await;

    if txn.commit().await.is_err() {
        return server_internal_error();
    }

    HttpResponse::Ok()
        .cookie(
            Cookie::build("access_token", access_token)
                .http_only(true)
                .secure(true)
                .same_site(actix_web::cookie::SameSite::Lax)
                .path("/")
                .finish(),
        )
        .cookie(
            Cookie::build("refresh_token", refresh_token)
                .http_only(true)
                .secure(true)
                .same_site(actix_web::cookie::SameSite::Lax)
                .path("/")
                .finish(),
        )
        .body("{ \"message\": \"Refresh token is updated\" }")
}
