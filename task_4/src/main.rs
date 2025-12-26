use std::{collections::BTreeMap, sync::LazyLock, time::Duration};

use actix_web::{
    App, Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
    dev::ServiceRequest,
    get, guard, post,
    web::{self, Data, Json},
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use base64::Engine;
use hmac::Mac;
use jwt::{SignWithKey, VerifyWithKey};
use rand::TryRngCore;
use sea_orm::{
    ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, IntoActiveModel,
    ModelTrait, QueryFilter,
};
use serde::Deserialize;

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
}

#[derive(Deserialize, Debug)]
struct RefreshTokenData {
    refresh_token: String,
}

#[derive(Clone)]
struct AuthUser {
    user_id: i32,
}

impl FromRequest for AuthUser {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let auth_user = req.extensions().get::<AuthUser>().cloned();
        Box::pin(async move {
            auth_user.ok_or(actix_web::error::ErrorUnauthorized(
                "Missing access-token to process a request",
            ))
        })
    }
}

fn server_internal_error() -> HttpResponse {
    HttpResponse::InternalServerError()
        .body("Failed to process the request. Try again another time.")
}

fn invalid_credintals() -> HttpResponse {
    HttpResponse::Unauthorized().body("Invalid username or password.")
}

fn generate_jwt_token(
    user_model: &UserModel,
) -> anyhow::Result<jwt::Token<jwt::Header, BTreeMap<String, String>, jwt::token::Signed>> {
    let key: hmac::Hmac<sha2::Sha256> = hmac::Hmac::new_from_slice(&*JWT_SECRET)?;
    let header = jwt::Header {
        algorithm: jwt::AlgorithmType::Hs256,
        ..Default::default()
    };
    let mut claims = BTreeMap::new();
    claims.insert("sub".to_string(), user_model.id.to_string());
    claims.insert(
        "iat".to_string(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .to_string(),
    );
    claims.insert(
        "exp".to_string(),
        std::time::SystemTime::now()
            .checked_add(Duration::from_mins(10))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .to_string(),
    );

    Ok(jwt::Token::new(header, claims).sign_with_key(&key)?)
}

async fn verify_jwt_token(
    req: ServiceRequest,
    credentials: Option<BearerAuth>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let Some(credentials) = credentials else {
        return Err((
            actix_web::error::ErrorUnauthorized(
                "Missing access-token to process request. Please register at /sign-up or log-in at /sign-in",
            ),
            req,
        ));
    };

    let key: hmac::Hmac<sha2::Sha256> = hmac::Hmac::new_from_slice(&*JWT_SECRET).unwrap();
    let Ok(verified_token): Result<jwt::Token<jwt::Header, BTreeMap<String, String>, _>, _> =
        credentials.token().verify_with_key(&key)
    else {
        return Err((
            actix_web::error::ErrorUnauthorized("Invalid authorization token"),
            req,
        ));
    };

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    if verified_token.claims()["iat"].parse::<u128>().unwrap() > current_time
        || current_time > verified_token.claims()["exp"].parse::<u128>().unwrap()
    {
        return Err((
            actix_web::error::ErrorUnauthorized("Invalid authorization token"),
            req,
        ));
    }

    let auth_user = AuthUser {
        user_id: verified_token.claims()["sub"].parse::<i32>().unwrap(),
    };

    req.extensions_mut().insert(auth_user);
    Ok(req)
}

async fn generate_refresh_token(db: &DatabaseConnection) -> String {
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

async fn save_refresh_token_for(
    user_model: UserModel,
    refresh_token: String,
    db: &DatabaseConnection,
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

#[get("/")]
async fn home(auth_user: AuthUser, db: Data<DatabaseConnection>) -> impl Responder {
    let user = User::find_by_id(auth_user.user_id)
        .one(&**db)
        .await
        .unwrap()
        .unwrap();

    HttpResponse::Ok().body(format!("Hello, {}!", user.username))
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

    dbg!(&user);

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
        passowrd: sea_orm::ActiveValue::Set(hashed_password),
    };

    if User::insert(new_model).exec(&**db).await.is_err() {
        return server_internal_error();
    }

    HttpResponse::Created().body("New user is registered!")
}

#[post("/sign-in")]
async fn sign_in(user: Json<UserData>, db: Data<DatabaseConnection>) -> impl Responder {
    let Ok(model) = User::find()
        .filter(user::Column::Username.eq(&user.username))
        .one(&**db)
        .await
    else {
        return server_internal_error();
    };

    dbg!(&user);

    let Some(user_model) = model else {
        return invalid_credintals();
    };

    let is_matched_password = match bcrypt::verify(user.password.clone(), &user_model.passowrd) {
        Ok(result) => result,
        Err(err) => {
            dbg!(err);
            return server_internal_error();
        }
    };

    if is_matched_password {
        let access_token = generate_jwt_token(&user_model).unwrap();
        let refresh_token = generate_refresh_token(&db).await;
        save_refresh_token_for(user_model, refresh_token.clone(), &db).await;

        HttpResponse::Ok().body(format!(
            "{{\"access_token\" : \"{}\", \"refresh_token\" : \"{}\" }}",
            access_token.as_str(),
            refresh_token
        ))
    } else {
        invalid_credintals()
    }
}

#[post("/refresh")]
async fn refresh(
    request_data: Json<RefreshTokenData>,
    db: Data<DatabaseConnection>,
) -> impl Responder {
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

    //TODO: better to do it in transaction

    let mut mut_rt_model = rt_model.into_active_model();
    mut_rt_model.revoked_at = sea_orm::ActiveValue::Set(Some(chrono::Utc::now()));
    RefreshToken::update(mut_rt_model)
        .exec(&**db)
        .await
        .unwrap();

    let access_token = generate_jwt_token(&user_model).unwrap();
    let refresh_token = generate_refresh_token(&db).await;
    save_refresh_token_for(user_model, refresh_token.clone(), &db).await;

    HttpResponse::Ok().body(format!(
        "{{ \"access_token\" : \"{}\", \"refresh_token\" : \"{}\" }}",
        access_token.as_str(),
        refresh_token,
    ))
}

#[actix::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut opt = ConnectOptions::new("sqlite://users.db");
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .set_schema_search_path("my_schema"); // Setting default PostgreSQL schema

    let db = web::Data::new(Database::connect(opt).await?);

    Ok(HttpServer::new(move || {
        App::new()
            .app_data(db.clone())
            .service(
                web::scope("")
                    .guard(guard::Header("Content-Type", "application/json"))
                    .service(sign_up)
                    .service(sign_in)
                    .service(refresh),
            )
            .service(
                web::scope("")
                    .wrap(actix_web_httpauth::middleware::HttpAuthentication::with_fn(
                        verify_jwt_token,
                    ))
                    .service(home),
            )
    })
    .bind(("localhost", 8000))?
    .run()
    .await?)
}
