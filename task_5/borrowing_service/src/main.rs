use actix_web::{
    App, Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
    dev::ServiceRequest,
    guard, post,
    web::{self, Data, Json},
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use chrono::{DateTime, Utc};
use entity::{borrowing_history, current_borrowing};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use sea_orm::{
    ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, QueryFilter, Select,
    TransactionTrait, TryIntoModel,
};
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
#[allow(unused)]
struct Claims {
    sub: i32,
    role: i32,
    iat: usize,
    exp: usize,
}

#[derive(Clone, Copy)]
#[repr(i32)]
#[allow(unused)]
enum UserRole {
    Admin = 0,
    User,
    Librarian,
}

#[derive(Clone)]
#[allow(unused)]
struct AuthUser {
    user_id: i32,
    user_role: UserRole,
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

#[derive(Deserialize)]
struct BorrowBookData {
    user_id: i32,
    book_id: i32,
    // In RFC 3339 format: YYYY-MM-DDTHH:mm:ss±HH:mm
    expected_return_at: String,
}

#[derive(Deserialize)]
struct ReturnBookData {
    user_id: i32,
    book_id: i32,
}

#[derive(Deserialize)]
struct UnreturnedBooksFilter {
    user_id: i32,
}

trait ApplyFilter<T: EntityTrait> {
    fn apply_filter(&self, selection: Select<T>) -> Select<T>;
}

impl ApplyFilter<current_borrowing::Entity> for UnreturnedBooksFilter {
    fn apply_filter(
        &self,
        selection: Select<current_borrowing::Entity>,
    ) -> Select<current_borrowing::Entity> {
        selection.filter(current_borrowing::Column::UserId.eq(self.user_id))
    }
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

    let Ok(decoding_key) = DecodingKey::from_rsa_pem(include_bytes!("../public.pem")) else {
        return Err((
            actix_web::error::ErrorInternalServerError(
                "Failed to process a request. Try again later.",
            ),
            req,
        ));
    };

    let Ok(verified_token) = decode::<Claims>(
        credentials.token(),
        &decoding_key,
        &Validation::new(Algorithm::RS256),
    ) else {
        return Err((
            actix_web::error::ErrorUnauthorized("Invalid authorization token"),
            req,
        ));
    };

    let Ok(response) = reqwest::Client::new()
        .get(format!(
            "http://user-service/service-api/verify-user/{}",
            verified_token.claims.sub
        ))
        .header(
            "Authorization",
            format!("ApiKey {}", std::env::var("SERVICE_API_KEY").unwrap()),
        )
        .send()
        .await
    else {
        return Err((
            actix_web::error::ErrorInternalServerError(
                "Failed to process a request. Try again later.",
            ),
            req,
        ));
    };

    match response.status() {
        reqwest::StatusCode::OK => (),
        reqwest::StatusCode::NOT_FOUND => {
            return Err((
                actix_web::error::ErrorUnauthorized("Invalid access-token."),
                req,
            ));
        }
        _ => {
            return Err((
                actix_web::error::ErrorInternalServerError(
                    "Failed to process a request. Try again later.",
                ),
                req,
            ));
        }
    }

    let auth_user = AuthUser {
        user_id: verified_token.claims.sub,
        // SAFETY: the role is always valid because the token is verified and signed.
        user_role: unsafe { std::mem::transmute::<i32, UserRole>(verified_token.claims.role) },
    };

    req.extensions_mut().insert(auth_user);
    Ok(req)
}

async fn verify_user(user_id: i32) -> Result<(), HttpResponse> {
    let Ok(response) = reqwest::Client::new()
        .get(format!("http://user-service/service-api/verify-user/{}", user_id))
        .header(
            "Authorization",
            format!("ApiKey {}", std::env::var("SERVICE_API_KEY").unwrap()),
        )
        .send()
        .await
    else {
        return Err(HttpResponse::InternalServerError()
            .body("Failed to process a request. Try again later."));
    };

    match response.status() {
        reqwest::StatusCode::OK => Ok(()),
        reqwest::StatusCode::NOT_FOUND => {
            Err(HttpResponse::Unauthorized().body("Invalid access-token."))
        }
        _ => Err(HttpResponse::InternalServerError()
            .body("Failed to process a request. Try again later.")),
    }
}

async fn verify_book(book_id: i32) -> Result<(), HttpResponse> {
    let Ok(response) = reqwest::Client::new()
        .get(format!(
            "http://library-service/service-api/verify-book/{}",
            book_id
        ))
        .header(
            "Authorization",
            format!("ApiKey {}", std::env::var("SERVICE_API_KEY").unwrap()),
        )
        .send()
        .await
    else {
        return Err(HttpResponse::InternalServerError()
            .body("Failed to process a request. Try again later."));
    };

    match response.status() {
        reqwest::StatusCode::OK => Ok(()),
        reqwest::StatusCode::NOT_FOUND => {
            Err(HttpResponse::BadRequest().body("The book is unknown to borrow."))
        }
        _ => Err(HttpResponse::InternalServerError()
            .body("Failed to process a request. Try again later.")),
    }
}

#[post("/borrow-book")]
async fn borrow_book(
    auth_user: AuthUser,
    data: Json<BorrowBookData>,
    db: Data<DatabaseConnection>,
) -> impl Responder {
    if !matches!(auth_user.user_role, UserRole::Admin | UserRole::Librarian) {
        return HttpResponse::Forbidden()
            .body("You don't have permission to perform this operation.");
    }

    if let Err(response) = verify_user(data.user_id).await {
        return response;
    }

    if let Err(response) = verify_book(data.book_id).await {
        return response;
    }

    let Ok(parsed_data) = DateTime::parse_from_rfc3339(&data.expected_return_at) else {
        return HttpResponse::BadRequest().body(
            "Invalid format of 'expected_return_at'. Expected format is: YYYY-MM-DDTHH:mm:ss±HH:mm",
        );
    };

    let mut new_borrowing = current_borrowing::ActiveModel {
        id: sea_orm::ActiveValue::NotSet,
        user_id: sea_orm::ActiveValue::Set(data.user_id),
        borrowed_book_id: sea_orm::ActiveValue::Set(data.book_id),
        borrowed_at: sea_orm::ActiveValue::Set(Utc::now()),
        expected_return_at: sea_orm::ActiveValue::Set(parsed_data.to_utc()),
    };

    match current_borrowing::Entity::insert(new_borrowing.clone())
        .exec(&**db)
        .await
    {
        Ok(insert_result) => {
            new_borrowing.id = sea_orm::ActiveValue::Set(insert_result.last_insert_id);

            HttpResponse::Created().body(
                serde_json::to_string(&new_borrowing.try_into_model().unwrap()).unwrap_or_default(),
            )
        }
        Err(sea_orm::DbErr::Exec(err)) if err.to_string().contains("unique") => {
            HttpResponse::Conflict().body("The book is already borrowed.")
        }
        Err(_) => HttpResponse::InternalServerError()
            .body("Failed to perform operation. Try again later."),
    }
}

#[post("/return-book")]
async fn return_book(
    auth_user: AuthUser,
    data: Json<ReturnBookData>,
    db: Data<DatabaseConnection>,
) -> impl Responder {
    if !matches!(auth_user.user_role, UserRole::Admin | UserRole::Librarian) {
        return HttpResponse::Forbidden().body("You don't have permissions to perform operations.");
    }

    if let Err(response) = verify_user(data.user_id).await {
        return response;
    }

    if let Err(response) = verify_book(data.book_id).await {
        return response;
    }

    let Ok(txn) = db.begin().await else {
        return HttpResponse::InternalServerError()
            .body("Failed to perform an operation. Try again later.");
    };

    let Ok(maybe_borrowed_book) = current_borrowing::Entity::find()
        .filter(current_borrowing::Column::BorrowedBookId.eq(data.book_id))
        .one(&txn)
        .await
    else {
        return HttpResponse::InternalServerError()
            .body("Failed to perform an operation. Try again later.");
    };

    let Some(borrowed_book) = maybe_borrowed_book else {
        return HttpResponse::Conflict().body("The book is not currently borrowed.");
    };

    if borrowed_book.user_id != data.user_id {
        return HttpResponse::Conflict().body("Book is borrowed by another user.");
    }

    let borrowing_history = borrowing_history::ActiveModel {
        id: sea_orm::ActiveValue::NotSet,
        user_id: sea_orm::ActiveValue::Set(borrowed_book.user_id),
        borrowed_book_id: sea_orm::ActiveValue::Set(borrowed_book.borrowed_book_id),
        borrowed_at: sea_orm::ActiveValue::Set(borrowed_book.borrowed_at),
        expected_return_at: sea_orm::ActiveValue::Set(borrowed_book.expected_return_at),
        returned_at: sea_orm::ActiveValue::Set(Utc::now()),
    };

    if borrowing_history::Entity::insert(borrowing_history)
        .exec(&txn)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .body("Failed to perform an operation. Try again later.");
    }

    if current_borrowing::Entity::delete_by_id(borrowed_book.id)
        .exec(&txn)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .body("Failed to perform an operation. Try again later.");
    };
    if txn.commit().await.is_err() {
        return HttpResponse::InternalServerError()
            .body("Failed to perform an operation. Try again later.");
    }

    HttpResponse::Ok().body("Returned.")
}

#[post("/unreturned-books")]
async fn unreturned_books(
    filters: Json<UnreturnedBooksFilter>,
    db: Data<DatabaseConnection>,
) -> impl Responder {
    let Ok(unreturned_books) = filters
        .apply_filter(current_borrowing::Entity::find())
        .all(&**db)
        .await
    else {
        return HttpResponse::InternalServerError()
            .body("Failed to process an operation. Try again later.");
    };

    HttpResponse::Ok().body(serde_json::to_string(&unreturned_books).unwrap_or_default())
}

#[actix::main]
async fn main() -> anyhow::Result<()> {
    let mut opt = ConnectOptions::new("sqlite://borrowing.db");
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .set_schema_search_path("my_schema");

    let db = web::Data::new(Database::connect(opt).await?);

    Ok(HttpServer::new(move || -> _ {
        App::new()
            .app_data(db.clone())
            .wrap(actix_web_httpauth::middleware::HttpAuthentication::with_fn(
                verify_jwt_token,
            ))
            .service(
                web::scope("/api")
                    .guard(guard::Header("Content-Type", "application/json"))
                    .service(borrow_book)
                    .service(return_book)
                    .service(unreturned_books),
            )
    })
    .bind(("0.0.0.0", 8000))?
    .run()
    .await?)
}
