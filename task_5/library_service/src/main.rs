use std::time::Duration;

use actix_web::{
    App, Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder, delete,
    dev::ServiceRequest,
    get, guard, post,
    web::{self, Data, Json, Path, Query},
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use entity::book;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use sea_orm::{
    ColumnTrait, ConnectOptions, Database, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
    Select, TryIntoModel, sqlx::types::chrono,
};
use serde::Deserialize;

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

struct ServiceAccess {
    api_key: String,
}

impl FromRequest for ServiceAccess {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn Future<Output = Result<ServiceAccess, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        fn unauthorized_error() -> actix_web::Error {
            actix_web::error::ErrorUnauthorized("You don't have permission to process a request")
        }

        let header = req.headers().get("Authorization").cloned();
        Box::pin(async move {
            header.ok_or(unauthorized_error()).and_then(|header| {
                let Ok(header_value) = header.to_str() else {
                    return Err(unauthorized_error());
                };

                if !header_value.starts_with("ApiKey") {
                    return Err(unauthorized_error());
                }

                let api_key = header_value.trim_start_matches("ApiKey ").to_string();
                if api_key != std::env::var("SERVICE_API_KEY").unwrap() {
                    return Err(unauthorized_error());
                }

                Ok(ServiceAccess { api_key })
            })
        })
    }
}

#[derive(Deserialize)]
struct Book {
    title: String,
    author: String,
    /// In RFC 3339 format: YYYY-MM-DDTHH:mm:ss±HH:mm
    publication_date: String,
}

#[derive(Deserialize)]
struct BookFilters {
    title: Option<String>,
    author: Option<String>,
}

trait ApplyFilters<T: EntityTrait> {
    fn apply_filters(&self, entity: Select<T>) -> Select<T>;
}

impl ApplyFilters<book::Entity> for BookFilters {
    fn apply_filters(&self, mut entity: Select<book::Entity>) -> Select<book::Entity> {
        if let Some(title) = &self.title {
            entity = entity.filter(book::Column::Title.eq(title.clone()));
        }

        if let Some(author) = &self.author {
            entity = entity.filter(book::Column::Author.eq(author.clone()));
        }

        entity
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

mod errors {
    use actix_web::HttpResponse;

    pub fn internal_server_error(msg: &'static str) -> HttpResponse {
        HttpResponse::InternalServerError().body(msg)
    }
}

#[get("/books")]
async fn get_books(
    book_filters: Query<BookFilters>,
    db: Data<DatabaseConnection>,
) -> impl Responder {
    const DEFAULT_ERROR_MSG: &str = "Cannot retrieve books at this moment. Try again later.";

    let Ok(books) = book_filters
        .apply_filters(book::Entity::find())
        .all(&**db)
        .await
    else {
        return errors::internal_server_error(DEFAULT_ERROR_MSG);
    };

    let Ok(json_data) = serde_json::to_string(&books) else {
        return errors::internal_server_error(DEFAULT_ERROR_MSG);
    };

    HttpResponse::Ok().body(json_data)
}

#[get("/books/{id}")]
async fn get_book_by_id(id: Path<i32>, db: Data<DatabaseConnection>) -> impl Responder {
    const DEFAULT_ERROR_MSG: &str = "Cannot retrieve a book at this moment. Try again later.";
    let Ok(book) = book::Entity::find_by_id(*id).one(&**db).await else {
        return errors::internal_server_error(DEFAULT_ERROR_MSG);
    };

    let Some(book) = book else {
        return HttpResponse::NotFound().body("The requesting item is not exists.");
    };

    let Ok(json_data) = serde_json::to_string(&book) else {
        return errors::internal_server_error(DEFAULT_ERROR_MSG);
    };

    HttpResponse::Ok().body(json_data)
}

#[post("/books")]
async fn add_new_book(
    auth_user: AuthUser,
    book: Json<Book>,
    db: Data<DatabaseConnection>,
) -> impl Responder {
    if !matches!(auth_user.user_role, UserRole::Admin | UserRole::Librarian) {
        return HttpResponse::Forbidden().body("You don't have permission to process a request.");
    }

    if book.title.trim().is_empty() {
        return HttpResponse::BadRequest().body("The title of the book is either empty or blank.");
    }

    if book.author.trim().is_empty() {
        return HttpResponse::BadRequest().body("The author of the book is either empty or blank");
    }

    let Ok(datetime) = chrono::DateTime::parse_from_rfc3339(&book.publication_date) else {
        return HttpResponse::BadRequest().body("The publication date of the book is in incorrect format. Expected format YYYY-MM_DDTHH:mm:ss±HH:mm");
    };

    let mut new_book = book::ActiveModel {
        id: sea_orm::ActiveValue::NotSet,
        title: sea_orm::ActiveValue::Set(book.title.clone()),
        author: sea_orm::ActiveValue::Set(book.author.clone()),
        publication_date: sea_orm::ActiveValue::Set(datetime.to_utc()),
    };

    match book::Entity::insert(new_book.clone()).exec(&**db).await {
        Ok(insert_result) => {
            new_book.id = sea_orm::ActiveValue::Set(insert_result.last_insert_id);
            let json_data =
                serde_json::to_string(&new_book.try_into_model().unwrap()).unwrap_or_default();
            HttpResponse::Created().body(json_data)
        }
        Err(DbErr::Exec(err)) if err.to_string().contains("unique") => {
            HttpResponse::Conflict().body("The book with the same title and author is exists.")
        }
        Err(_) => {
            HttpResponse::InternalServerError().body("Failed to persist a book. Try again later.")
        }
    }
}

#[delete("/books/{id}")]
async fn delete_book(
    auth_user: AuthUser,
    book_id: Path<i32>,
    db: Data<DatabaseConnection>,
) -> impl Responder {
    if !matches!(auth_user.user_role, UserRole::Admin | UserRole::Librarian) {
        return HttpResponse::Forbidden().body("You don't have permissions to perform a request.");
    }

    if book::Entity::delete_by_id(*book_id)
        .exec(&**db)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .body("Failed to process a request. Try again later.");
    }

    HttpResponse::NoContent().body("Successfully deleted an item.")
}

#[get("/verify-book/{id}")]
async fn verify_book(
    _service_access: ServiceAccess,
    book_id: Path<i32>,
    db: Data<DatabaseConnection>,
) -> impl Responder {
    let Ok(book) = book::Entity::find_by_id(*book_id).one(&**db).await else {
        return HttpResponse::InternalServerError()
            .body("Failed to perform an operation. Try again later.");
    };

    if book.is_none() {
        return HttpResponse::NotFound().body("The requested book is unknown.");
    }

    HttpResponse::Ok().body("The book is valid")
}

#[actix::main]
async fn main() -> anyhow::Result<()> {
    let mut opt = ConnectOptions::new("sqlite://books.db");
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
            .service(web::scope("/service-api").service(verify_book))
            .service(
                web::scope("/api")
                    .wrap(actix_web_httpauth::middleware::HttpAuthentication::with_fn(
                        verify_jwt_token,
                    ))
                    .service(
                        web::scope("")
                            .guard(guard::Header("Content-Type", "application/json"))
                            .service(add_new_book),
                    )
                    .service(
                        web::scope("")
                            .service(get_books)
                            .service(get_book_by_id)
                            .service(delete_book),
                    ),
            )
    })
    .bind(("0.0.0.0", 8000))?
    .run()
    .await?)
}
