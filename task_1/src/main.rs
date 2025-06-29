use sea_orm::ActiveModelTrait;
use sea_orm::ColumnTrait;
use sea_orm::ModelTrait;
use std::time::Duration;

use actix_web::{
    App, HttpResponse, HttpServer, Responder, body::BoxBody, guard, http::header::ContentType,
    post, web,
};
use entity::book::{ActiveModel, Model};
use sea_orm::{ConnectOptions, Database, DatabaseConnection, DbErr, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "soapenv:Envelope")]
struct XmlEnvelope {
    #[serde(
        rename = "@xmlns:soapenv",
        skip_deserializing,
        default = "xmlns_soapenv"
    )]
    xmlns_soapenv: String,
    #[serde(rename = "@xmlns:lib", skip_deserializing, default = "xmlns_lib")]
    xmlns_lib: String,
    #[serde(rename = "soapenv:Header", default)]
    header: XmlHeader,
    #[serde(rename = "soapenv:Body")]
    body: XmlBody,
}

impl Default for XmlEnvelope {
    fn default() -> Self {
        Self {
            xmlns_soapenv: xmlns_soapenv(),
            xmlns_lib: xmlns_lib(),
            header: Default::default(),
            body: Default::default(),
        }
    }
}

fn xmlns_soapenv() -> String {
    "http://www.w3.org/2003/05/soap-envelope".to_string()
}

fn xmlns_lib() -> String {
    "http://example.org/library-service".to_string()
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(rename = "soapenv:Header")]
struct XmlHeader {
    // Leave with nothing, the SOAP service doesn't have way to parse header
}

#[derive(Serialize, Deserialize, Default, Debug)]
enum XmlBody {
    #[serde(rename = "lib:Request")]
    Request(XmlRequest),
    #[serde(rename = "lib:Response")]
    Response(XmlResponse),
    #[default]
    Empty,
}

#[derive(Serialize, Deserialize, Debug)]
enum XmlRequest {
    #[serde(rename = "lib:GetBook")]
    GetBook {
        #[serde(rename = "lib:isbn")]
        isbn: String,
    },
    #[serde(rename = "lib:AddBook")]
    AddBook {
        #[serde(rename = "lib:Book")]
        book: Book,
    },
    #[serde(rename = "lib:DeleteBook")]
    DeleteBook {
        #[serde(rename = "lib:isbn")]
        isbn: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
enum XmlResponse {
    #[serde(rename = "lib:BookInfo")]
    BookInfo(Book),
    #[serde(rename = "lib:Message")]
    Message(String),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "lib:Book")]
struct Book {
    #[serde(rename = "lib:isbn")]
    isbn: String,
    #[serde(rename = "lib:title")]
    title: String,
    #[serde(rename = "lib:author")]
    author: String,
    #[serde(rename = "lib:publisher")]
    publisher: String,
    #[serde(rename = "lib:publicationYear")]
    publication_year: i16,
    #[serde(rename = "lib:language")]
    language: String,
}

impl From<Model> for Book {
    fn from(value: Model) -> Self {
        Book {
            isbn: value.isbn,
            title: value.title,
            author: value.author,
            publisher: value.publisher,
            publication_year: value.publication_year,
            language: value.language,
        }
    }
}

impl From<Book> for ActiveModel {
    fn from(value: Book) -> Self {
        ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            isbn: sea_orm::ActiveValue::Set(value.isbn),
            title: sea_orm::ActiveValue::Set(value.title),
            author: sea_orm::ActiveValue::Set(value.author),
            publisher: sea_orm::ActiveValue::Set(value.publisher),
            publication_year: sea_orm::ActiveValue::Set(value.publication_year),
            language: sea_orm::ActiveValue::Set(value.language),
        }
    }
}

impl Responder for XmlEnvelope {
    type Body = BoxBody;

    fn respond_to(self, _req: &actix_web::HttpRequest) -> actix_web::HttpResponse<Self::Body> {
        let body = serde_xml_rs::to_string(&self).unwrap();

        HttpResponse::Ok()
            .content_type(ContentType::xml())
            .body(body)
    }
}

fn invalid_xml_request() -> XmlEnvelope {
    XmlEnvelope {
        body: XmlBody::Response(XmlResponse::Message("Invalid XML request".to_string())),
        ..Default::default()
    }
}

fn db_error(_err: DbErr) -> XmlEnvelope {
    XmlEnvelope {
        body: XmlBody::Response(XmlResponse::Message("Internal error".to_string())),
        ..Default::default()
    }
}

async fn retrieve_book(isbn: String, db: web::Data<DatabaseConnection>) -> XmlEnvelope {
    match entity::prelude::Book::find()
        .filter(entity::book::Column::Isbn.contains(&isbn))
        .one(&**db)
        .await
    {
        Ok(possible_model) => match possible_model {
            Some(book) => XmlEnvelope {
                body: XmlBody::Response(XmlResponse::BookInfo(book.into())),
                ..Default::default()
            },
            None => XmlEnvelope {
                body: XmlBody::Response(XmlResponse::Message("Book doesn't exists".to_string())),
                ..Default::default()
            },
        },
        Err(err) => db_error(err),
    }
}

async fn add_book(book: Book, db: web::Data<DatabaseConnection>) -> XmlEnvelope {
    match ActiveModel::from(book).insert(&**db).await {
        Ok(model) => XmlEnvelope {
            body: XmlBody::Response(XmlResponse::BookInfo(model.into())),
            ..Default::default()
        },
        Err(err) => db_error(err),
    }
}

async fn delete_book(isbn: String, db: web::Data<DatabaseConnection>) -> XmlEnvelope {
    match entity::prelude::Book::find()
        .filter(entity::book::Column::Isbn.contains(isbn))
        .one(&**db)
        .await
    {
        Ok(possible_model) => match possible_model {
            Some(model) => {
                let book: Book = model.clone().into();
                if let Err(err) = model.delete(&**db).await {
                    return db_error(err);
                }

                XmlEnvelope {
                    body: XmlBody::Response(XmlResponse::BookInfo(book)),
                    ..Default::default()
                }
            }
            None => XmlEnvelope {
                body: XmlBody::Response(XmlResponse::Message("Book doesn't exists".to_string())),
                ..Default::default()
            },
        },
        Err(err) => db_error(err),
    }
}

#[post("/library-service")]
async fn library_service(request: String, db: web::Data<DatabaseConnection>) -> impl Responder {
    let Ok(request_xml) = serde_xml_rs::from_str::<XmlEnvelope>(&request) else {
        return invalid_xml_request();
    };

    match request_xml.body {
        XmlBody::Request(xml_request) => match xml_request {
            XmlRequest::GetBook { isbn } => retrieve_book(isbn, db).await,
            XmlRequest::AddBook { book } => add_book(book, db).await,
            XmlRequest::DeleteBook { isbn } => delete_book(isbn, db).await,
        },
        _ => invalid_xml_request(),
    }
}

#[actix::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut opt = ConnectOptions::new("sqlite://books.db");
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .set_schema_search_path("my_schema"); // Setting default PostgreSQL schema

    let db = web::Data::new(Database::connect(opt).await?);

    Ok(HttpServer::new(move || {
        App::new().app_data(db.clone()).service(
            web::scope("")
                .guard(guard::Header("Content-Type", "application/xml"))
                .service(library_service),
        )
    })
    .bind(("localhost", 8000))?
    .run()
    .await?)
}
