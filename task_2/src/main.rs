use std::{str::FromStr, time::Duration};

use actix_web::{
    App, HttpResponse, HttpServer, Responder, delete, get, middleware::Logger, patch, post, web,
};
use derive_more::{Display, FromStr};
use entity::{
    order::{ActiveModel as OrderActiveModel, Model as OrderModel},
    order_item::{
        ActiveModel as OrderItemActiveModel, Column as OrderItemColumn, Model as OrderItemModel,
    },
    prelude::{Order as OrderEntity, OrderItem as OrderItemEntity},
};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectOptions, Database, DatabaseConnection,
    EntityTrait, IntoActiveModel, ModelTrait, QueryFilter, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize)]
struct Order {
    id: Option<i32>,
    customer_name: String,
    customer_email: String,
    customer_commentary: String,
    /// Due to complexity of numerical computations and unacceptability of float-numbers, the
    /// price_total will be stored as string.
    price_total: String,
    items: Vec<OrderItem>,
    #[serde(skip_deserializing, default)]
    created_at: Option<OffsetDateTime>,
    #[serde(default)]
    status: OrderStatus,
    shipping_address: String,
}

#[derive(Debug, Deserialize)]
struct OrderModification {
    customer_name: Option<String>,
    customer_email: Option<String>,
    customer_commentary: Option<String>,
    price_total: Option<String>,
    items: Option<Vec<OrderItem>>,
    status: Option<OrderStatus>,
    shipping_address: Option<String>,
}

impl OrderModification {
    fn is_empty(&self) -> bool {
        self.customer_name.is_none()
            && self.customer_email.is_none()
            && self.customer_commentary.is_none()
            && self.price_total.is_none()
            && self.items.is_none()
            && self.status.is_none()
            && self.shipping_address.is_none()
    }

    fn update_active_model(
        self,
        order_active_model: &mut OrderActiveModel,
    ) -> Option<Vec<OrderItem>> {
        if let Some(customer_name) = self.customer_name {
            order_active_model.customer_name = ActiveValue::Set(customer_name)
        }
        if let Some(customer_email) = self.customer_email {
            order_active_model.customer_email = ActiveValue::Set(customer_email)
        }
        if let Some(customer_commentary) = self.customer_commentary {
            order_active_model.customer_commentary = ActiveValue::Set(customer_commentary)
        }
        if let Some(price_total) = self.price_total {
            order_active_model.price_total = ActiveValue::Set(price_total)
        }
        if let Some(status) = self.status {
            order_active_model.status = ActiveValue::Set(status.to_string())
        }
        if let Some(shipping_address) = self.shipping_address {
            order_active_model.shipping_address = ActiveValue::Set(shipping_address)
        }

        self.items
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OrderItem {
    name: String,
    quantity: i32,
}

#[derive(Default, Debug, Serialize, Deserialize, Display, FromStr)]
enum OrderStatus {
    #[default]
    #[serde(rename = "pending")]
    #[display("pending")]
    Pending,
    #[serde(rename = "shipped")]
    #[display("shipped")]
    Shipped,
    #[serde(rename = "delivered")]
    #[display("delivered")]
    Delivered,
    #[serde(rename = "cancelled")]
    #[display("cancelled")]
    Cancelled,
}

impl From<Order> for OrderActiveModel {
    fn from(value: Order) -> Self {
        Self {
            id: value
                .id
                .map(|id| ActiveValue::Set(id))
                .unwrap_or(ActiveValue::NotSet),
            customer_name: ActiveValue::Set(value.customer_name),
            customer_email: ActiveValue::Set(value.customer_email),
            customer_commentary: ActiveValue::Set(value.customer_commentary),
            price_total: ActiveValue::Set(value.price_total),
            created_at: ActiveValue::Set(value.created_at.unwrap()),
            status: ActiveValue::Set(value.status.to_string()),
            shipping_address: ActiveValue::Set(value.shipping_address),
        }
    }
}

impl OrderItem {
    fn into_active_model(self, order_id: i32) -> OrderItemActiveModel {
        OrderItemActiveModel {
            id: ActiveValue::NotSet,
            order_id: ActiveValue::Set(order_id),
            name: ActiveValue::Set(self.name),
            quantity: ActiveValue::Set(self.quantity),
        }
    }
}

impl From<OrderItemModel> for OrderItem {
    fn from(value: OrderItemModel) -> Self {
        Self {
            name: value.name,
            quantity: value.quantity,
        }
    }
}

impl From<(OrderModel, Vec<OrderItemModel>)> for Order {
    fn from((order_model, order_items_model): (OrderModel, Vec<OrderItemModel>)) -> Self {
        Self {
            id: Some(order_model.id),
            customer_name: order_model.customer_name,
            customer_email: order_model.customer_email,
            customer_commentary: order_model.customer_commentary,
            price_total: order_model.price_total,
            items: order_items_model.into_iter().map(OrderItem::from).collect(),
            created_at: Some(order_model.created_at),
            status: OrderStatus::from_str(&order_model.status)
                .expect("There should be valid enum variant name in database"),
            shipping_address: order_model.shipping_address,
        }
    }
}

fn database_error_response() -> HttpResponse {
    HttpResponse::InternalServerError()
        .body("{\"message\":\"Server can't handle this request. Try later.\"}")
}

#[get("/orders")]
async fn get_orders(db: web::Data<DatabaseConnection>) -> impl Responder {
    let Ok(data) = OrderEntity::find()
        .find_with_related(OrderItemEntity)
        .all(&**db)
        .await
    else {
        return database_error_response();
    };

    let orders: Vec<Order> = data.into_iter().map(Order::from).collect();
    HttpResponse::Ok().body(
        serde_json::to_string(&orders)
            .expect("The data of orders should be valid to serialize into JSON"),
    )
}

#[get("/orders/{id}")]
async fn get_order(order_id: web::Path<i32>, db: web::Data<DatabaseConnection>) -> impl Responder {
    let order_model = match OrderEntity::find_by_id(*order_id).one(&**db).await {
        Ok(Some(model)) => model,
        Ok(None) => {
            return HttpResponse::NotFound()
                .body("{\"message\": \"The requested order doesn't exists.\"}");
        }
        Err(_err) => {
            return database_error_response();
        }
    };

    let Ok(order_items_model) = order_model.find_related(OrderItemEntity).all(&**db).await else {
        return database_error_response();
    };

    let order = Order::from((order_model, order_items_model));
    HttpResponse::Ok().body(
        serde_json::to_string(&order)
            .expect("The data of order should be valid to serialize into JSON"),
    )
}

#[post("/orders")]
async fn add_order(
    order_json: web::Json<Order>,
    db: web::Data<DatabaseConnection>,
) -> impl Responder {
    let mut order = order_json.0;
    order.created_at = Some(OffsetDateTime::now_utc());

    let order_items = order.items.clone();
    let order_active_model = OrderActiveModel::from(order);

    let Ok(transaction) = db.begin().await else {
        return database_error_response();
    };

    let Ok(order_model) = order_active_model.insert(&transaction).await else {
        transaction.rollback().await.unwrap();
        return database_error_response();
    };

    if !order_items.is_empty() {
        let order_items_active_model: Vec<OrderItemActiveModel> = order_items
            .into_iter()
            .map(|order_item| order_item.into_active_model(order_model.id))
            .collect();
        if let Err(_err) = OrderItemEntity::insert_many(order_items_active_model)
            .exec(&transaction)
            .await
        {
            transaction.rollback().await.unwrap();
            return database_error_response();
        }
    }

    transaction.commit().await.unwrap();

    let Ok(order_items_model) = order_model.find_related(OrderItemEntity).all(&**db).await else {
        return database_error_response();
    };

    let order = Order::from((order_model, order_items_model));
    HttpResponse::Created().body(
        serde_json::to_string(&order)
            .expect("The data of order should be valid to serialize into JSON"),
    )
}

#[patch("/orders/{id}")]
async fn modify_order(
    order_id: web::Path<i32>,
    order_modification: web::Json<OrderModification>,
    db: web::Data<DatabaseConnection>,
) -> impl Responder {
    if order_modification.is_empty() {
        return HttpResponse::BadRequest()
            .body("{\"message\": \"There's should be a valid JSON body for data modification.\"}");
    }

    let order_model = match OrderEntity::find_by_id(*order_id).one(&**db).await {
        Ok(Some(model)) => model,
        Ok(None) => {
            return HttpResponse::NotFound()
                .body("{\"message\": \"The requested order doesn't exists.\"}");
        }
        Err(_err) => {
            return database_error_response();
        }
    };
    let mut order_active_model = order_model.into_active_model();
    let order_items_modification = order_modification
        .0
        .update_active_model(&mut order_active_model);

    let Ok(transaction) = db.begin().await else {
        return database_error_response();
    };

    let Ok(updated_order_model) = order_active_model.update(&transaction).await else {
        transaction.rollback().await.unwrap();
        return database_error_response();
    };

    if let Some(order_items_modification) = order_items_modification {
        if let Err(_err) = OrderItemEntity::delete_many()
            .filter(OrderItemColumn::OrderId.eq(updated_order_model.id))
            .exec(&transaction)
            .await
        {
            transaction.rollback().await.unwrap();
            return database_error_response();
        }

        if !order_items_modification.is_empty() {
            let order_items_active_model: Vec<OrderItemActiveModel> = order_items_modification
                .into_iter()
                .map(|order_item| order_item.into_active_model(updated_order_model.id))
                .collect();
            if let Err(_err) = OrderItemEntity::insert_many(order_items_active_model)
                .exec(&transaction)
                .await
            {
                transaction.rollback().await.unwrap();
                return database_error_response();
            }
        }
    }

    transaction.commit().await.unwrap();

    let Ok(order_items_model) = updated_order_model
        .find_related(OrderItemEntity)
        .all(&**db)
        .await
    else {
        return database_error_response();
    };

    let order = Order::from((updated_order_model, order_items_model));
    HttpResponse::Created().body(
        serde_json::to_string(&order)
            .expect("The data of order should be valid to serialize into JSON"),
    )
}

#[delete("/orders/{id}")]
async fn delete_order(
    order_id: web::Path<i32>,
    db: web::Data<DatabaseConnection>,
) -> impl Responder {
    let Ok(transaction) = db.begin().await else {
        return database_error_response();
    };

    let Ok(_delete_result) = OrderEntity::delete_by_id(*order_id)
        .exec(&transaction)
        .await
    else {
        transaction.rollback().await.unwrap();
        return database_error_response();
    };

    transaction.commit().await.unwrap();

    HttpResponse::NoContent().body("")
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let mut opt = ConnectOptions::new("postgres://postgres:test@localhost/orders");
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8));

    let db = web::Data::new(Database::connect(opt).await?);

    Ok(HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(db.clone())
            .service(get_orders)
            .service(get_order)
            .service(add_order)
            .service(modify_order)
            .service(delete_order)
    })
    .bind(("localhost", 8000))?
    .run()
    .await?)
}
