use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Order::Table)
                    .if_not_exists()
                    .col(pk_auto(Order::Id))
                    .col(string(Order::CustomerName))
                    .col(string(Order::CustomerEmail))
                    .col(string(Order::CustomerCommentary))
                    .col(string(Order::PriceTotal))
                    .col(timestamp_with_time_zone(Order::CreatedAt))
                    .col(string(Order::Status))
                    .col(string(Order::ShippingAddress))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(OrderItem::Table)
                    .if_not_exists()
                    .col(pk_auto(OrderItem::Id))
                    .col(integer(OrderItem::OrderId))
                    .col(string(OrderItem::Name))
                    .col(integer(OrderItem::Quantity))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_order_info")
                            .from(OrderItem::Table, OrderItem::OrderId)
                            .to(Order::Table, Order::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(OrderItem::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Order::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Order {
    Table,
    Id,
    CustomerName,
    CustomerEmail,
    CustomerCommentary,
    PriceTotal,
    CreatedAt,
    Status,
    ShippingAddress,
}

#[derive(DeriveIden)]
enum OrderItem {
    Table,
    Id,
    OrderId,
    Name,
    Quantity,
}
