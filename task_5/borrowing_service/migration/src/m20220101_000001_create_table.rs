use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CurrentBorrowing::Table)
                    .if_not_exists()
                    .col(pk_auto(CurrentBorrowing::Id))
                    .col(integer(CurrentBorrowing::UserId))
                    .col(integer_uniq(CurrentBorrowing::BorrowedBookId))
                    .col(timestamp(CurrentBorrowing::BorrowedAt))
                    .col(timestamp(CurrentBorrowing::ExpectedReturnAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(BorrowingHistory::Table)
                    .if_not_exists()
                    .col(pk_auto(BorrowingHistory::Id))
                    .col(integer(BorrowingHistory::UserId))
                    .col(integer(BorrowingHistory::BorrowedBookId))
                    .col(timestamp(BorrowingHistory::BorrowedAt))
                    .col(timestamp(BorrowingHistory::ExpectedReturnAt))
                    .col(timestamp(BorrowingHistory::ReturnedAt))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(CurrentBorrowing::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(BorrowingHistory::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum CurrentBorrowing {
    Table,
    Id,
    UserId,
    BorrowedBookId,
    BorrowedAt,
    ExpectedReturnAt,
}

#[derive(DeriveIden)]
enum BorrowingHistory {
    Table,
    Id,
    UserId,
    BorrowedBookId,
    BorrowedAt,
    ExpectedReturnAt,
    ReturnedAt,
}
