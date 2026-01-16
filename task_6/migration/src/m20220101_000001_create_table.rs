use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .if_not_exists()
                    .col(pk_auto(User::Id))
                    .col(string(User::Username))
                    .col(string(User::Password))
                    .col(string(User::Email))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(RefreshToken::Table)
                    .if_not_exists()
                    .col(pk_auto(RefreshToken::Id))
                    .col(string_uniq(RefreshToken::Token))
                    .col(integer(RefreshToken::UserId))
                    .col(timestamp(RefreshToken::ExpiresAt))
                    .col(timestamp_null(RefreshToken::RevokedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_refresh_token")
                            .from(RefreshToken::Table, RefreshToken::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(RefreshToken::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum User {
    Table,
    Id,
    Username,
    Password,
    Email
}

#[derive(DeriveIden)]
enum RefreshToken {
    Table,
    Id,
    UserId,
    Token,
    ExpiresAt,
    RevokedAt,
}
