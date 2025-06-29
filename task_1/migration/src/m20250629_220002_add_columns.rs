use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_column("book", "publisher").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Book::Table)
                        .add_column(string(Book::Publisher))
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("book", "publication_year").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Book::Table)
                        .add_column(small_integer(Book::PublicationYear))
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("book", "language").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Book::Table)
                        .add_column(string(Book::Language))
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Book::Table)
                    .drop_column(Book::Publisher)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Book::Table)
                    .drop_column(Book::PublicationYear)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Book::Table)
                    .drop_column(Book::Language)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Book {
    Table,
    Publisher,
    PublicationYear,
    Language,
}
