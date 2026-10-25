use std::{env, error::Error, io};

use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let database_url = env::var("DATABASE_URL").map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "DATABASE_URL is required; copy .env.example to .env",
        )
    })?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;

    sqlx::migrate!("../../migrations").run(&pool).await?;
    println!("database migrations applied");
    Ok(())
}
