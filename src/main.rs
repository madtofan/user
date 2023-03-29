use crate::{config::AppConfig, handler::user::RequestHandler};
use clap::Parser;
use common::repository::connection_pool::ServiceConnectionManager;
use dotenv::dotenv;
use repository::users::{DynUserRepositoryTrait, UserRepository};
use service::users::UserService;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use tonic::transport::Server;
use user::user_server::UserServer;

mod config;
mod handler;
mod repository;
mod service;
pub mod user {
    tonic::include_proto!("user");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().expect("Failed to read .env file, please add a .env file to the project root");

    let config = Arc::new(AppConfig::parse());

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&config.rust_log))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Environment loaded and configuration parsed, initializing Postgres connection and running migrations...");
    let pg_pool = ServiceConnectionManager::new_pool(&config.database_url)
        .await
        .expect("could not initialize the database connection pool");

    if *&config.seed {
        todo!("Migrations is not done yet")
        // info!("migrations enabled, running...");
        // sqlx::migrate!()
        //     .run(&pool)
        //     .await
        //     .context("error while running database migrations")?;
    }

    let app_host = &config.service_url;
    let app_port = &config.service_port;
    let app_url = format!("{}:{}", app_host, app_port).parse().unwrap();
    let user_repository = Arc::new(UserRepository::new(pg_pool.clone())) as DynUserRepositoryTrait;
    let user_service = Arc::new(UserService::new(user_repository, config));
    let request_handler = RequestHandler::new(user_service);

    info!("Service ready for request!");
    Server::builder()
        .add_service(UserServer::new(request_handler))
        .serve(app_url)
        .await?;
    Ok(())
}
