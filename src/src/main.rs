use crate::repository::permissions::{DynPermissionRepositoryTrait, PermissionRepository};
use crate::repository::roles::{DynRoleRepositoryTrait, RoleRepository};
use crate::service::permissions::PermissionService;
use crate::service::roles::RoleService;
use crate::{config::AppConfig, handler::user::RequestHandler};
use clap::Parser;
use dotenv::dotenv;
use madtofan_microservice_common::{
    repository::connection_pool::ServiceConnectionManager, user::user_server::UserServer,
};
use repository::users::{DynUserRepositoryTrait, UserRepository};
use service::users::UserService;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use tonic::transport::Server;

mod config;
mod handler;
mod repository;
mod service;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let config = Arc::new(AppConfig::parse());

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&config.rust_log))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Environment loaded and configuration parsed, initializing Postgres connection...");
    let pg_pool = ServiceConnectionManager::new_pool(&config.database_url)
        .await
        .expect("could not initialize the database connection pool");

    if config.run_migrations {
        info!("migrations enabled, running...");
        sqlx::migrate!()
            .run(&pg_pool)
            .await
            .unwrap_or_else(|err| error!("There was an error during migration: {:?}", err));
    }

    info!("Database configured! initializing repositories...");
    let app_host = &config.service_url;
    let app_port = &config.service_port;
    let app_url = format!("{}:{}", app_host, app_port).parse().unwrap();
    let user_repository = Arc::new(UserRepository::new(pg_pool.clone())) as DynUserRepositoryTrait;
    let role_repository = Arc::new(RoleRepository::new(pg_pool.clone())) as DynRoleRepositoryTrait; //Arc::new(Repository::new(pg_pool.clone())) as DynUserRepositoryTrait;
    let permission_repository =
        Arc::new(PermissionRepository::new(pg_pool.clone())) as DynPermissionRepositoryTrait;

    info!("Repositories initialized, Initializing Services");
    let user_service = Arc::new(UserService::new(user_repository, config));
    let role_service = Arc::new(RoleService::new(role_repository));
    let permission_service = Arc::new(PermissionService::new(permission_repository));

    info!("Services initialized, Initializing Handler");
    let request_handler = RequestHandler::new(user_service, role_service, permission_service);

    info!("Service ready for request at {:#?}!", app_url);
    Server::builder()
        .add_service(UserServer::new(request_handler))
        .serve(app_url)
        .await?;
    Ok(())
}
