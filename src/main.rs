use crate::config::AppConfig;
use clap::Parser;
use common::repository::connection_pool::ServiceConnectionManager;
use dotenv::dotenv;
use repository::{DynUserRepositoryTrait, UserRepository};
use service::{DynUserServiceTrait, UserService};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use tonic::{transport::Server, Request, Response, Status};
use user::{
    user_server::{User, UserServer},
    LoginRequest, RegisterRequest, UpdateRequest, UserResponse,
};

mod config;
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

    Server::builder()
        .add_service(UserServer::new(request_handler))
        .serve(app_url)
        .await?;
    Ok(())
}

pub struct RequestHandler {
    user_service: DynUserServiceTrait,
}

impl RequestHandler {
    pub fn new(user_service: DynUserServiceTrait) -> Self {
        Self { user_service }
    }
}

#[tonic::async_trait]
impl User for RequestHandler {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        let logged_in_user = self.user_service.login_user(request.into_inner()).await?;

        Ok(Response::new(logged_in_user))
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        let created_user = self
            .user_service
            .register_user(request.into_inner())
            .await?;

        Ok(Response::new(created_user))
    }

    async fn update(
        &self,
        request: Request<UpdateRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        let r = request.into_inner();
        match r.fields {
            Some(fields) => {
                let updated_user = self.user_service.updated_user(r.id, fields).await?;

                Ok(Response::new(updated_user))
            }
            None => Err(Status::new(
                tonic::Code::NotFound,
                "Unable to obtain the field to update the user",
            )),
        }
    }
}
