use std::{sync::Arc, time::SystemTime};

use async_trait::async_trait;
use madtofan_microservice_common::repository::connection_pool::ServiceConnectionPool;
use mockall::automock;
use sqlx::{types::time::OffsetDateTime, FromRow};

#[derive(FromRow)]
pub struct PermissionEntity {
    pub id: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub name: String,
}

impl Default for PermissionEntity {
    fn default() -> Self {
        PermissionEntity {
            id: 1,
            created_at: OffsetDateTime::from(SystemTime::now()),
            updated_at: OffsetDateTime::from(SystemTime::now()),
            name: String::from("default permission name"),
        }
    }
}

#[automock]
#[async_trait]
pub trait PermissionRepositoryTrait {
    async fn create_permission(&self, name: &str) -> anyhow::Result<PermissionEntity>;
    async fn delete_permission(&self, name: &str) -> anyhow::Result<Option<PermissionEntity>>;
    async fn get_permissions(&self) -> anyhow::Result<PermissionEntity>;
}

pub type DynPermissionRepositoryTrait = Arc<dyn PermissionRepositoryTrait + Send + Sync>;

#[derive(Clone)]
pub struct PermissionRepository {
    pool: ServiceConnectionPool,
}

impl PermissionRepository {
    pub fn new(pool: ServiceConnectionPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionRepositoryTrait for PermissionRepository {
    async fn create_permission(&self, name: &str) -> anyhow::Result<PermissionEntity> {
        todo!()
    }
    async fn delete_permission(&self, name: &str) -> anyhow::Result<Option<PermissionEntity>> {
        todo!()
    }
    async fn get_permissions(&self) -> anyhow::Result<PermissionEntity> {
        todo!()
    }
}
