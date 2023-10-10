use std::{sync::Arc, time::SystemTime};

use async_trait::async_trait;
use madtofan_microservice_common::repository::connection_pool::ServiceConnectionPool;
use mockall::automock;
use sqlx::{types::time::OffsetDateTime, FromRow};

#[derive(FromRow)]
pub struct RoleEntity {
    pub id: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub name: String,
}

#[derive(FromRow)]
pub struct RolePermissionsEntity {
    pub id: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub name: String,
    pub permissions: Vec<String>,
}

impl Default for RoleEntity {
    fn default() -> Self {
        RoleEntity {
            id: 1,
            created_at: OffsetDateTime::from(SystemTime::now()),
            updated_at: OffsetDateTime::from(SystemTime::now()),
            name: String::from("default role name"),
        }
    }
}

#[automock]
#[async_trait]
pub trait RoleRepositoryTrait {
    async fn create_role(&self, name: &str) -> anyhow::Result<RoleEntity>;
    async fn delete_role(&self, name: &str) -> anyhow::Result<Option<RoleEntity>>;
    async fn link_permissions(
        &self,
        role_name: &str,
        permissions: Vec<String>,
    ) -> anyhow::Result<RolePermissionsEntity>;
    async fn get_roles(&self) -> anyhow::Result<RoleEntity>;
    async fn get_role(&self, name: &str) -> anyhow::Result<RolePermissionsEntity>;
}

pub type DynRoleRepositoryTrait = Arc<dyn RoleRepositoryTrait + Send + Sync>;

#[derive(Clone)]
pub struct RoleRepository {
    pool: ServiceConnectionPool,
}

impl RoleRepository {
    pub fn new(pool: ServiceConnectionPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepositoryTrait for RoleRepository {
    async fn create_role(&self, name: &str) -> anyhow::Result<RoleEntity> {
        todo!()
    }
    async fn delete_role(&self, name: &str) -> anyhow::Result<Option<RoleEntity>> {
        todo!()
    }
    async fn link_permissions(
        &self,
        role_name: &str,
        permissions: Vec<String>,
    ) -> anyhow::Result<RoleEntity> {
        todo!()
    }
    async fn get_roles(&self) -> anyhow::Result<RoleEntity> {
        todo!()
    }
    async fn get_role(&self, name: &str) -> anyhow::Result<RoleEntity> {
        todo!()
    }
}
