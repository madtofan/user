use anyhow::Context;
use std::{sync::Arc, time::SystemTime};

use async_trait::async_trait;
use madtofan_microservice_common::repository::connection_pool::ServiceConnectionPool;
use mockall::automock;
use sqlx::{query, query_as, types::time::OffsetDateTime, FromRow};

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
    async fn get_permissions(
        &self,
        offset: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<PermissionEntity>>;
    async fn get_permissions_count(&self) -> anyhow::Result<i64>;
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
        query_as!(
            PermissionEntity,
            r#"
                insert into permissions (
                        created_at,
                        updated_at,
                        name
                    )
                values (
                        current_timestamp,
                        current_timestamp,
                        $1::varchar
                    )
                returning
                    id,
                    created_at,
                    updated_at,
                    name
            "#,
            name,
        )
        .fetch_one(&self.pool)
        .await
        .context("an unexpected error occured while creating the permission")
    }
    async fn delete_permission(&self, name: &str) -> anyhow::Result<Option<PermissionEntity>> {
        query_as!(
            PermissionEntity,
            r#"
                delete from permissions 
                where name = $1::varchar
                returning *
            "#,
            name,
        )
        .fetch_optional(&self.pool)
        .await
        .context("an unexpected error occured while deleting the permission")
    }
    async fn get_permissions(
        &self,
        offset: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<PermissionEntity>> {
        query_as!(
            PermissionEntity,
            r#"
                select
                    id,
                    name,
                    created_at,
                    updated_at
                from permissions
                order by created_at desc
                limit $1::int
                offset $2::int
            "#,
            limit as i32,
            offset as i32,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while obtaining the permissions")
    }
    async fn get_permissions_count(&self) -> anyhow::Result<i64> {
        let count_result = query!(
            r#"
                select
                    count(*)
                from permissions
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count_result.count.unwrap())
    }
}
