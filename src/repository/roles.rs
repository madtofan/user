use anyhow::Context;
use std::{sync::Arc, time::SystemTime};

use async_trait::async_trait;
use madtofan_microservice_common::repository::connection_pool::ServiceConnectionPool;
use mockall::automock;
use sqlx::{query, query_as, types::time::OffsetDateTime, FromRow};

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
    async fn unlink_permissions(
        &self,
        role_name: &str,
        permissions: Vec<String>,
    ) -> anyhow::Result<RolePermissionsEntity>;
    async fn get_roles(&self, offset: i64, limit: i64) -> anyhow::Result<Vec<RoleEntity>>;
    async fn get_role(&self, name: &str) -> anyhow::Result<Option<RolePermissionsEntity>>;
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
        query_as!(
            RoleEntity,
            r#"
                insert into roles (
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
        .context("an unexpected error occured while creating the role")
    }
    async fn delete_role(&self, name: &str) -> anyhow::Result<Option<RoleEntity>> {
        query_as!(
            RoleEntity,
            r#"
                delete from roles 
                where name = $1::varchar
                returning *
            "#,
            name,
        )
        .fetch_optional(&self.pool)
        .await
        .context("an unexpected error occured while deleting the role")
    }
    async fn link_permissions(
        &self,
        role_name: &str,
        permissions: Vec<String>,
    ) -> anyhow::Result<RolePermissionsEntity> {
        let role_entity = query!(
            r#"
                select
                    id
                from roles
                where name = $1::varchar
            "#,
            role_name,
        )
        .fetch_one(&self.pool)
        .await
        .context("an unexpected error occured while obtaining the role to link")?;
        let role_ids = vec![role_entity.id; permissions.len()];

        let permission_ids = query!(
            r#"
                select
                    id
                from permissions
                where name = any($1::text[])
            "#,
            &permissions,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while obtaining the permissions to link")?
        .into_iter()
        .map(|r| r.id)
        .collect::<Vec<i64>>();

        query!(
            r#"
                insert into roles_permissions (
                        role_id,
                        permission_id
                    )
                select * from unnest (
                        $1::bigint[],
                        $2::bigint[]
                    )
                returning *
            "#,
            &role_ids,
            &permission_ids,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while linking the permissions")?;

        Ok(self.get_role(role_name).await?.unwrap())
    }
    async fn unlink_permissions(
        &self,
        role_name: &str,
        permissions: Vec<String>,
    ) -> anyhow::Result<RolePermissionsEntity> {
        let role_entity = query!(
            r#"
                select
                    id
                from roles
                where name = $1::varchar
            "#,
            role_name,
        )
        .fetch_one(&self.pool)
        .await
        .context("an unexpected error occured while obtaining the role to unlink")?;
        let role_ids = vec![role_entity.id; permissions.len()];

        let permission_ids = query!(
            r#"
                select
                    id
                from permissions
                where name = any($1::text[])
            "#,
            &permissions,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while obtaining the permissions to unlink")?
        .into_iter()
        .map(|r| r.id)
        .collect::<Vec<i64>>();

        query!(
            r#"
                delete from roles_permissions 
                where (role_id, permission_id) in (select * from unnest (
                        $1::bigint[],
                        $2::bigint[]
                    ))
                returning *
            "#,
            &role_ids,
            &permission_ids,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while unlinking the permissions")?;

        Ok(self.get_role(role_name).await?.unwrap())
    }
    async fn get_roles(&self, offset: i64, limit: i64) -> anyhow::Result<Vec<RoleEntity>> {
        query_as!(
            RoleEntity,
            r#"
                select
                    id,
                    name,
                    created_at,
                    updated_at
                from roles
                order by created_at desc
                limit $1::int
                offset $2::int
            "#,
            limit as i32,
            offset as i32,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while obtaining the roles")
    }
    async fn get_role(&self, name: &str) -> anyhow::Result<Option<RolePermissionsEntity>> {
        query_as!(
            RolePermissionsEntity,
            r#"
                select
                    r.id as id,
                    r.name as name,
                    r.created_at as created_at,
                    r.updated_at as updated_at,
                    array_agg((
                        select name from permissions where id = rp.permission_id
                    )) as "permissions!: Vec<String>"
                from roles as r
                inner join roles_permissions as rp
                    on r.id = rp.role_id
                where r.name = $1::varchar
                group by r.id
            "#,
            name,
        )
        .fetch_optional(&self.pool)
        .await
        .context("an unexpected error occured while querying user by email")
    }
}
