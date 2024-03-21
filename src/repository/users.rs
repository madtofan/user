use anyhow::Context;
use async_trait::async_trait;
use madtofan_microservice_common::repository::connection_pool::ServiceConnectionPool;
use madtofan_microservice_common::user::UserList;
use mockall::automock;
use sqlx::types::time::OffsetDateTime;
use sqlx::{query, query_as, FromRow};
use std::sync::Arc;
use std::time::SystemTime;

#[derive(FromRow)]
pub struct UserEntity {
    pub id: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub bio: String,
    pub image: String,
    pub token: Option<String>,
    pub verified_at: Option<OffsetDateTime>,
}

impl Default for UserEntity {
    fn default() -> Self {
        UserEntity {
            id: 1,
            created_at: OffsetDateTime::from(SystemTime::now()),
            updated_at: OffsetDateTime::from(SystemTime::now()),
            email: String::from("default email"),
            password: String::from("default password"),
            first_name: String::from("default first name"),
            last_name: String::from("default last name"),
            bio: String::from("default bio"),
            image: String::from("default image"),
            token: None,
            verified_at: None,
        }
    }
}

impl From<UserEntity> for UserList {
    fn from(user: UserEntity) -> Self {
        UserList {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            bio: Some(user.bio),
            image: Some(user.image),
            verified: user.verified_at.is_some(),
        }
    }
}

#[derive(FromRow, Debug, Clone)]
pub struct RoleEntity {
    pub name: String,
    pub permissions: Vec<String>,
}

#[automock]
#[async_trait]
pub trait UserRepositoryTrait {
    async fn create_user(
        &self,
        email: &str,
        hashed_password: &str,
        first_name: &str,
        last_name: &str,
    ) -> anyhow::Result<UserEntity>;
    async fn get_user_by_email(&self, email: &str) -> anyhow::Result<Option<UserEntity>>;
    async fn get_user_by_id(&self, id: i64) -> anyhow::Result<UserEntity>;
    async fn update_user(
        &self,
        id: i64,
        password: &str,
        first_name: &str,
        last_name: &str,
        bio: &str,
        image: &str,
    ) -> anyhow::Result<UserEntity>;
    async fn update_refresh_token(&self, id: i64, token: &str) -> anyhow::Result<UserEntity>;
    async fn verify_registration(&self, id: i64) -> anyhow::Result<UserEntity>;
    async fn get_user_roles(&self, id: i64) -> anyhow::Result<Vec<RoleEntity>>;
    async fn link_roles(&self, id: i64, roles: Vec<String>) -> anyhow::Result<()>;
    async fn unlink_roles(&self, id: i64, roles: Vec<String>) -> anyhow::Result<()>;
    async fn get_user_list(&self, offset: i64, limit: i64) -> anyhow::Result<Vec<UserEntity>>;
    async fn get_users_count(&self) -> anyhow::Result<i64>;
}

pub type DynUserRepositoryTrait = Arc<dyn UserRepositoryTrait + Send + Sync>;

#[derive(Clone)]
pub struct UserRepository {
    pool: ServiceConnectionPool,
}

impl UserRepository {
    pub fn new(pool: ServiceConnectionPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepositoryTrait for UserRepository {
    async fn create_user(
        &self,
        email: &str,
        hashed_password: &str,
        first_name: &str,
        last_name: &str,
    ) -> anyhow::Result<UserEntity> {
        query_as!(
            UserEntity,
            r#"
                insert into users (
                        created_at,
                        updated_at,
                        email,
                        password,
                        first_name,
                        last_name,
                        bio,
                        image,
                        token
                    )
                values (
                        current_timestamp,
                        current_timestamp,
                        $1::varchar,
                        $2::varchar,
                        $3::varchar,
                        $4::varchar,
                        '',
                        '',
                        NULL
                    )
                returning
                    id,
                    created_at,
                    updated_at,
                    email,
                    password,
                    first_name,
                    last_name,
                    bio,
                    image,
                    token,
                    verified_at
            "#,
            email,
            hashed_password,
            first_name,
            last_name
        )
        .fetch_one(&self.pool)
        .await
        .context("an unexpected error occured while creating the user")
    }

    async fn get_user_by_email(&self, email: &str) -> anyhow::Result<Option<UserEntity>> {
        query_as!(
            UserEntity,
            r#"
                select
                    id,
                    created_at,
                    updated_at,
                    email,
                    password,
                    first_name,
                    last_name,
                    bio,
                    image,
                    token,
                    verified_at
                from users
                where email = $1::varchar
                and verified_at is not null
            "#,
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .context("an unexpected error occured while querying user by email")
    }

    async fn get_user_by_id(&self, id: i64) -> anyhow::Result<UserEntity> {
        query_as!(
            UserEntity,
            r#"
                select
                    id,
                    created_at,
                    updated_at,
                    email,
                    password,
                    first_name,
                    last_name,
                    bio,
                    image,
                    token,
                    verified_at
                from users
                where id = $1
            "#,
            id,
        )
        .fetch_one(&self.pool)
        .await
        .context("user was not found")
    }

    async fn update_user(
        &self,
        id: i64,
        password: &str,
        first_name: &str,
        last_name: &str,
        bio: &str,
        image: &str,
    ) -> anyhow::Result<UserEntity> {
        query_as!(
            UserEntity,
            r#"
                    update users
                    set
                        password = $1::varchar,
                        first_name = $2::varchar,
                        last_name = $3::varchar,
                        bio = $4::varchar,
                        image = $5::varchar,
                        updated_at = current_timestamp
                    where
                        id = $6
                    returning
                        id,
                        created_at,
                        updated_at,
                        email,
                        password,
                        first_name,
                        last_name,
                        bio,
                        image,
                        token,
                        verified_at
                "#,
            password,
            first_name,
            last_name,
            bio,
            image,
            id
        )
        .fetch_one(&self.pool)
        .await
        .context("could not update the user")
    }

    async fn update_refresh_token(&self, id: i64, token: &str) -> anyhow::Result<UserEntity> {
        query_as!(
            UserEntity,
            r#"
                    update users
                    set
                        token = $1::varchar,
                        updated_at = current_timestamp
                    where
                        id = $2::bigint
                    returning
                        id,
                        created_at,
                        updated_at,
                        email,
                        password,
                        first_name,
                        last_name,
                        bio,
                        image,
                        token,
                        verified_at
                "#,
            token,
            id
        )
        .fetch_one(&self.pool)
        .await
        .context("could not update the user token")
    }

    async fn verify_registration(&self, id: i64) -> anyhow::Result<UserEntity> {
        query_as!(
            UserEntity,
            r#"
                    update users
                    set
                        verified_at = current_timestamp
                    where
                        id = $1::bigint
                    and
                        verified_at is null
                    returning
                        id,
                        created_at,
                        updated_at,
                        email,
                        password,
                        first_name,
                        last_name,
                        bio,
                        image,
                        token,
                        verified_at
                "#,
            id
        )
        .fetch_one(&self.pool)
        .await
        .context("could not verify the user")
    }

    async fn get_user_roles(&self, id: i64) -> anyhow::Result<Vec<RoleEntity>> {
        query_as!(
            RoleEntity,
            r#"
                select
                    r.name as name,
                    array_agg((
                        p.name
                    )) as "permissions!: Vec<String>"
                    from user_roles as ur
                    left join roles as r
                        on ur.role_id = r.id
                        and ur.user_id = $1::bigint
                    left join roles_permissions as rp
                        on r.id = rp.role_id
                    left join permissions as p
                        on rp.permission_id = p.id
                    group by r.name
            "#,
            id
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while obtaining the roles")
    }

    async fn link_roles(&self, id: i64, roles: Vec<String>) -> anyhow::Result<()> {
        let user_ids = vec![id; roles.len()];

        let role_ids = query!(
            r#"
                select
                    id
                from roles
                where name = any($1::text[])
            "#,
            &roles,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while obtaining the roles to link")?
        .into_iter()
        .map(|r| r.id)
        .collect::<Vec<i64>>();

        query!(
            r#"
                insert into user_roles (
                        user_id,
                        role_id
                    )
                select * from unnest (
                        $1::bigint[],
                        $2::bigint[]
                    )
                returning *
            "#,
            &user_ids,
            &role_ids,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while linking the roles")?;

        Ok(())
    }

    async fn unlink_roles(&self, id: i64, roles: Vec<String>) -> anyhow::Result<()> {
        let user_ids = vec![id; roles.len()];

        let role_ids = query!(
            r#"
                select
                    id
                from roles
                where name = any($1::text[])
            "#,
            &roles,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while obtaining the roles to link")?
        .into_iter()
        .map(|r| r.id)
        .collect::<Vec<i64>>();

        query!(
            r#"
                delete from user_roles 
                where (user_id, role_id) in (select * from unnest (
                        $1::bigint[],
                        $2::bigint[]
                    ))
                returning *
            "#,
            &user_ids,
            &role_ids,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while unlinking the roles")?;

        Ok(())
    }

    async fn get_user_list(&self, offset: i64, limit: i64) -> anyhow::Result<Vec<UserEntity>> {
        query_as!(
            UserEntity,
            r#"
                select
                    id,
                    created_at,
                    updated_at,
                    email,
                    password,
                    first_name,
                    last_name,
                    bio,
                    image,
                    token,
                    verified_at
                from users
                order by created_at desc
                limit $1::int
                offset $2::int
            "#,
            limit as i32,
            offset as i32,
        )
        .fetch_all(&self.pool)
        .await
        .context("an unexpected error occured while obtaining the users")
    }

    async fn get_users_count(&self) -> anyhow::Result<i64> {
        let count_result = query!(
            r#"
                select
                    count(*)
                from users
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count_result.count.unwrap())
    }
}
