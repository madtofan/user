use anyhow::Context;
use async_trait::async_trait;
use madtofan_microservice_common::{
    repository::connection_pool::ServiceConnectionPool, user::UserResponse,
};
use mockall::automock;
use sqlx::types::time::OffsetDateTime;
use sqlx::{query_as, FromRow};
use std::sync::Arc;
use std::time::SystemTime;

#[derive(FromRow)]
pub struct UserEntity {
    pub id: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub username: String,
    pub email: String,
    pub password: String,
    pub bio: String,
    pub image: String,
    pub token: Option<String>,
    pub verified_at: Option<OffsetDateTime>,
}

impl UserEntity {
    pub fn into_user_response(self) -> UserResponse {
        UserResponse {
            id: self.id,
            username: self.username,
            email: self.email,
            bio: Some(self.bio),
            image: Some(self.image),
            token: self.token,
        }
    }
}

impl Default for UserEntity {
    fn default() -> Self {
        UserEntity {
            id: 1,
            created_at: OffsetDateTime::from(SystemTime::now()),
            updated_at: OffsetDateTime::from(SystemTime::now()),
            username: String::from("default username"),
            email: String::from("default email"),
            password: String::from("default password"),
            bio: String::from("default bio"),
            image: String::from("default image"),
            token: None,
            verified_at: None,
        }
    }
}

#[automock]
#[async_trait]
pub trait UserRepositoryTrait {
    async fn search_user_by_email_or_username(
        &self,
        email: &str,
        username: &str,
    ) -> anyhow::Result<Option<UserEntity>>;
    async fn create_user(
        &self,
        email: &str,
        username: &str,
        hashed_password: &str,
    ) -> anyhow::Result<UserEntity>;
    async fn get_user_by_email(&self, email: &str) -> anyhow::Result<Option<UserEntity>>;
    async fn get_user_by_username(&self, username: &str) -> anyhow::Result<Option<UserEntity>>;
    async fn get_user_by_id(&self, id: i64) -> anyhow::Result<UserEntity>;
    async fn update_user(
        &self,
        id: i64,
        email: &str,
        username: &str,
        password: &str,
        bio: &str,
        image: &str,
    ) -> anyhow::Result<UserEntity>;
    async fn update_refresh_token(&self, id: i64, token: &str) -> anyhow::Result<UserEntity>;
    async fn verify_registration(&self, id: i64) -> anyhow::Result<UserEntity>;
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
    async fn search_user_by_email_or_username(
        &self,
        email: &str,
        username: &str,
    ) -> anyhow::Result<Option<UserEntity>> {
        query_as!(
            UserEntity,
            r#"
                select
                    id,
                    created_at,
                    updated_at,
                    username,
                    email,
                    password,
                    bio,
                    image,
                    token,
                    verified_at
                from users
                where email = $1::varchar
                or username = $2::varchar
                and verified_at is not null
            "#,
            email,
            username
        )
        .fetch_optional(&self.pool)
        .await
        .context("an unexpected error occured while search for users")
    }

    async fn create_user(
        &self,
        email: &str,
        username: &str,
        hashed_password: &str,
    ) -> anyhow::Result<UserEntity> {
        query_as!(
            UserEntity,
            r#"
                insert into users (
                        created_at,
                        updated_at,
                        username,
                        email,
                        password,
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
                        '',
                        '',
                        NULL
                    )
                returning
                    id,
                    created_at,
                    updated_at,
                    username,
                    email,
                    password,
                    bio,
                    image,
                    token,
                    verified_at
            "#,
            username,
            email,
            hashed_password
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
                    username,
                    email,
                    password,
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

    async fn get_user_by_username(&self, username: &str) -> anyhow::Result<Option<UserEntity>> {
        query_as!(
            UserEntity,
            r#"
                select
                    id,
                    created_at,
                    updated_at,
                    username,
                    email,
                    password,
                    bio,
                    image,
                    token,
                    verified_at
                from users
                where username = $1::varchar
                and verified_at is not null
            "#,
            username,
        )
        .fetch_optional(&self.pool)
        .await
        .context("an unexpected error occured while querying user by username")
    }

    async fn get_user_by_id(&self, id: i64) -> anyhow::Result<UserEntity> {
        query_as!(
            UserEntity,
            r#"
                select
                    id,
                    created_at,
                    updated_at,
                    username,
                    email,
                    password,
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
        email: &str,
        username: &str,
        password: &str,
        bio: &str,
        image: &str,
    ) -> anyhow::Result<UserEntity> {
        query_as!(
            UserEntity,
            r#"
                    update users
                    set
                        username = $1::varchar,
                        email = $2::varchar,
                        password = $3::varchar,
                        bio = $4::varchar,
                        image = $5::varchar,
                        updated_at = current_timestamp
                    where
                        id = $6
                    returning
                        id,
                        created_at,
                        updated_at,
                        username,
                        email,
                        password,
                        bio,
                        image,
                        token,
                        verified_at
                "#,
            username,
            email,
            password,
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
                        username,
                        email,
                        password,
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
                        username,
                        email,
                        password,
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
}
