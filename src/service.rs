use crate::config::AppConfig;
use crate::repository::DynUserRepositoryTrait;
use crate::user::{update_request::UpdateFields, LoginRequest, RegisterRequest, UserResponse};
use async_trait::async_trait;
use common::errors::{ServiceError, ServiceResult};
use common::token::Claims;
use jsonwebtoken::{encode, EncodingKey, Header};
use mockall::automock;
use sqlx::types::time::OffsetDateTime;
use std::ops::Add;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{error, info};

#[automock]
#[async_trait]
pub trait UserServiceTrait {
    async fn register_user(&self, request: RegisterRequest) -> ServiceResult<UserResponse>;
    async fn login_user(&self, request: LoginRequest) -> ServiceResult<UserResponse>;
    async fn get_current_user(&self, user_id: i64) -> ServiceResult<UserResponse>;
    async fn updated_user(
        &self,
        user_id: i64,
        request: UpdateFields,
    ) -> ServiceResult<UserResponse>;
}

pub type DynUserServiceTrait = Arc<dyn UserServiceTrait + Send + Sync>;

pub struct UserService {
    repository: DynUserRepositoryTrait,
    config: Arc<AppConfig>,
}

impl UserService {
    pub fn new(repository: DynUserRepositoryTrait, config: Arc<AppConfig>) -> Self {
        Self { repository, config }
    }

    fn create_token(&self, user_id: i64, email: &str) -> ServiceResult<String> {
        let from_now = Duration::from_secs(3600);
        let expired_future_time = SystemTime::now().add(from_now);
        let exp = OffsetDateTime::from(expired_future_time);

        let claims = Claims {
            sub: String::from(email),
            exp: exp.unix_timestamp() as usize,
            user_id,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.token_secret.as_bytes()),
        )
        .map_err(|err| ServiceError::InternalServerErrorWithContext(err.to_string()))?;

        Ok(token)
    }
}

#[async_trait]
impl UserServiceTrait for UserService {
    async fn register_user(&self, request: RegisterRequest) -> ServiceResult<UserResponse> {
        let email = request.email;
        let username = request.username;
        let hashed_password = request.password;

        let existing_user = self
            .repository
            .search_user_by_email_or_username(&email, &username)
            .await?;

        if existing_user.is_some() {
            error!("user {:?}/{:?} already exists", &email, &username);
            return Err(ServiceError::ObjectConflict(String::from(
                "username or email is taken",
            )));
        }

        info!("creating user {:?}", &email);
        let created_user = self
            .repository
            .create_user(&email, &username, &hashed_password)
            .await?;

        info!("user successfully created, generating token");
        let token = self.create_token(created_user.id, &created_user.email)?;

        Ok(created_user.into_user_response(token))
    }

    async fn login_user(&self, request: LoginRequest) -> ServiceResult<UserResponse> {
        let email = request.email;
        let attempted_password = request.password;

        info!("searching for existing user {:?}", &email);
        let existing_user = self.repository.get_user_by_email(&email).await?;

        if existing_user.is_none() {
            return Err(ServiceError::NotFound(String::from(
                "user email does not exist",
            )));
        }

        let user = existing_user.unwrap();

        info!("user found, verifying password hash for user {:?}", &email);
        let is_valid_login_attempt = &user.password.eq(&attempted_password);

        if !is_valid_login_attempt {
            error!("invalid login attempt for user {:?}", &email);
            return Err(ServiceError::InvalidLoginAttempt);
        }

        info!("user login successful, generating token");
        let token = self.create_token(user.id, &user.email)?;

        Ok(user.into_user_response(token))
    }

    async fn get_current_user(&self, user_id: i64) -> ServiceResult<UserResponse> {
        info!("retrieving user {:?}", user_id);
        let user = self.repository.get_user_by_id(user_id).await?;

        info!(
            "user found with email {:?}, generating new token",
            user.email
        );
        let token = self.create_token(user.id, user.email.as_str())?;

        Ok(user.into_user_response(token))
    }

    async fn updated_user(
        &self,
        user_id: i64,
        request: UpdateFields,
    ) -> ServiceResult<UserResponse> {
        info!("retrieving user {:?}", user_id);
        let user = self.repository.get_user_by_id(user_id).await?;

        let updated_email = request.email.unwrap_or(user.email);
        let updated_username = request.username.unwrap_or(user.username);
        let updated_bio = request.bio.unwrap_or(user.bio);
        let updated_image = request.image.unwrap_or(user.image);
        let updated_hashed_password = request.password.unwrap_or(user.password);

        info!("updating user {:?}", user_id);
        let updated_user = self
            .repository
            .update_user(
                user_id,
                Some(updated_email.clone()),
                Some(updated_username),
                Some(updated_hashed_password),
                Some(updated_bio),
                Some(updated_image),
            )
            .await?;

        info!("user {:?} updated, generating a new token", user_id);
        let token = self.create_token(user_id, updated_email.as_str())?;

        Ok(updated_user.into_user_response(token))
    }
}
