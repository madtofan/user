use crate::config::AppConfig;
use crate::repository::users::DynUserRepositoryTrait;
use argon2::Config;
use async_trait::async_trait;
use madtofan_microservice_common::{
    errors::{ServiceError, ServiceResult},
    user::{
        update_request::UpdateFields, GetUserRequest, LoginRequest, RefreshTokenRequest,
        RegisterRequest, UserResponse, VerifyRegistrationRequest,
    },
};
use mockall::automock;
use std::sync::Arc;
use tracing::{error, info};

#[automock]
#[async_trait]
pub trait UserServiceTrait {
    async fn register_user(&self, request: RegisterRequest) -> ServiceResult<UserResponse>;
    async fn login_user(&self, request: LoginRequest) -> ServiceResult<UserResponse>;
    async fn get_user(&self, user_id: GetUserRequest) -> ServiceResult<UserResponse>;
    async fn update_user(&self, user_id: i64, fields: UpdateFields) -> ServiceResult<UserResponse>;
    async fn refresh_token(&self, request: RefreshTokenRequest) -> ServiceResult<UserResponse>;
    async fn verify_registration(
        &self,
        request: VerifyRegistrationRequest,
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

    fn hash_password(&self, raw_password: &str) -> ServiceResult<String> {
        let password_bytes = raw_password.as_bytes();
        let hashed_password = argon2::hash_encoded(
            password_bytes,
            self.config.argon_salt.as_bytes(),
            &Config::default(),
        )
        .map_err(|err| ServiceError::InternalServerErrorWithContext(err.to_string()))?;

        Ok(hashed_password)
    }

    fn verify_password(
        &self,
        stored_password: &str,
        attempted_password: String,
    ) -> ServiceResult<bool> {
        let hashes_match =
            argon2::verify_encoded(stored_password, attempted_password.as_bytes())
                .map_err(|err| ServiceError::InternalServerErrorWithContext(err.to_string()))?;

        Ok(hashes_match)
    }
}

#[async_trait]
impl UserServiceTrait for UserService {
    async fn register_user(&self, request: RegisterRequest) -> ServiceResult<UserResponse> {
        let email = request.email;
        let password = request.password;
        let first_name = request.first_name;
        let last_name = request.last_name;

        let existing_user = self.repository.get_user_by_email(&email).await?;

        if existing_user.is_some() {
            error!("user {:?} already exists", &email);
            return Err(ServiceError::ObjectConflict(String::from("email is taken")));
        }

        info!("creating password hash for user {:?}", email);
        let hashed_password = self.hash_password(&password)?;

        info!("creating user {:?}", &email);
        let created_user = self
            .repository
            .create_user(&email, &hashed_password, &first_name, &last_name)
            .await?;

        info!("user successfully created");

        Ok(created_user.into_user_response())
    }

    async fn verify_registration(
        &self,
        request: VerifyRegistrationRequest,
    ) -> ServiceResult<UserResponse> {
        let verified_user = self.repository.verify_registration(request.id).await?;

        info!("verified user registration for user id: {:?}", &request.id);
        Ok(verified_user.into_user_response())
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
        let is_valid_login_attempt = self.verify_password(&user.password, attempted_password)?;

        if !is_valid_login_attempt {
            error!("invalid login attempt for user {:?}", &email);
            return Err(ServiceError::InvalidLoginAttempt);
        }

        Ok(user.into_user_response())
    }

    async fn get_user(&self, request: GetUserRequest) -> ServiceResult<UserResponse> {
        info!("retrieving user {:?}", request.id);
        let user = self.repository.get_user_by_id(request.id).await?;

        info!("user found with email {:?}", user.email);

        Ok(user.into_user_response())
    }

    async fn update_user(&self, user_id: i64, fields: UpdateFields) -> ServiceResult<UserResponse> {
        info!("retrieving user {:?}", &user_id);
        let user = self.repository.get_user_by_id(user_id).await?;

        let updated_first_name = fields.first_name.unwrap_or(user.first_name);
        let updated_last_name = fields.last_name.unwrap_or(user.last_name);
        let updated_bio = fields.bio.unwrap_or(user.bio);
        let updated_image = fields.image.unwrap_or(user.image);
        let updated_hashed_password = fields.password.unwrap_or(user.password);

        info!("updating user {:?}", &user_id);
        let updated_user = self
            .repository
            .update_user(
                user_id,
                &updated_hashed_password,
                &updated_first_name,
                &updated_last_name,
                &updated_bio,
                &updated_image,
            )
            .await?;

        info!("user {:?} updated", &user_id);

        Ok(updated_user.into_user_response())
    }

    async fn refresh_token(&self, request: RefreshTokenRequest) -> ServiceResult<UserResponse> {
        info!("updating user's token {:?}", request.id);
        let user = self
            .repository
            .update_refresh_token(request.id, &request.token)
            .await?;

        info!("updated user {:?} token", user.email);

        Ok(user.into_user_response())
    }
}
