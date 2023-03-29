pub mod user;

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use clap::Parser;
    use sqlx::PgPool;
    use tonic::Request;

    use crate::{
        config::AppConfig,
        handler::user::RequestHandler,
        repository::users::{DynUserRepositoryTrait, UserRepository},
        service::users::{DynUserServiceTrait, UserService},
        user::{
            update_request::UpdateFields, user_server::User, GetUserRequest, LoginRequest,
            RegisterRequest, UpdateRequest,
        },
    };

    #[sqlx::test]
    async fn register_test(pool: PgPool) -> anyhow::Result<()> {
        let config = Arc::new(AppConfig::parse());
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_respository.clone(), config)) as DynUserServiceTrait;
        let request_handler = RequestHandler::new(user_service);

        let email = "username@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = Request::new(RegisterRequest {
            username: "username".to_string(),
            email: email.clone(),
            password: password.clone(),
        });

        let register_user = request_handler.register(register_request).await;

        assert!(register_user.is_ok());

        let find_user = user_respository
            .get_user_by_id(register_user.unwrap().into_inner().id)
            .await;

        assert!(find_user.is_ok());
        assert_eq!(&find_user?.email, &email);

        Ok(())
    }

    #[sqlx::test]
    async fn login_test(pool: PgPool) -> anyhow::Result<()> {
        let config = Arc::new(AppConfig::parse());
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_respository.clone(), config)) as DynUserServiceTrait;
        let request_handler = RequestHandler::new(user_service.clone());

        let email = "username@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = RegisterRequest {
            username: "username".to_string(),
            email: email.clone(),
            password: password.clone(),
        };

        let registered_user = user_service.register_user(register_request).await?;

        let login_request = Request::new(LoginRequest {
            email: email.clone(),
            password: password.clone(),
        });

        let login_user = request_handler.login(login_request).await?;

        assert_eq!(&login_user.into_inner().email, &registered_user.email);

        Ok(())
    }

    #[sqlx::test]
    async fn get_test(pool: PgPool) -> anyhow::Result<()> {
        let config = Arc::new(AppConfig::parse());
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_respository.clone(), config)) as DynUserServiceTrait;
        let request_handler = RequestHandler::new(user_service.clone());

        let email = "username@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = RegisterRequest {
            username: "username".to_string(),
            email: email.clone(),
            password: password.clone(),
        };

        let registered_user = user_service.register_user(register_request).await?;

        let get_request = Request::new(GetUserRequest {
            id: registered_user.id,
        });

        let get_user = request_handler.get(get_request).await?;

        assert_eq!(&get_user.into_inner().email, &email);

        Ok(())
    }

    #[sqlx::test]
    async fn update_test(pool: PgPool) -> anyhow::Result<()> {
        let config = Arc::new(AppConfig::parse());
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_respository.clone(), config)) as DynUserServiceTrait;
        let request_handler = RequestHandler::new(user_service.clone());

        let email = "username@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = RegisterRequest {
            username: "username".to_string(),
            email: email.clone(),
            password: password.clone(),
        };

        let registered_user = user_service.register_user(register_request).await?;

        let update_bio_value = "test".to_string();

        let update_request = Request::new(UpdateRequest {
            id: registered_user.id,
            fields: Some(UpdateFields {
                email: None,
                username: None,
                password: None,
                bio: Some(update_bio_value.clone()),
                image: None,
            }),
        });

        let updated_user = request_handler.update(update_request).await?;

        let updated_bio = &updated_user.into_inner().bio.unwrap();
        assert_eq!(updated_bio, &update_bio_value);

        Ok(())
    }
}
