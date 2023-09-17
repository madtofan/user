pub mod user;

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use clap::Parser;
    use madtofan_microservice_common::user::{
        update_request::UpdateFields, user_server::User, GetUserRequest, LoginRequest,
        RefreshTokenRequest, RegisterRequest, UpdateRequest, VerifyTokenRequest,
    };
    use sqlx::PgPool;
    use tonic::Request;

    use crate::{
        config::AppConfig,
        handler::user::RequestHandler,
        repository::users::{DynUserRepositoryTrait, UserRepository},
        service::users::{DynUserServiceTrait, UserService},
    };

    struct AllTraits {
        handler: RequestHandler,
        user_service: DynUserServiceTrait,
        user_repository: DynUserRepositoryTrait,
    }

    fn initialize_handler(pool: PgPool) -> AllTraits {
        let config = Arc::new(AppConfig::parse());
        let user_repository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_repository.clone(), config)) as DynUserServiceTrait;
        let handler = RequestHandler::new(user_service.clone());

        AllTraits {
            handler,
            user_service,
            user_repository,
        }
    }

    #[sqlx::test]
    async fn register_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let email = "email@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = Request::new(RegisterRequest {
            email: email.clone(),
            password: password.clone(),
            first_name: "first_name".to_string(),
            last_name: "last_name".to_string(),
        });

        let register_user = all_traits.handler.register(register_request).await;

        assert!(register_user.is_ok());

        let find_user = all_traits
            .user_repository
            .get_user_by_id(register_user.unwrap().into_inner().id)
            .await;

        assert!(find_user.is_ok());
        assert_eq!(&find_user?.email, &email);

        Ok(())
    }

    #[sqlx::test]
    async fn login_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let email = "email@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = RegisterRequest {
            email: email.clone(),
            password: password.clone(),
            first_name: "first_name".to_string(),
            last_name: "last_name".to_string(),
        };

        let registered_user = all_traits
            .user_service
            .register_user(register_request)
            .await?;
        all_traits
            .user_repository
            .verify_registration(registered_user.id)
            .await?;

        let login_request = Request::new(LoginRequest {
            email: email.clone(),
            password: password.clone(),
        });

        let login_user = all_traits.handler.login(login_request).await?;

        assert_eq!(&login_user.into_inner().email, &registered_user.email);

        Ok(())
    }

    #[sqlx::test]
    async fn get_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let email = "email@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = RegisterRequest {
            email: email.clone(),
            password: password.clone(),
            first_name: "first_name".to_string(),
            last_name: "last_name".to_string(),
        };

        let registered_user = all_traits
            .user_service
            .register_user(register_request)
            .await?;

        let get_request = Request::new(GetUserRequest {
            id: registered_user.id,
        });

        let get_user = all_traits.handler.get(get_request).await?;

        assert_eq!(&get_user.into_inner().email, &email);

        Ok(())
    }

    #[sqlx::test]
    async fn update_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let email = "email@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = RegisterRequest {
            email: email.clone(),
            password: password.clone(),
            first_name: "first_name".to_string(),
            last_name: "last_name".to_string(),
        };

        let registered_user = all_traits
            .user_service
            .register_user(register_request)
            .await?;

        let update_bio_value = "test".to_string();

        let update_request = Request::new(UpdateRequest {
            id: registered_user.id,
            fields: Some(UpdateFields {
                password: None,
                first_name: None,
                last_name: None,
                bio: Some(update_bio_value.clone()),
                image: None,
            }),
        });

        let updated_user = all_traits.handler.update(update_request).await?;

        let updated_bio = &updated_user.into_inner().bio.unwrap();
        assert_eq!(updated_bio, &update_bio_value);

        Ok(())
    }

    #[sqlx::test]
    async fn refresh_token_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let created_user = all_traits
            .user_repository
            .create_user(
                "email@email.com",
                "hashed_password",
                "First Name",
                "Last Name",
            )
            .await
            .unwrap();

        assert_eq!(created_user.token, None);

        let test_token = "this is a test token".to_string();

        let refresh_token_request = Request::new(RefreshTokenRequest {
            id: created_user.id,
            token: test_token.clone(),
        });

        let refreshed_token_user = all_traits
            .handler
            .refresh_token(refresh_token_request)
            .await?;

        let updated_token = &refreshed_token_user.into_inner().token;
        assert_eq!(updated_token, &Some(test_token));

        Ok(())
    }

    #[sqlx::test]
    async fn verify_registration_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let created_user = all_traits
            .user_repository
            .create_user(
                "email@email.com",
                "hashed_password",
                "First Name",
                "Last Name",
            )
            .await
            .unwrap();

        assert_eq!(created_user.token, None);

        let test_token = "this is a test token".to_string();

        let refresh_token_request = Request::new(RefreshTokenRequest {
            id: created_user.id,
            token: test_token.clone(),
        });

        let refreshed_token_user = all_traits
            .handler
            .refresh_token(refresh_token_request)
            .await?;

        let updated_token = &refreshed_token_user.into_inner().token;
        assert_eq!(updated_token, &Some(test_token));

        Ok(())
    }

    #[sqlx::test]
    async fn verify_token_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let created_user = all_traits
            .user_repository
            .create_user(
                "email@email.com",
                "hashed_password",
                "First Name",
                "Last Name",
            )
            .await
            .unwrap();

        assert_eq!(created_user.token, None);

        let test_token = "this is a test token".to_string();

        all_traits
            .user_repository
            .update_refresh_token(created_user.id, &test_token.clone())
            .await?;

        let verify_token_request = Request::new(VerifyTokenRequest {
            id: created_user.id,
            token: test_token.clone(),
        });

        let is_verified = all_traits
            .handler
            .verify_token(verify_token_request)
            .await?;

        assert!(is_verified.into_inner().valid);

        Ok(())
    }
}
