pub mod permissions;
pub mod roles;
pub mod users;

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use clap::Parser;
    use madtofan_microservice_common::user::{
        update_request::UpdateFields, GetUserRequest, LoginRequest, RefreshTokenRequest,
        RegisterRequest, VerifyRegistrationRequest, VerifyTokenRequest,
    };
    use sqlx::PgPool;

    use crate::{
        config::AppConfig,
        repository::users::{DynUserRepositoryTrait, UserRepository},
        service::users::{DynUserServiceTrait, UserService},
    };
    struct AllTraits {
        user_service: DynUserServiceTrait,
        user_repository: DynUserRepositoryTrait,
    }

    fn initialize_handler(pool: PgPool) -> AllTraits {
        let config = Arc::new(AppConfig::parse());
        let user_repository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_repository.clone(), config)) as DynUserServiceTrait;

        AllTraits {
            user_service,
            user_repository,
        }
    }

    #[sqlx::test]
    async fn register_user_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let email = "email@email.com".to_string();
        let register_request = RegisterRequest {
            email: email.clone(),
            password: "user_hashed_password".to_string(),
            first_name: "first_name".to_string(),
            last_name: "last_name".to_string(),
        };

        let register_user = all_traits
            .user_service
            .register_user(register_request)
            .await;

        assert!(register_user.is_ok());

        let find_user = all_traits
            .user_repository
            .get_user_by_id(register_user.unwrap().id)
            .await;

        assert!(find_user.is_ok());
        assert_eq!(&find_user?.email, &email);

        Ok(())
    }

    #[sqlx::test]
    async fn login_user_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let email = "email@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = RegisterRequest {
            email: email.clone(),
            password: password.clone(),
            first_name: "first_name".to_string(),
            last_name: "last_name".to_string(),
        };
        let created_user = all_traits
            .user_service
            .register_user(register_request)
            .await?;

        let login_request = LoginRequest {
            email: email.clone(),
            password: password.clone(),
        };

        let login_user = all_traits
            .user_service
            .login_user(login_request.clone())
            .await;

        assert!(login_user.is_err());

        all_traits
            .user_repository
            .verify_registration(created_user.id)
            .await?;

        let login_user = all_traits.user_service.login_user(login_request).await?;

        assert_eq!(&login_user.email, &email);

        Ok(())
    }

    #[sqlx::test]
    async fn get_user_test(pool: PgPool) -> anyhow::Result<()> {
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

        let get_request = GetUserRequest {
            id: registered_user.id,
        };

        let get_user = all_traits.user_service.get_user(get_request).await;

        assert!(get_user.is_ok());
        assert_eq!(&get_user?.email, &email);

        Ok(())
    }

    #[sqlx::test]
    async fn update_user_test(pool: PgPool) -> anyhow::Result<()> {
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

        let bio = "This is the user bio".to_string();

        let update_fields = UpdateFields {
            password: None,
            first_name: None,
            last_name: None,
            bio: Some(bio.clone()),
            image: None,
        };

        let update_user = all_traits
            .user_service
            .update_user(registered_user.id, update_fields)
            .await;

        assert!(update_user.is_ok());
        assert_eq!(&update_user?.bio.unwrap(), &bio);

        Ok(())
    }

    #[sqlx::test]
    async fn verify_registration_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let user_email = "email@email.com";
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

        let get_user = all_traits
            .user_repository
            .get_user_by_email(user_email)
            .await?;

        assert!(get_user.is_none());

        let verify_registration_request = VerifyRegistrationRequest {
            id: created_user.id,
        };

        all_traits
            .user_service
            .verify_registration(verify_registration_request)
            .await?;

        let get_user = all_traits
            .user_repository
            .get_user_by_email(user_email)
            .await?;

        assert!(get_user.is_some());

        Ok(())
    }

    #[sqlx::test]
    async fn refresh_token_test(pool: PgPool) -> anyhow::Result<()> {
        let config = Arc::new(AppConfig::parse());
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_respository.clone(), config)) as DynUserServiceTrait;

        let created_user = user_respository
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

        let update_token_request = RefreshTokenRequest {
            id: created_user.id,
            token: test_token.clone(),
        };

        let update_token = user_service.refresh_token(update_token_request).await;

        assert!(update_token.is_ok());
        assert_eq!(&update_token?.token, &Some(test_token));

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

        let verify_token_request = VerifyTokenRequest {
            id: created_user.id,
            token: test_token.clone(),
        };

        let verify_token = all_traits
            .user_service
            .verify_token(verify_token_request)
            .await?;

        assert!(verify_token.valid);

        Ok(())
    }
}
