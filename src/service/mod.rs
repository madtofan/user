pub mod users;

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use clap::Parser;
    use sqlx::PgPool;

    use crate::{
        config::AppConfig,
        repository::users::{DynUserRepositoryTrait, UserRepository},
        service::users::{DynUserServiceTrait, UserService},
        user::{update_request::UpdateFields, GetUserRequest, LoginRequest, RegisterRequest},
    };

    #[sqlx::test]
    async fn register_user_test(pool: PgPool) -> anyhow::Result<()> {
        let config = Arc::new(AppConfig::parse());
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_respository.clone(), config)) as DynUserServiceTrait;

        let email = "username@email.com".to_string();
        let register_request = RegisterRequest {
            username: "username".to_string(),
            email: email.clone(),
            password: "user_hashed_password".to_string(),
        };

        let register_user = user_service.register_user(register_request).await;

        assert!(register_user.is_ok());

        let find_user = user_respository
            .get_user_by_id(register_user.unwrap().id)
            .await;

        assert!(find_user.is_ok());
        assert_eq!(&find_user?.email, &email);

        Ok(())
    }

    #[sqlx::test]
    async fn login_user_test(pool: PgPool) -> anyhow::Result<()> {
        let config = Arc::new(AppConfig::parse());
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service = Arc::new(UserService::new(Arc::clone(&user_respository), config))
            as DynUserServiceTrait;

        let email = "username@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = RegisterRequest {
            username: "username".to_string(),
            email: email.clone(),
            password: password.clone(),
        };
        user_service.register_user(register_request).await?;

        let login_request = LoginRequest {
            email: email.clone(),
            password: password.clone(),
        };

        let login_user = user_service.login_user(login_request).await?;

        assert_eq!(&login_user.email, &email);

        Ok(())
    }

    #[sqlx::test]
    async fn get_user_test(pool: PgPool) -> anyhow::Result<()> {
        let config = Arc::new(AppConfig::parse());
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_respository.clone(), config)) as DynUserServiceTrait;

        let email = "username@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = RegisterRequest {
            username: "username".to_string(),
            email: email.clone(),
            password: password.clone(),
        };

        let registered_user = user_service.register_user(register_request).await?;

        let get_request = GetUserRequest {
            id: registered_user.id,
        };

        let get_user = user_service.get_user(get_request).await;

        assert!(get_user.is_ok());
        assert_eq!(&get_user?.email, &email);

        Ok(())
    }

    #[sqlx::test]
    async fn update_user_test(pool: PgPool) -> anyhow::Result<()> {
        let config = Arc::new(AppConfig::parse());
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_respository.clone(), config)) as DynUserServiceTrait;

        let email = "username@email.com".to_string();
        let password = "user_hashed_password".to_string();

        let register_request = RegisterRequest {
            username: "username".to_string(),
            email: email.clone(),
            password: password.clone(),
        };

        let registered_user = user_service.register_user(register_request).await?;

        let bio = "This is the user bio".to_string();

        let update_fields = UpdateFields {
            email: None,
            username: None,
            password: None,
            bio: Some(bio.clone()),
            image: None,
        };

        let update_user = user_service
            .update_user(registered_user.id, update_fields)
            .await;

        assert!(update_user.is_ok());
        assert_eq!(&update_user?.bio.unwrap(), &bio);

        Ok(())
    }
}
