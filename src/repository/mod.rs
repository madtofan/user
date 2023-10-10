pub mod permissions;
pub mod roles;
pub mod users;

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use sqlx::PgPool;

    use crate::repository::users::{DynUserRepositoryTrait, UserRepository};

    #[sqlx::test]
    async fn get_user_by_id_test(pool: PgPool) -> anyhow::Result<()> {
        let user_repository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        // Positive test
        let created_user = user_repository
            .create_user(
                "email@email.com",
                "hashed_password",
                "First Name",
                "Last Name",
            )
            .await
            .unwrap();

        let get_user_by_id = user_repository.get_user_by_id(created_user.id).await?;

        assert_eq!(get_user_by_id.email, "email@email.com");

        // Negative test
        let get_user_by_false_id = user_repository.get_user_by_id(-1).await;

        assert!(get_user_by_false_id.is_err());

        Ok(())
    }

    #[sqlx::test]
    async fn get_user_by_email_test(pool: PgPool) -> anyhow::Result<()> {
        let user_repository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        // Positive test
        let created_user = user_repository
            .create_user(
                "email@email.com",
                "hashed_password",
                "First Name",
                "Last Name",
            )
            .await
            .unwrap();

        let get_user_by_email = user_repository
            .get_user_by_email(&created_user.email)
            .await?;

        assert!(get_user_by_email.is_none());

        user_repository
            .verify_registration(created_user.id)
            .await
            .unwrap();

        let get_user_by_email = user_repository
            .get_user_by_email(&created_user.email)
            .await?;

        assert!(get_user_by_email.is_some());

        let email_user = get_user_by_email.unwrap();

        assert_eq!(email_user.first_name, "First Name");

        // Negative test
        let get_user_by_false_email = user_repository
            .get_user_by_email("false_email@email.com")
            .await?;

        assert!(get_user_by_false_email.is_none());

        Ok(())
    }

    #[sqlx::test]
    async fn search_user_test(pool: PgPool) -> anyhow::Result<()> {
        let user_repository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        // Positive test
        let created_user = user_repository
            .create_user(
                "email@email.com",
                "hashed_password",
                "First Name",
                "Last Name",
            )
            .await
            .unwrap();

        user_repository.verify_registration(created_user.id).await?;

        let search_user_by_email = user_repository
            .get_user_by_email(&created_user.email)
            .await?;

        assert!(search_user_by_email.is_some());

        let email_user = search_user_by_email.unwrap();
        assert_eq!(email_user.first_name, "First Name");

        // Negative test
        let search_user_by_false_values = user_repository
            .get_user_by_email("false_email@email.com")
            .await?;

        assert!(search_user_by_false_values.is_none());

        Ok(())
    }

    #[sqlx::test]
    async fn update_user_test(pool: PgPool) -> anyhow::Result<()> {
        let user_repository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        let created_user = user_repository
            .create_user(
                "email@email.com",
                "hashed_password",
                "First Name",
                "Last Name",
            )
            .await
            .unwrap();

        assert_eq!(created_user.bio, "");

        let test_bio = "this is a test bio".to_string();

        let updated_user = user_repository
            .update_user(
                created_user.id,
                &created_user.password,
                &created_user.first_name,
                &created_user.last_name,
                &test_bio,
                &created_user.image,
            )
            .await?;

        assert_eq!(&updated_user.bio, &test_bio);

        Ok(())
    }

    #[sqlx::test]
    async fn update_refresh_token_test(pool: PgPool) -> anyhow::Result<()> {
        let user_repository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        let created_user = user_repository
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

        let updated_user = user_repository
            .update_refresh_token(created_user.id, &test_token)
            .await?;

        assert_eq!(&updated_user.token, &Some(test_token));

        Ok(())
    }

    #[sqlx::test]
    async fn verify_registration_test(pool: PgPool) -> anyhow::Result<()> {
        let user_repository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        let user_email = "email@email.com";
        let created_user = user_repository
            .create_user(user_email, "hashed_password", "First Name", "Last Name")
            .await
            .unwrap();

        let get_user = user_repository.get_user_by_email(user_email).await?;

        assert!(get_user.is_none());

        user_repository.verify_registration(created_user.id).await?;

        let get_user = user_repository.get_user_by_email(user_email).await?;

        assert!(get_user.is_some());

        Ok(())
    }
}
