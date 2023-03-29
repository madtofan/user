pub mod users;

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use sqlx::PgPool;

    use crate::repository::users::{DynUserRepositoryTrait, UserRepository};

    #[sqlx::test]
    async fn get_user_by_id_test(pool: PgPool) -> anyhow::Result<()> {
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        // Positive test
        let created_user = user_respository
            .create_user("email@email.com", "username", "hashed_password")
            .await
            .unwrap();

        let get_user_by_id = user_respository.get_user_by_id(created_user.id).await?;

        assert_eq!(get_user_by_id.username, "username");

        // Negative test
        let get_user_by_false_id = user_respository.get_user_by_id(-1).await;

        assert!(get_user_by_false_id.is_err());

        Ok(())
    }

    #[sqlx::test]
    async fn get_user_by_email_test(pool: PgPool) -> anyhow::Result<()> {
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        // Positive test
        let created_user = user_respository
            .create_user("email@email.com", "username", "hashed_password")
            .await
            .unwrap();

        let get_user_by_email = user_respository
            .get_user_by_email(&created_user.email)
            .await?;

        assert!(get_user_by_email.is_some());

        let email_user = get_user_by_email.unwrap();

        assert_eq!(email_user.username, "username");

        // Negative test
        let get_user_by_false_email = user_respository
            .get_user_by_email("false_email@email.com")
            .await?;

        assert!(get_user_by_false_email.is_none());

        Ok(())
    }

    #[sqlx::test]
    async fn get_user_by_username_test(pool: PgPool) -> anyhow::Result<()> {
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        // Positive test
        let created_user = user_respository
            .create_user("email@email.com", "username", "hashed_password")
            .await
            .unwrap();

        let get_user_by_username = user_respository
            .get_user_by_username(&created_user.username)
            .await?;

        assert!(get_user_by_username.is_some());

        let username_user = get_user_by_username.unwrap();

        assert_eq!(username_user.username, "username");

        // Negative test
        let get_user_by_false_username = user_respository
            .get_user_by_username("false_username")
            .await?;

        assert!(get_user_by_false_username.is_none());

        Ok(())
    }

    #[sqlx::test]
    async fn search_user_test(pool: PgPool) -> anyhow::Result<()> {
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        // Positive test
        let created_user = user_respository
            .create_user("email@email.com", "username", "hashed_password")
            .await
            .unwrap();

        let search_user_by_email = user_respository
            .search_user_by_email_or_username(&created_user.email, "")
            .await?;

        assert!(search_user_by_email.is_some());

        let email_user = search_user_by_email.unwrap();

        assert_eq!(email_user.username, "username");

        let search_user_by_id = user_respository
            .search_user_by_email_or_username("", &created_user.username)
            .await?;

        assert!(search_user_by_id.is_some());

        let id_user = search_user_by_id.unwrap();

        assert_eq!(id_user.username, "username");

        // Negative test
        let search_user_by_false_values = user_respository
            .search_user_by_email_or_username("false_email@email.com", "false_username")
            .await?;

        assert!(search_user_by_false_values.is_none());

        Ok(())
    }

    #[sqlx::test]
    async fn update_user_test(pool: PgPool) -> anyhow::Result<()> {
        let user_respository = Arc::new(UserRepository::new(pool)) as DynUserRepositoryTrait;

        let created_user = user_respository
            .create_user("email@email.com", "username", "hashed_password")
            .await
            .unwrap();

        assert_eq!(created_user.bio, "");

        let test_bio = "this is a test bio".to_string();

        let updated_user = user_respository
            .update_user(
                created_user.id,
                &created_user.email,
                &created_user.username,
                &created_user.password,
                &test_bio,
                &created_user.image,
            )
            .await?;

        assert_eq!(&updated_user.bio, &test_bio);

        Ok(())
    }
}
