pub mod permissions;
pub mod roles;
pub mod users;

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use sqlx::PgPool;

    use crate::repository::{
        permissions::{DynPermissionRepositoryTrait, PermissionRepository},
        roles::{DynRoleRepositoryTrait, RoleRepository},
        users::{DynUserRepositoryTrait, UserRepository},
    };

    #[sqlx::test]
    async fn get_user_by_id_test(pool: PgPool) -> anyhow::Result<()> {
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

        let get_user_by_id = user_repository.get_user_by_id(created_user.id).await?;

        assert_eq!(get_user_by_id.email, "email@email.com");

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

    #[sqlx::test]
    async fn create_role_test(pool: PgPool) -> anyhow::Result<()> {
        let role_repository = Arc::new(RoleRepository::new(pool)) as DynRoleRepositoryTrait;

        let role_name = "role_name";
        role_repository.create_role(role_name).await?;

        let roles = role_repository.get_roles(0, 10).await?;

        assert_eq!(roles.len(), 1);
        assert_eq!(roles.first().unwrap().name, role_name);

        Ok(())
    }

    #[sqlx::test]
    async fn get_roles_count_test(pool: PgPool) -> anyhow::Result<()> {
        let role_repository = Arc::new(RoleRepository::new(pool)) as DynRoleRepositoryTrait;

        role_repository.create_role("role_name").await?;
        let roles_count = role_repository.get_roles_count().await?;
        assert_eq!(roles_count, 1);

        role_repository.create_role("role_name_2").await?;
        let roles_count = role_repository.get_roles_count().await?;
        assert_eq!(roles_count, 2);
        Ok(())
    }

    #[sqlx::test]
    async fn delete_role_test(pool: PgPool) -> anyhow::Result<()> {
        let role_repository = Arc::new(RoleRepository::new(pool)) as DynRoleRepositoryTrait;

        let deleted_role_name = "deleted_role_name";
        role_repository.create_role(deleted_role_name).await?;
        let not_deleted_role_name = "not_deleted_role_name";
        role_repository.create_role(not_deleted_role_name).await?;

        let roles = role_repository.get_roles(0, 10).await?;
        assert_eq!(roles.len(), 2);

        let deleted_role = role_repository.delete_role(deleted_role_name).await?;
        assert!(deleted_role.is_some());
        assert_eq!(deleted_role.unwrap().name, deleted_role_name);

        let roles = role_repository.get_roles(0, 10).await?;
        assert_eq!(roles.len(), 1);
        assert_eq!(roles.first().unwrap().name, not_deleted_role_name);

        Ok(())
    }

    #[sqlx::test]
    async fn create_permissions_test(pool: PgPool) -> anyhow::Result<()> {
        let permission_repository =
            Arc::new(PermissionRepository::new(pool)) as DynPermissionRepositoryTrait;

        let permission_name = "permission_name";
        permission_repository
            .create_permission(permission_name)
            .await?;

        let permissions = permission_repository.get_permissions(0, 10).await?;

        assert_eq!(permissions.len(), 1);
        assert_eq!(permissions.first().unwrap().name, permission_name);

        Ok(())
    }

    #[sqlx::test]
    async fn get_permissions_count_test(pool: PgPool) -> anyhow::Result<()> {
        let permission_repository =
            Arc::new(PermissionRepository::new(pool)) as DynPermissionRepositoryTrait;

        permission_repository
            .create_permission("permission_name")
            .await?;
        let permissions_count = permission_repository.get_permissions_count().await?;
        assert_eq!(permissions_count, 1);

        permission_repository
            .create_permission("permission_name_2")
            .await?;
        let permissions_count = permission_repository.get_permissions_count().await?;
        assert_eq!(permissions_count, 2);
        Ok(())
    }

    #[sqlx::test]
    async fn delete_permissions_test(pool: PgPool) -> anyhow::Result<()> {
        let permission_repository =
            Arc::new(PermissionRepository::new(pool)) as DynPermissionRepositoryTrait;

        let deleted_permission_name = "deleted_permission_name";
        permission_repository
            .create_permission(deleted_permission_name)
            .await?;
        let not_deleted_permission_name = "not_deleted_permission_name";
        permission_repository
            .create_permission(not_deleted_permission_name)
            .await?;

        let permissions = permission_repository.get_permissions(0, 10).await?;
        assert_eq!(permissions.len(), 2);

        let deleted_permission = permission_repository
            .delete_permission(deleted_permission_name)
            .await?;
        assert!(deleted_permission.is_some());
        assert_eq!(deleted_permission.unwrap().name, deleted_permission_name);

        let permissions = permission_repository.get_permissions(0, 10).await?;

        assert_eq!(permissions.len(), 1);
        assert_eq!(
            permissions.first().unwrap().name,
            not_deleted_permission_name
        );

        Ok(())
    }

    #[sqlx::test]
    async fn link_role_permission_test(pool: PgPool) -> anyhow::Result<()> {
        let role_repository = Arc::new(RoleRepository::new(pool.clone())) as DynRoleRepositoryTrait;
        let permission_repository =
            Arc::new(PermissionRepository::new(pool)) as DynPermissionRepositoryTrait;

        let role_name = "role_name";
        role_repository.create_role(role_name).await?;
        let permission_name = "permission_name";
        permission_repository
            .create_permission(permission_name)
            .await?;
        role_repository
            .link_permissions(role_name, vec![permission_name.to_string()])
            .await?;

        let role_option = role_repository.get_role(role_name).await?;
        assert!(role_option.is_some());
        let role = role_option.unwrap();
        assert_eq!(role.name, role_name);
        assert_eq!(role.permissions.len(), 1);
        assert_eq!(role.permissions.first().unwrap(), permission_name);

        Ok(())
    }

    #[sqlx::test]
    async fn unlink_role_permission_test(pool: PgPool) -> anyhow::Result<()> {
        let role_repository = Arc::new(RoleRepository::new(pool.clone())) as DynRoleRepositoryTrait;
        let permission_repository =
            Arc::new(PermissionRepository::new(pool)) as DynPermissionRepositoryTrait;

        let role_name = "role_name";
        role_repository.create_role(role_name).await?;
        let permission_one_name = "permission_one_name";
        permission_repository
            .create_permission(permission_one_name)
            .await?;
        let permission_two_name = "permission_two_name";
        permission_repository
            .create_permission(permission_two_name)
            .await?;
        role_repository
            .link_permissions(
                role_name,
                vec![
                    permission_one_name.to_string(),
                    permission_two_name.to_string(),
                ],
            )
            .await?;

        let role_option = role_repository.get_role(role_name).await?;
        assert!(role_option.is_some());
        let role = role_option.unwrap();
        assert_eq!(role.name, role_name);
        assert_eq!(role.permissions.len(), 2);

        role_repository
            .unlink_permissions(role_name, vec![permission_one_name.to_string()])
            .await?;

        let role = role_repository.get_role(role_name).await?.unwrap();
        assert_eq!(role.permissions.len(), 1);
        assert_eq!(role.permissions.first().unwrap(), permission_two_name);

        Ok(())
    }

    #[sqlx::test]
    async fn link_user_roles_test(pool: PgPool) -> anyhow::Result<()> {
        let user_repository = Arc::new(UserRepository::new(pool.clone())) as DynUserRepositoryTrait;

        let user_email = "email@email.com";
        let created_user = user_repository
            .create_user(user_email, "hashed_password", "First Name", "Last Name")
            .await
            .unwrap();
        user_repository.verify_registration(created_user.id).await?;

        let roles = user_repository.get_user_roles(created_user.id).await?;
        assert_eq!(roles.len(), 0);

        let role_repository = Arc::new(RoleRepository::new(pool.clone())) as DynRoleRepositoryTrait;
        let permission_repository =
            Arc::new(PermissionRepository::new(pool)) as DynPermissionRepositoryTrait;

        let role_name = "role_name";
        role_repository.create_role(role_name).await?;
        let permission_name = "permission_name";
        permission_repository
            .create_permission(permission_name)
            .await?;
        role_repository
            .link_permissions(role_name, vec![permission_name.to_string()])
            .await?;

        user_repository
            .link_roles(created_user.id, vec![role_name.to_string()])
            .await?;

        let roles = user_repository.get_user_roles(created_user.id).await?;
        assert_eq!(roles.len(), 1);
        assert_eq!(roles.first().unwrap().name, role_name);
        assert_eq!(roles.first().unwrap().permissions.len(), 1);
        assert_eq!(
            roles.first().unwrap().permissions.first().unwrap(),
            permission_name
        );

        Ok(())
    }

    #[sqlx::test]
    async fn unlink_user_roles_test(pool: PgPool) -> anyhow::Result<()> {
        let user_repository = Arc::new(UserRepository::new(pool.clone())) as DynUserRepositoryTrait;

        let user_email = "email@email.com";
        let created_user = user_repository
            .create_user(user_email, "hashed_password", "First Name", "Last Name")
            .await
            .unwrap();
        user_repository.verify_registration(created_user.id).await?;

        let role_repository = Arc::new(RoleRepository::new(pool.clone())) as DynRoleRepositoryTrait;
        let permission_repository =
            Arc::new(PermissionRepository::new(pool)) as DynPermissionRepositoryTrait;

        let role_one_name = "role_one_name";
        role_repository.create_role(role_one_name).await?;
        let permission_one_name = "permission_one_name";
        permission_repository
            .create_permission(permission_one_name)
            .await?;
        let role_two_name = "role_two_name";
        role_repository.create_role(role_two_name).await?;
        let permission_two_name = "permission_two_name";
        permission_repository
            .create_permission(permission_two_name)
            .await?;
        role_repository
            .link_permissions(role_one_name, vec![permission_one_name.to_string()])
            .await?;
        role_repository
            .link_permissions(role_two_name, vec![permission_two_name.to_string()])
            .await?;

        user_repository
            .link_roles(
                created_user.id,
                vec![role_one_name.to_string(), role_two_name.to_string()],
            )
            .await?;

        let roles = user_repository.get_user_roles(created_user.id).await?;

        assert_eq!(roles.len(), 2);

        user_repository
            .unlink_roles(created_user.id, vec![role_one_name.to_string()])
            .await?;

        let roles = user_repository.get_user_roles(created_user.id).await?;

        assert_eq!(roles.len(), 1);
        assert_eq!(roles.first().unwrap().name, role_two_name);
        assert_eq!(roles.first().unwrap().permissions.len(), 1);
        assert_eq!(
            roles.first().unwrap().permissions.first().unwrap(),
            permission_two_name
        );

        Ok(())
    }
}
