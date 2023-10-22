pub mod permissions;
pub mod roles;
pub mod users;

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use clap::Parser;
    use madtofan_microservice_common::user::{
        update_request::UpdateFields, GetUserRequest, LoginRequest, RefreshTokenRequest,
        RegisterRequest, Role, RolesPermissionsRequest, VerifyRegistrationRequest,
        VerifyTokenRequest,
    };
    use sqlx::PgPool;

    use crate::{
        config::AppConfig,
        repository::{
            permissions::{DynPermissionRepositoryTrait, PermissionRepository},
            roles::{DynRoleRepositoryTrait, RoleRepository},
            users::{DynUserRepositoryTrait, UserRepository},
        },
    };

    use super::{
        permissions::{DynPermissionServiceTrait, PermissionService},
        roles::{DynRoleServiceTrait, RoleService},
        users::{DynUserServiceTrait, UserService},
    };

    struct AllTraits {
        user_service: DynUserServiceTrait,
        user_repository: DynUserRepositoryTrait,
        role_service: DynRoleServiceTrait,
        role_repository: DynRoleRepositoryTrait,
        permission_service: DynPermissionServiceTrait,
        permission_repository: DynPermissionRepositoryTrait,
    }

    fn initialize_handler(pool: PgPool) -> AllTraits {
        let config = Arc::new(AppConfig::parse());
        let user_repository = Arc::new(UserRepository::new(pool.clone())) as DynUserRepositoryTrait;
        let user_service =
            Arc::new(UserService::new(user_repository.clone(), config)) as DynUserServiceTrait;
        let role_repository = Arc::new(RoleRepository::new(pool.clone())) as DynRoleRepositoryTrait;
        let role_service =
            Arc::new(RoleService::new(role_repository.clone())) as DynRoleServiceTrait;
        let permission_repository =
            Arc::new(PermissionRepository::new(pool.clone())) as DynPermissionRepositoryTrait;
        let permission_service = Arc::new(PermissionService::new(permission_repository.clone()))
            as DynPermissionServiceTrait;

        AllTraits {
            user_service,
            user_repository,
            role_repository,
            role_service,
            permission_repository,
            permission_service,
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

    #[sqlx::test]
    async fn add_role_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let role_name = "role_name".to_string();
        let request = RolesPermissionsRequest {
            name: role_name.clone(),
        };
        all_traits.role_service.add_role(request).await?;

        let role = all_traits.role_repository.get_roles(0, 10).await?;

        assert_eq!(role.len(), 1);
        assert_eq!(role.first().unwrap().name, role_name);

        Ok(())
    }

    #[sqlx::test]
    async fn delete_role_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let role_to_delete = "role_to_delete_name".to_string();
        all_traits
            .role_repository
            .create_role(&role_to_delete)
            .await?;
        let role_to_not_delete = "role_to_not_delete_name".to_string();
        all_traits
            .role_repository
            .create_role(&role_to_not_delete)
            .await?;

        let role = all_traits.role_repository.get_roles(0, 10).await?;

        assert_eq!(role.len(), 2);

        let request = RolesPermissionsRequest {
            name: role_to_delete.clone(),
        };
        all_traits.role_service.delete_role(request).await?;

        let role = all_traits.role_repository.get_roles(0, 10).await?;

        assert_eq!(role.len(), 1);
        assert_eq!(role.first().unwrap().name, role_to_not_delete);

        Ok(())
    }

    #[sqlx::test]
    async fn add_permission_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let permission_name = "permission_name".to_string();
        let request = RolesPermissionsRequest {
            name: permission_name.clone(),
        };
        all_traits
            .permission_service
            .add_permission(request)
            .await?;

        let permission = all_traits
            .permission_repository
            .get_permissions(0, 10)
            .await?;

        assert_eq!(permission.len(), 1);
        assert_eq!(permission.first().unwrap().name, permission_name);

        Ok(())
    }

    #[sqlx::test]
    async fn delete_permission_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let permission_to_delete = "permission_to_delete_name".to_string();
        all_traits
            .permission_repository
            .create_permission(&permission_to_delete)
            .await?;
        let permission_to_not_delete = "permission_to_not_delete_name".to_string();
        all_traits
            .permission_repository
            .create_permission(&permission_to_not_delete)
            .await?;

        let permission = all_traits
            .permission_repository
            .get_permissions(0, 10)
            .await?;

        assert_eq!(permission.len(), 2);

        let request = RolesPermissionsRequest {
            name: permission_to_delete.clone(),
        };
        all_traits
            .permission_service
            .delete_permission(request)
            .await?;

        let permission = all_traits
            .permission_repository
            .get_permissions(0, 10)
            .await?;

        assert_eq!(permission.len(), 1);
        assert_eq!(permission.first().unwrap().name, permission_to_not_delete);

        Ok(())
    }

    #[sqlx::test]
    async fn authorize_role_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let role_name = "role_name".to_string();
        all_traits.role_repository.create_role(&role_name).await?;
        let permission_name = "permission_name".to_string();
        all_traits
            .permission_repository
            .create_permission(&permission_name)
            .await?;

        let request = Role {
            name: role_name.clone(),
            permissions: vec![permission_name.clone()],
        };
        all_traits.role_service.authorize_role(request).await?;
        let role = all_traits
            .role_repository
            .get_role(&role_name)
            .await?
            .unwrap();

        assert_eq!(role.permissions.len(), 1);
        assert_eq!(role.permissions.first().unwrap(), &permission_name);

        Ok(())
    }

    #[sqlx::test]
    async fn revoke_role_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let role_name = "role_name".to_string();
        all_traits.role_repository.create_role(&role_name).await?;
        let permission_one_name = "permission_one_name".to_string();
        all_traits
            .permission_repository
            .create_permission(&permission_one_name)
            .await?;
        let permission_two_name = "permission_two_name".to_string();
        all_traits
            .permission_repository
            .create_permission(&permission_two_name)
            .await?;
        all_traits
            .role_repository
            .link_permissions(
                &role_name,
                vec![permission_one_name.clone(), permission_two_name.clone()],
            )
            .await?;

        let request = Role {
            name: role_name.clone(),
            permissions: vec![permission_one_name.clone()],
        };
        all_traits.role_service.revoke_role(request).await?;
        let role = all_traits
            .role_repository
            .get_role(&role_name)
            .await?
            .unwrap();

        assert_eq!(role.permissions.len(), 1);
        assert_eq!(role.permissions.first().unwrap(), &permission_two_name);

        Ok(())
    }
}
