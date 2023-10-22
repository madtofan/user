pub mod user;

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use clap::Parser;
    use madtofan_microservice_common::user::{
        update_request::UpdateFields, user_server::User, GetUserRequest, LoginRequest,
        RefreshTokenRequest, RegisterRequest, Role, RolesPermissionsRequest, UpdateRequest,
        VerifyTokenRequest,
    };
    use sqlx::PgPool;
    use tonic::Request;

    use crate::{
        config::AppConfig,
        handler::user::RequestHandler,
        repository::{
            permissions::{DynPermissionRepositoryTrait, PermissionRepository},
            roles::{DynRoleRepositoryTrait, RoleRepository},
            users::{DynUserRepositoryTrait, UserRepository},
        },
        service::{
            permissions::{DynPermissionServiceTrait, PermissionService},
            roles::{DynRoleServiceTrait, RoleService},
            users::{DynUserServiceTrait, UserService},
        },
    };

    struct AllTraits {
        handler: RequestHandler,
        user_service: DynUserServiceTrait,
        user_repository: DynUserRepositoryTrait,
        role_repository: DynRoleRepositoryTrait,
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
        let handler = RequestHandler::new(user_service.clone(), role_service, permission_service);

        AllTraits {
            handler,
            user_service,
            user_repository,
            role_repository,
            permission_repository,
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

    #[sqlx::test]
    async fn add_role_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let role_name = "role_name".to_string();
        let request = Request::new(RolesPermissionsRequest {
            name: role_name.clone(),
        });
        all_traits.handler.add_role(request).await?;

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

        let request = Request::new(RolesPermissionsRequest {
            name: role_to_delete.clone(),
        });
        all_traits.handler.delete_role(request).await?;

        let role = all_traits.role_repository.get_roles(0, 10).await?;

        assert_eq!(role.len(), 1);
        assert_eq!(role.first().unwrap().name, role_to_not_delete);

        Ok(())
    }

    #[sqlx::test]
    async fn add_permission_test(pool: PgPool) -> anyhow::Result<()> {
        let all_traits = initialize_handler(pool);

        let permission_name = "permission_name".to_string();
        let request = Request::new(RolesPermissionsRequest {
            name: permission_name.clone(),
        });
        all_traits.handler.add_permission(request).await?;

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

        let request = Request::new(RolesPermissionsRequest {
            name: permission_to_delete.clone(),
        });
        all_traits.handler.delete_permission(request).await?;

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

        let request = Request::new(Role {
            name: role_name.clone(),
            permissions: vec![permission_name.clone()],
        });
        all_traits.handler.authorize_role(request).await?;
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

        let request = Request::new(Role {
            name: role_name.clone(),
            permissions: vec![permission_one_name.clone()],
        });
        all_traits.handler.revoke_role(request).await?;
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
