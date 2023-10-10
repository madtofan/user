use crate::repository::roles::DynRoleRepositoryTrait;
use async_trait::async_trait;
use madtofan_microservice_common::{
    errors::ServiceResult,
    user::{Role, RolesPermissionsRequest, StatusMessageResponse},
};
use mockall::automock;
use std::sync::Arc;

#[automock]
#[async_trait]
pub trait RoleServiceTrait {
    async fn add_role(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse>;
    async fn delete_role(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse>;
    async fn authorize_role(&self, request: Role) -> ServiceResult<StatusMessageResponse>;
    async fn revoke_role(&self, request: Role) -> ServiceResult<StatusMessageResponse>;
}

pub type DynRoleServiceTrait = Arc<dyn RoleServiceTrait + Send + Sync>;

pub struct RoleService {
    repository: DynRoleRepositoryTrait,
}

#[async_trait]
impl RoleServiceTrait for RoleService {
    async fn add_role(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse> {
        todo!()
    }
    async fn delete_role(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse> {
        todo!()
    }
    async fn authorize_role(&self, request: Role) -> ServiceResult<StatusMessageResponse> {
        todo!()
    }
    async fn revoke_role(&self, request: Role) -> ServiceResult<StatusMessageResponse> {
        todo!()
    }
}
