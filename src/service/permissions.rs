use crate::repository::users::DynUserRepositoryTrait;
use async_trait::async_trait;
use madtofan_microservice_common::{
    errors::ServiceResult,
    user::{RolesPermissionsRequest, StatusMessageResponse},
};
use mockall::automock;
use std::sync::Arc;

#[automock]
#[async_trait]
pub trait PermissionServiceTrait {
    async fn add_permission(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse>;
    async fn delete_permission(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse>;
}

pub type DynPermissionServiceTrait = Arc<dyn PermissionServiceTrait + Send + Sync>;

pub struct PermissionService {
    repository: DynUserRepositoryTrait,
}

#[async_trait]
impl PermissionServiceTrait for PermissionService {
    async fn add_permission(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse> {
        todo!()
    }
    async fn delete_permission(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse> {
        todo!()
    }
}
