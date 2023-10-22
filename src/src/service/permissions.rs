use crate::repository::permissions::DynPermissionRepositoryTrait;
use async_trait::async_trait;
use madtofan_microservice_common::{
    errors::ServiceResult,
    user::{RolesPermissionsRequest, StatusMessageResponse},
};
use std::sync::Arc;
use tracing::log::info;

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
    async fn get_permissions(&self, offset: i64, limit: i64) -> ServiceResult<Vec<String>>;
}

pub type DynPermissionServiceTrait = Arc<dyn PermissionServiceTrait + Send + Sync>;

pub struct PermissionService {
    repository: DynPermissionRepositoryTrait,
}

impl PermissionService {
    pub fn new(repository: DynPermissionRepositoryTrait) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl PermissionServiceTrait for PermissionService {
    async fn add_permission(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse> {
        info!("adding permission {:?}", request.name);
        let permission = self.repository.create_permission(&request.name).await?;

        info!("added permission {:?}", permission.name);

        let message = format!("permission added: {:?}", permission.name);
        Ok(StatusMessageResponse { message })
    }
    async fn delete_permission(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse> {
        info!("deleting permission {:?}", request.name);
        let permission_delete_result = self.repository.delete_permission(&request.name).await?;

        let message = match permission_delete_result {
            Some(permission) => {
                info!("deleted permission {:?}", permission.name);
                format!("permission deleted: {:?}", permission.name)
            }
            None => {
                info!("permission not found: {:?}", request.name);
                format!("permission not found: {:?}", request.name)
            }
        };

        Ok(StatusMessageResponse { message })
    }
    async fn get_permissions(&self, offset: i64, limit: i64) -> ServiceResult<Vec<String>> {
        info!(
            "getting permissions with offset {} and limit {}",
            offset, limit
        );
        let permissions = self.repository.get_permissions(offset, limit).await?;
        return Ok(permissions
            .into_iter()
            .map(|permission| permission.name)
            .collect());
    }
}
