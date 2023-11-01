use crate::repository::roles::DynRoleRepositoryTrait;
use async_trait::async_trait;
use madtofan_microservice_common::{
    errors::ServiceResult,
    user::{
        GetListRequest, ListResponse, Role, RolePermission, RolesPermissionsRequest,
        StatusMessageResponse,
    },
};
use mockall::automock;
use std::sync::Arc;
use tracing::log::info;

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
    async fn list_roles(&self, request: GetListRequest) -> ServiceResult<ListResponse>;
}

pub type DynRoleServiceTrait = Arc<dyn RoleServiceTrait + Send + Sync>;

pub struct RoleService {
    repository: DynRoleRepositoryTrait,
}

impl RoleService {
    pub fn new(repository: DynRoleRepositoryTrait) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl RoleServiceTrait for RoleService {
    async fn add_role(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse> {
        info!("adding role {:?}", request.name);
        let role = self.repository.create_role(&request.name).await?;

        info!("role added");
        let message = format!("role added: {:?}", role.name);
        Ok(StatusMessageResponse { message })
    }

    async fn delete_role(
        &self,
        request: RolesPermissionsRequest,
    ) -> ServiceResult<StatusMessageResponse> {
        info!("deleting role {:?}", request.name);
        let role = self.repository.delete_role(&request.name).await?;

        let message = match role {
            Some(role) => {
                info!("role deleted");
                format!("role deleted: {:?}", role.name)
            }
            None => {
                info!("role not found");
                format!("role not found: {:?}", request.name)
            }
        };

        Ok(StatusMessageResponse { message })
    }

    async fn authorize_role(&self, request: Role) -> ServiceResult<StatusMessageResponse> {
        info!(
            "linking role {:?} with permissions {:?}",
            request.name,
            request.permissions.join(",")
        );
        let role = self
            .repository
            .link_permissions(&request.name, request.permissions)
            .await?;

        info!("permissions linked to role");
        let message = format!("permissions linked to role: {:?}", role.name);
        Ok(StatusMessageResponse { message })
    }

    async fn revoke_role(&self, request: Role) -> ServiceResult<StatusMessageResponse> {
        info!(
            "unlinking role {:?} from permissions {:?}",
            request.name,
            request.permissions.join(",")
        );
        let role = self
            .repository
            .unlink_permissions(&request.name, request.permissions)
            .await?;

        info!("permissions unlinked from role");
        let message = format!("permissions unlinked from role: {:?}", role.name);
        Ok(StatusMessageResponse { message })
    }

    async fn list_roles(&self, request: GetListRequest) -> ServiceResult<ListResponse> {
        let offset = request.offset;
        let limit = request.limit;
        info!("getting roles with offset {} and limit {}", offset, limit);
        let roles = self.repository.get_roles(offset, limit).await?;
        let count = self.repository.get_roles_count().await?;
        return Ok(ListResponse {
            list: roles
                .into_iter()
                .map(|role| RolePermission {
                    id: role.id,
                    name: role.name,
                })
                .collect(),
            count,
        });
    }
}
