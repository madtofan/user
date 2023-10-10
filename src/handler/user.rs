use madtofan_microservice_common::user::{
    user_server::User, GetUserRequest, LoginRequest, RefreshTokenRequest, RegisterRequest, Role,
    RolesPermissionsRequest, StatusMessageResponse, UpdateRequest, UserResponse,
    VerifyRegistrationRequest, VerifyTokenRequest, VerifyTokenResponse,
};
use tonic::{Request, Response, Status};
use tracing::log::info;

use crate::service::users::DynUserServiceTrait;

pub struct RequestHandler {
    user_service: DynUserServiceTrait,
}

impl RequestHandler {
    pub fn new(user_service: DynUserServiceTrait) -> Self {
        Self { user_service }
    }
}

#[tonic::async_trait]
impl User for RequestHandler {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        info!("Login Request!");
        let logged_in_user = self.user_service.login_user(request.into_inner()).await?;

        Ok(Response::new(logged_in_user))
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        info!("Register Request!");
        let created_user = self
            .user_service
            .register_user(request.into_inner())
            .await?;

        Ok(Response::new(created_user))
    }

    async fn verify_registration(
        &self,
        request: Request<VerifyRegistrationRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        info!("Verify Registration Request!");
        let verified_user = self
            .user_service
            .verify_registration(request.into_inner())
            .await?;

        Ok(Response::new(verified_user))
    }

    async fn get(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        info!("Get User Request!");
        let user = self.user_service.get_user(request.into_inner()).await?;

        Ok(Response::new(user))
    }

    async fn update(
        &self,
        request: Request<UpdateRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        info!("Update User Request!");
        let r = request.into_inner();

        match r.fields {
            Some(fields) => {
                let updated_user = self.user_service.update_user(r.id, fields).await?;

                Ok(Response::new(updated_user))
            }
            None => Err(Status::new(
                tonic::Code::NotFound,
                "Unable to obtain the field to update the user",
            )),
        }
    }

    async fn refresh_token(
        &self,
        request: Request<RefreshTokenRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        info!("Update Token Request!");
        let user = self
            .user_service
            .refresh_token(request.into_inner())
            .await?;

        Ok(Response::new(user))
    }

    async fn verify_token(
        &self,
        request: Request<VerifyTokenRequest>,
    ) -> Result<Response<VerifyTokenResponse>, Status> {
        info!("Verify Token Request!");
        let result = self.user_service.verify_token(request.into_inner()).await?;

        Ok(Response::new(result))
    }

    async fn add_permission(
        &self,
        request: Request<RolesPermissionsRequest>,
    ) -> Result<Response<StatusMessageResponse>, Status> {
        info!("Add Permission Request!");
        todo!()
    }

    async fn delete_permission(
        &self,
        request: Request<RolesPermissionsRequest>,
    ) -> Result<Response<StatusMessageResponse>, Status> {
        info!("Delete Permission Request!");
        todo!()
    }

    async fn add_role(
        &self,
        request: Request<RolesPermissionsRequest>,
    ) -> Result<Response<StatusMessageResponse>, Status> {
        info!("Add Role Request!");
        todo!()
    }

    async fn delete_role(
        &self,
        request: Request<RolesPermissionsRequest>,
    ) -> Result<Response<StatusMessageResponse>, Status> {
        info!("Delete Role Request!");
        todo!()
    }

    async fn authorize_role(
        &self,
        request: Request<Role>,
    ) -> Result<Response<StatusMessageResponse>, Status> {
        info!("Authorize Role Request!");
        todo!()
    }

    async fn revoke_role(
        &self,
        request: Request<Role>,
    ) -> Result<Response<StatusMessageResponse>, Status> {
        info!("Revoke Role Request!");
        todo!()
    }
}
