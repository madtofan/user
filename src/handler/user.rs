use tonic::{Request, Response, Status};
use tracing::log::info;

use crate::{
    service::users::DynUserServiceTrait,
    user::{
        user_server::User, GetUserRequest, LoginRequest, RegisterRequest, UpdateRequest,
        UserResponse,
    },
};

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
}
