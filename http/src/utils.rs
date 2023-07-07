use axum::{
    async_trait,
    extract::{rejection::JsonRejection, FromRequest},
    http::Request,
    http::StatusCode,
};

pub struct CustomErrorJson<T>(pub T);

#[async_trait]
impl<S, B, T> FromRequest<S, B> for CustomErrorJson<T>
where
    axum::Json<T>: FromRequest<S, B, Rejection = JsonRejection>,
    S: Send + Sync,
    B: Send + 'static,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let req = Request::from_parts(parts, body);

        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => {
                let message = rejection.to_string();
                let code = if let JsonRejection::JsonDataError(_) = rejection {
                    StatusCode::BAD_REQUEST
                } else {
                    rejection.status()
                };
                Err((code, message))
            }
        }
    }
}
