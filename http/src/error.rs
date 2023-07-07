use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::{debug, error};

#[derive(Debug, Clone)]
pub struct Error {
    status: StatusCode,
    body: ErrorBody,
}

#[derive(Debug, Clone)]
pub enum ErrorBody {
    Text(String),
    // Json(serde_json::Value),
}

impl From<(StatusCode, String)> for Error {
    fn from(e: (StatusCode, String)) -> Error {
        Error {
            status: e.0,
            body: ErrorBody::Text(e.1),
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        error!("{:?}", e);
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: ErrorBody::Text(e.to_string()),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self.body {
            ErrorBody::Text(t) => {
                debug!("{t}");
                (self.status, t).into_response()
            } // ErrorBody::Json(j) => (self.status, axum::Json(j)).into_response(),
        }
    }
}
