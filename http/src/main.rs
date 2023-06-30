use std::net::SocketAddr;

use axum::{
    routing::{get, post},
    Extension, Router,
};
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use tower::ServiceBuilder;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing::info;

use crate::keys::KeyMap;

mod config;
mod credentials;
mod error;
mod identifiers;
mod keys;
mod presentations;
mod utils;

pub async fn healthcheck() {}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let pkg_name = env!("CARGO_PKG_NAME").replace('-', "_");
    let config: config::Config = Figment::new()
        .merge(Toml::string(include_str!("../defaults.toml")).nested())
        .merge(Toml::file(format!("{pkg_name}.toml")).nested())
        .merge(
            Env::prefixed(&format!("{}_", pkg_name.to_uppercase()))
                .split("_")
                .global(),
        )
        .extract()
        .expect("Unable to load config");

    let keys: KeyMap = config
        .issuer
        .keys
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|jwk| (jwk.to_public(), jwk))
        .collect();

    let app = Router::new()
        .route("/healthz", get(healthcheck))
        // vc-http-api 0.0.1
        .route("/issue/credentials", post(credentials::issue))
        .route("/verify/credentials", post(credentials::verify))
        .route("/issue/presentations", post(presentations::issue))
        .route("/verify/presentations", post(presentations::verify))
        //
        .route("/credentials/issue", post(credentials::issue))
        .route("/credentials/verify", post(credentials::verify))
        .route("/presentations/issue", post(presentations::issue))
        .route("/presentations/verify", post(presentations::verify))
        .route("/identifiers/:id", get(identifiers::resolve))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(config.http.body_size_limit))
        .layer(
            ServiceBuilder::new()
                .layer(Extension(config.clone()))
                .layer(Extension(keys.clone())),
        );

    let addr = SocketAddr::from((config.http.address, config.http.port));
    info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .expect("failed to start server");
}

#[cfg(test)]
mod test {
    use didkit::JWK;
    use figment::providers::Format;
    use serde_json::json;

    use super::*;

    pub fn default_config() -> config::Config {
        Figment::new()
            .merge(Toml::string(include_str!("../defaults.toml")).nested())
            .extract()
            .expect("Unable to load config")
    }

    #[test]
    fn can_generate_default_config() {
        default_config();
    }

    pub fn default_keys() -> KeyMap {
        let keys: Vec<JWK> = serde_json::from_value(json!([{"kty":"OKP","crv":"Ed25519","x":"HvjBEw94RHAh9KkiD385aYZNxGkxIkwBcrLBY5Z7Koo","d":"1onWu34oC29Y09qCRl0aD2FOp5y5obTqHZxQQRT3-bs"}, {"kty":"EC","crv":"P-256","x":"FMWMt6D0SymYPdlxXzeGMo1OrZLTrZ44aaW0_gyqCZM","y":"3DOY-ceh9ivyq9CzrmWR67ILrC7e3_FegeBxixWoiYc","d":"DjD-ngByYFcS6bfmofNeT7WNJBtWcO2GnGHJq1S9zkU"}])).unwrap();
        keys.into_iter().map(|jwk| (jwk.to_public(), jwk)).collect()
    }
}
