use didkit::JWK;
use serde::Deserialize;
use serde_with::{json::JsonString, serde_as};

#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Config {
    pub http: Http,
    pub issuer: Issuer,
}

#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Http {
    pub port: u16,
    pub address: [u8; 4],
    #[serde(rename = "bodysizelimit")]
    pub body_size_limit: usize,
}

// #[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
// pub struct Resolver {
//     pub fallback: Option<Url>,
// }

#[serde_as]
#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Issuer {
    #[serde_as(as = "Option<JsonString>")]
    pub keys: Option<Vec<JWK>>,
}
