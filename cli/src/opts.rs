use clap::StructOpt;

use didkit::{HTTPDIDResolver, SeriesResolver, DID_METHODS};

#[derive(StructOpt, Debug, Clone, Default)]
pub struct ResolverOptions {
    #[clap(env, short = 'r', long, parse(from_str = HTTPDIDResolver::new))]
    /// Fallback DID Resolver HTTP(S) endpoint, for non-built-in DID methods.
    pub did_resolver: Option<HTTPDIDResolver>,
    #[clap(env, short = 'R', long, parse(from_str = HTTPDIDResolver::new))]
    /// Override DID Resolver HTTP(S) endpoint, for all DID methods.
    pub did_resolver_override: Option<HTTPDIDResolver>,
}

impl ResolverOptions {
    pub fn to_resolver<'a>(&'a self) -> SeriesResolver<'a> {
        let mut resolvers = vec![DID_METHODS.to_resolver()];
        if let Some(http_did_resolver) = &self.did_resolver {
            resolvers.push(http_did_resolver);
        }
        if let Some(http_did_resolver) = &self.did_resolver_override {
            resolvers.insert(0, http_did_resolver);
        }
        SeriesResolver { resolvers }
    }
}
