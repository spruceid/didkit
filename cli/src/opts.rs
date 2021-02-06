use structopt::StructOpt;

use didkit::{HTTPDIDResolver, SeriesResolver, DID_METHODS};

#[derive(StructOpt, Debug, Clone, Default)]
pub struct ResolverOptions {
    #[structopt(env, short = "r", long, parse(from_str = HTTPDIDResolver::new))]
    /// DID Resolver HTTP(S) endpoint, for non-built-in DID methods.
    pub did_resolver: Option<HTTPDIDResolver>,
}

impl ResolverOptions {
    pub fn to_resolver<'a>(&'a self) -> SeriesResolver<'a> {
        let mut resolvers = vec![DID_METHODS.to_resolver()];
        if let Some(http_did_resolver) = &self.did_resolver {
            resolvers.push(http_did_resolver);
        }
        SeriesResolver { resolvers }
    }
}
