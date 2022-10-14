use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use clap::{AppSettings, ArgGroup, Parser, StructOpt};
use hyper::Server;

use didkit::JWK;
use didkit_cli::opts::ResolverOptions;
use didkit_http::DIDKitHTTPMakeSvc;
use didkit_http::Error;

#[derive(StructOpt, Debug)]
pub struct DIDKitHttpOpts {
    /// Port to listen on
    #[clap(env, short, long)]
    port: Option<u16>,
    /// Hostname to listen on
    #[clap(env, short = 's', long)]
    host: Option<std::net::IpAddr>,
    /// JWK to use for issuing
    #[clap(flatten)]
    key: KeyArg,
    #[clap(flatten)]
    resolver_options: ResolverOptions,
}

#[derive(StructOpt, Debug)]
pub struct KeyArg {
    #[clap(env, short, long, parse(from_os_str), group = "key_group")]
    key_path: Option<Vec<PathBuf>>,
    #[clap(
        env,
        short,
        long,
        parse(try_from_str = serde_json::from_str),
        conflicts_with = "key-path",
        group = "key_group",
        help = "WARNING: you should not use this through the CLI in a production environment, prefer its environment variable."
    )]
    jwk: Option<Vec<JWK>>,
}

impl KeyArg {
    fn get_jwks(&self) -> Vec<JWK> {
        match self.key_path.clone() {
            Some(paths) => paths
                .iter()
                .map(|filename| {
                    let key_file = File::open(filename).unwrap();
                    let key_reader = BufReader::new(key_file);
                    serde_json::from_reader(key_reader).unwrap()
                })
                .collect(),
            None => self.jwk.clone().unwrap_or_default(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let opt = DIDKitHttpOpts::from_args();

    let keys = opt.key.get_jwks();
    let makesvc = DIDKitHTTPMakeSvc::new(keys, opt.resolver_options);
    let host = opt.host.unwrap_or([127, 0, 0, 1].into());
    let addr = (host, opt.port.unwrap_or(0)).into();

    let server = Server::bind(&addr).serve(makesvc);
    let url = "http://".to_string() + &server.local_addr().to_string() + "/";
    println!("Listening on {}", url);
    server.await?;
    Ok(())
}
