use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use hyper::Server;
use structopt::StructOpt;

use didkit::JWK;
use didkit_http::DIDKitHTTPMakeSvc;
use didkit_http::Error;

#[derive(StructOpt, Debug)]
pub struct DIDKitHttpOpts {
    /// Port to listen on
    #[structopt(short, long)]
    port: Option<u16>,
    /// Hostname to listen on
    #[structopt(short = "s", long)]
    host: Option<std::net::IpAddr>,
    /// JWK to use for issuing
    #[structopt(short, long, parse(from_os_str))]
    key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let opt = DIDKitHttpOpts::from_args();

    let key = match opt.key {
        Some(key_path) => {
            let key_file = File::open(key_path).unwrap();
            let key_reader = BufReader::new(key_file);
            let key: JWK = serde_json::from_reader(key_reader).unwrap();
            Some(key)
        }
        None => None,
    };
    let makesvc = DIDKitHTTPMakeSvc::new(key);
    let host = opt.host.unwrap_or([127, 0, 0, 1].into());
    let addr = (host, opt.port.unwrap_or(0)).into();

    let server = Server::bind(&addr).serve(makesvc);
    let url = "http://".to_string() + &server.local_addr().to_string() + "/";
    println!("Listening on {}", url);
    server.await?;
    Ok(())
}
