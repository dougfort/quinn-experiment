use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;

mod certs;

// TODO: get from config
pub(crate) const KEY_PATH: &str = r#"/home/dougfort/Development/rcgen/certs/key.der"#;
pub(crate) const CERT_PATH: &str = r#"/home/dougfort/Development/rcgen/certs/cert.der"#;
pub(crate) const ROOT_PATH: &str = r#"/home/dougfort/Development/quinn"#;
pub(crate) const LISTEN_ADDRESS: &str = "[::1]:4433";

#[tokio::main]
async fn main() -> Result<()> {
    // Set the RUST_LOG, if it hasn't been explicitly defined
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "debug")
    }
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )?;

    let (certs, key) = certs::load_certs(KEY_PATH, CERT_PATH)?;

    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    let root_buf = PathBuf::from(ROOT_PATH);
    let root = Arc::<Path>::from(root_buf);
    if !root.exists() {
        bail!("root path does not exist");
    }

    let listen: SocketAddr = LISTEN_ADDRESS
        .parse()
        .context("unable to parse socket address")?;
    let (endpoint, mut incoming) = quinn::Endpoint::server(server_config, listen)?;

    info!("listening on {}", endpoint.local_addr()?);

    Ok(())
}
