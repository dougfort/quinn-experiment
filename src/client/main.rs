use std::sync::Arc;
use std::{net::ToSocketAddrs, str::FromStr};
use std::time::{Duration, Instant};
use std::io::{self, Write};

use anyhow::{anyhow, Context, Result};
use tracing::info;
use url::Url;

mod certs;

const CERT_PATH: &str = r#"/home/dougfort/Development/rcgen/certs/cert.der"#;
const URL: &str = "https://localhost:4433/README.md";
const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
const CLIENT_ENDPOINT_ADDR: &str = "[::]:0";
const NAT_REBINDING: bool = false;
const OVERRIDE_HOST: Option<String> = None;

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

    info!("client starts");
    let url = Url::from_str(URL)?;
    let remote = (url.host_str().unwrap(), url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let roots = certs::load_cert(CERT_PATH).context("loading cert")?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
//    client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut endpoint = quinn::Endpoint::client(CLIENT_ENDPOINT_ADDR.parse().unwrap())?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));

    let request = format!("GET {}\r\n", url.path());
    let start = Instant::now();
    let _rebind = NAT_REBINDING;
    let host = OVERRIDE_HOST
        .as_ref()
        .map_or_else(|| url.host_str(), |x| Some(x))
        .ok_or_else(|| anyhow!("no hostname specified"))?;

    info!("connecting to {} at {}", host, remote);
    let new_conn = endpoint
        .connect(remote, host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;

    info!("connected at {:?}", start.elapsed());

    let quinn::NewConnection {
        connection: conn, ..
    } = new_conn;

    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;

    send.write_all(request.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to send request: {}", e))?;
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;

    let response_start = Instant::now();
    info!("request sent at {:?}", response_start - start);

    let resp = recv
        .read_to_end(usize::max_value())
        .await
        .map_err(|e| anyhow!("failed to read response: {}", e))?;

    let duration = response_start.elapsed();
    info!(
        "response received in {:?} - {} KiB/s",
        duration,
        resp.len() as f32 / (duration_secs(&duration) * 1024.0)
    );

    io::stdout().write_all(&resp).unwrap();
    io::stdout().flush().unwrap();
    conn.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    endpoint.wait_idle().await;

    Ok(())
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}
