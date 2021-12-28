use anyhow::{anyhow, bail, Context, Result};
use futures_util::{StreamExt, TryFutureExt};
use std::ascii;
use std::fs;
use std::net::SocketAddr;
use std::path::{self, Path, PathBuf};
use std::str;
use std::sync::Arc;
use tracing::{debug, error, info, info_span};
use tracing_futures::Instrument as _;

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

    while let Some(conn) = incoming.next().await {
        debug!("connection incoming");
        tokio::spawn(
            handle_connection(root.clone(), conn).unwrap_or_else(move |e| {
                error!("connection failed: {reason}", reason = e.to_string())
            }),
        );
    }

    Ok(())
}

async fn handle_connection(root: Arc<Path>, conn: quinn::Connecting) -> Result<()> {
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );

    async {
        info!("established");

        // each stream initiated by the client constitutes a new request
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };

            tokio::spawn(
                handle_request(root.clone(), stream)
                    .unwrap_or_else(move |e| error!("failed: {reason}", reason = e.to_string()))
                    .instrument(info_span!("request")),
            );
        }

        Ok(())
    }
    .instrument(span)
    .await?;

    Ok(())
}

async fn handle_request(
    root: Arc<Path>,
    (mut send, recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;

    let mut escaped = String::new();
    for &x in &req[..] {
        let part = ascii::escape_default(x).collect::<Vec<_>>();
        escaped.push_str(str::from_utf8(&part).unwrap());
    }
    info!(content = %escaped);

    // execute the request
    let resp = process_get(&root, &req).unwrap_or_else(|e| {
        error!("failed: {}", e);
        format!("failed to process request: {}\n", e).into_bytes()
    });

    // write the response
    send.write_all(&resp)
        .await
        .map_err(|e| anyhow!("failed to send response: {}", e))?;

    // Gracefully terminate the stream
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;

    Ok(())
}

fn process_get(root: &Path, x: &[u8]) -> Result<Vec<u8>> {
    if x.len() < 4 || &x[0..4] != b"GET" {
        bail!("missing GET");
    }
    if x[4..].len() < 2 || &x[x.len() - 2..] != b"\r\n" {
        bail!("missing \\r\\n");
    }
    let x = &x[4..x.len() - 2];
    let end = x.iter().position(|&c| c == b' ').unwrap_or_else(|| x.len());
    let path = str::from_utf8(&x[..end]).context("path is malformed UTF-8")?;
    let path = Path::new(&path);
    let mut real_path = PathBuf::from(root);
    let mut components = path.components();
    match components.next() {
        Some(path::Component::RootDir) => {}
        _ => {
            bail!("path must be absolute");
        }
    }
    for c in components {
        match c {
            path::Component::Normal(x) => {
                real_path.push(x);
            }
            x => {
                bail!("illegal components in path: {:?}", x);
            }
        }
    }
    let data = fs::read(&real_path).context("failed reading file")?;
    Ok(data)
}
