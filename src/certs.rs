use anyhow::{Context, Result};
use std::fs;

pub fn load_certs(
    key_path: &str,
    cert_path: &str,
) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    let key = fs::read(key_path).context("failed to read private key")?;
    let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;

    Ok((
        vec![rustls::Certificate(cert_chain)],
        rustls::PrivateKey(key),
    ))
}
