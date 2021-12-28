use anyhow::Result;
use std::fs;

pub fn load_cert(ca_path: &str) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(&rustls::Certificate(fs::read(&ca_path)?))?;
    Ok(roots)
}
