#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("malformed PEM: {0}")]
    Pem(String),
    #[error("private key does not match certificate: {0}")]
    KeyMismatch(String),
    #[error("{0}: no private key found")]
    NoKey(String),
    #[error("could not read certificate validity: {0}")]
    Expiry(String),
}
