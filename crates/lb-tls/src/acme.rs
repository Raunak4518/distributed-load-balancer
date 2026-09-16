use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, ChallengeType,
    Error as AcmeProtocolError, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Debug)]
pub enum AcmeError {
    Protocol(AcmeProtocolError),
    Io(std::io::Error),
    Serde(serde_json::Error),
    ChallengeUnavailable,
    AuthorizationFailed(String),
    OrderNotReady(OrderStatus),
    GaveUp,
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Protocol(e) => write!(f, "{e}"),
            AcmeError::Io(e) => write!(f, "{e}"),
            AcmeError::Serde(e) => write!(f, "{e}"),
            AcmeError::ChallengeUnavailable => write!(f, "no http-01 challenge offered"),
            AcmeError::AuthorizationFailed(status) => {
                write!(f, "authorization failed with status {status}")
            }
            AcmeError::OrderNotReady(status) => write!(f, "order not ready: {status:?}"),
            AcmeError::GaveUp => write!(f, "gave up retrying after exhausting the retry window"),
        }
    }
}

impl std::error::Error for AcmeError {}

impl From<AcmeProtocolError> for AcmeError {
    fn from(e: AcmeProtocolError) -> Self {
        AcmeError::Protocol(e)
    }
}

impl From<std::io::Error> for AcmeError {
    fn from(e: std::io::Error) -> Self {
        AcmeError::Io(e)
    }
}

impl From<serde_json::Error> for AcmeError {
    fn from(e: serde_json::Error) -> Self {
        AcmeError::Serde(e)
    }
}

#[derive(Default)]
pub struct AcmeChallengeStore {
    tokens: RwLock<HashMap<String, String>>,
}

impl AcmeChallengeStore {
    pub fn new() -> Self {
        AcmeChallengeStore {
            tokens: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(&self, token: String, key_authorization: String) {
        self.tokens
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token, key_authorization);
    }

    pub fn remove(&self, token: &str) {
        self.tokens
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
    }

    pub fn get(&self, token: &str) -> Option<String> {
        self.tokens
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(token)
            .cloned()
    }
}

pub enum AcmeTrust<'a> {
    SystemRoots,
    CustomRootPem(&'a Path),
}

fn account_builder(trust: &AcmeTrust) -> Result<AccountBuilder, AcmeError> {
    Ok(match trust {
        AcmeTrust::SystemRoots => Account::builder()?,
        AcmeTrust::CustomRootPem(path) => Account::builder_with_root(path)?,
    })
}

pub async fn account_for(
    trust: AcmeTrust<'_>,
    directory_url: &str,
    contact_email: &str,
    credentials_path: &Path,
) -> Result<Account, AcmeError> {
    if let Ok(existing) = std::fs::read_to_string(credentials_path) {
        if let Ok(credentials) = serde_json::from_str::<AccountCredentials>(&existing) {
            if let Ok(account) = account_builder(&trust)?.from_credentials(credentials).await {
                return Ok(account);
            }
        }
    }

    let contact = format!("mailto:{contact_email}");
    let (account, credentials) = account_builder(&trust)?
        .create(
            &NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_string(),
            None,
        )
        .await?;

    if let Some(parent) = credentials_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(credentials_path, serde_json::to_string(&credentials)?)?;

    Ok(account)
}

pub async fn obtain_certificate_http01(
    account: &Account,
    domain: &str,
    challenges: &AcmeChallengeStore,
) -> Result<(String, String), AcmeError> {
    let identifiers = [Identifier::Dns(domain.to_string())];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    let mut pending_tokens = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => return Err(AcmeError::AuthorizationFailed(format!("{other:?}"))),
        }

        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or(AcmeError::ChallengeUnavailable)?;
        let key_authorization = challenge.key_authorization();
        let token = challenge.token.clone();
        challenges.insert(token.clone(), key_authorization.as_str().to_string());
        pending_tokens.push(token);
        challenge.set_ready().await?;
    }

    let status = order.poll_ready(&RetryPolicy::default()).await;
    for token in &pending_tokens {
        challenges.remove(token);
    }
    match status? {
        OrderStatus::Ready => {}
        other => return Err(AcmeError::OrderNotReady(other)),
    }

    let private_key_pem = order.finalize().await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

    Ok((cert_chain_pem, private_key_pem))
}

pub fn ensure_bootstrap_certificate(
    cert_file: &Path,
    key_file: &Path,
    hostname: &str,
) -> Result<(), AcmeError> {
    if cert_file.exists() && key_file.exists() {
        return Ok(());
    }
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| AcmeError::Io(std::io::Error::other(e.to_string())))?;
    let mut params = rcgen::CertificateParams::new([hostname.to_string()])
        .map_err(|e| AcmeError::Io(std::io::Error::other(e.to_string())))?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(2);
    params.not_after = now - time::Duration::days(1);
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| AcmeError::Io(std::io::Error::other(e.to_string())))?;
    if let Some(parent) = cert_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cert_file, cert.pem())?;
    std::fs::write(key_file, key_pair.serialize_pem())?;
    Ok(())
}

pub fn needs_renewal(cert_file: &Path, renew_before: Duration) -> bool {
    let Ok(pem) = std::fs::read_to_string(cert_file) else {
        return true;
    };
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let Some(Ok(der)) = rustls_pemfile::certs(&mut reader).next() else {
        return true;
    };
    use x509_parser::prelude::FromDer;
    let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(der.as_ref()) else {
        return true;
    };
    let not_after = cert.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    not_after - now < renew_before.as_secs() as i64
}

#[allow(clippy::too_many_arguments)]
pub async fn renew_once(
    trust: AcmeTrust<'_>,
    directory_url: String,
    contact_email: &str,
    account_key_file: &Path,
    domain: &str,
    cert_file: &Path,
    key_file: &Path,
    challenges: &AcmeChallengeStore,
) -> Result<(), AcmeError> {
    let account = account_for(trust, &directory_url, contact_email, account_key_file).await?;
    let (cert_chain_pem, private_key_pem) =
        obtain_certificate_http01(&account, domain, challenges).await?;

    if let Some(parent) = cert_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cert_file, cert_chain_pem)?;
    std::fs::write(key_file, private_key_pem)?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct AcmeRetryPolicy {
    pub fallback_directory_url: Option<String>,
    pub staging_directory_url: Option<String>,
    pub immediate_retry_delay: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub give_up_after: Duration,
}

impl Default for AcmeRetryPolicy {
    fn default() -> Self {
        AcmeRetryPolicy {
            fallback_directory_url: None,
            staging_directory_url: None,
            immediate_retry_delay: Duration::from_secs(10),
            initial_backoff: Duration::from_secs(60),
            max_backoff: Duration::from_secs(3_600),
            give_up_after: Duration::from_secs(30 * 86_400),
        }
    }
}

pub fn next_backoff(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

pub async fn retry_issuance<F, Fut>(
    policy: &AcmeRetryPolicy,
    primary_directory_url: &str,
    mut attempt: F,
) -> Result<(), AcmeError>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<(), AcmeError>>,
{
    if attempt(primary_directory_url.to_string()).await.is_ok() {
        return Ok(());
    }

    tokio::time::sleep(policy.immediate_retry_delay).await;
    if attempt(primary_directory_url.to_string()).await.is_ok() {
        return Ok(());
    }

    if let Some(fallback) = &policy.fallback_directory_url {
        if attempt(fallback.clone()).await.is_ok() {
            return Ok(());
        }
    }

    let started = tokio::time::Instant::now();
    let mut backoff = policy.initial_backoff;
    let retry_url = policy
        .staging_directory_url
        .clone()
        .unwrap_or_else(|| primary_directory_url.to_string());
    loop {
        if started.elapsed() >= policy.give_up_after {
            return Err(AcmeError::GaveUp);
        }
        tokio::time::sleep(backoff).await;
        if attempt(retry_url.clone()).await.is_ok() {
            return Ok(());
        }
        backoff = next_backoff(backoff, policy.max_backoff);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_acme_renewer(
    directory_url: String,
    contact_email: String,
    account_key_file: PathBuf,
    domain: String,
    cert_file: PathBuf,
    key_file: PathBuf,
    renew_before: Duration,
    check_interval: Duration,
    custom_root_pem: Option<PathBuf>,
    retry_policy: AcmeRetryPolicy,
    challenges: Arc<AcmeChallengeStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(check_interval);
        loop {
            ticker.tick().await;
            if !needs_renewal(&cert_file, renew_before) {
                continue;
            }
            let outcome = retry_issuance(&retry_policy, &directory_url, |url| {
                let trust = match &custom_root_pem {
                    Some(path) => AcmeTrust::CustomRootPem(path),
                    None => AcmeTrust::SystemRoots,
                };
                renew_once(
                    trust,
                    url,
                    &contact_email,
                    &account_key_file,
                    &domain,
                    &cert_file,
                    &key_file,
                    &challenges,
                )
            })
            .await;
            match outcome {
                Ok(()) => {
                    tracing::info!(domain = %domain, "acme certificate obtained");
                }
                Err(err) => {
                    tracing::error!(domain = %domain, error = %err, "acme certificate renewal failed");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_challenge_store_has_no_tokens() {
        let store = AcmeChallengeStore::new();
        assert_eq!(store.get("nonexistent"), None);
    }

    #[test]
    fn insert_then_get_round_trips() {
        let store = AcmeChallengeStore::new();
        store.insert("tok1".to_string(), "auth1".to_string());
        assert_eq!(store.get("tok1"), Some("auth1".to_string()));
    }

    #[test]
    fn remove_clears_a_token() {
        let store = AcmeChallengeStore::new();
        store.insert("tok1".to_string(), "auth1".to_string());
        store.remove("tok1");
        assert_eq!(store.get("tok1"), None);
    }

    #[test]
    fn removing_an_unknown_token_does_not_panic() {
        let store = AcmeChallengeStore::new();
        store.remove("ghost");
    }

    #[test]
    fn next_backoff_doubles_up_to_the_cap() {
        let max = Duration::from_secs(3600);
        assert_eq!(
            next_backoff(Duration::from_secs(60), max),
            Duration::from_secs(120)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(1800), max),
            Duration::from_secs(3600)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(3600), max),
            Duration::from_secs(3600)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(2400), max),
            Duration::from_secs(3600)
        );
    }

    fn fast_policy() -> AcmeRetryPolicy {
        AcmeRetryPolicy {
            fallback_directory_url: Some("https://fallback.example/dir".to_string()),
            staging_directory_url: Some("https://staging.example/dir".to_string()),
            immediate_retry_delay: Duration::from_secs(1),
            initial_backoff: Duration::from_secs(60),
            max_backoff: Duration::from_secs(3_600),
            give_up_after: Duration::from_secs(30 * 86_400),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_try_success_needs_no_retry() {
        let calls = std::sync::Mutex::new(Vec::<String>::new());
        let result = retry_issuance(&fast_policy(), "https://primary.example/dir", |url| {
            calls.lock().unwrap().push(url);
            std::future::ready(Ok(()))
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(*calls.lock().unwrap(), vec!["https://primary.example/dir"]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_immediate_retry_reuses_the_primary_issuer() {
        let calls = std::sync::Mutex::new(Vec::<String>::new());
        let n = std::sync::atomic::AtomicU32::new(0);
        let result = retry_issuance(&fast_policy(), "https://primary.example/dir", |url| {
            calls.lock().unwrap().push(url);
            let attempt = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(if attempt == 0 {
                Err(AcmeError::GaveUp)
            } else {
                Ok(())
            })
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                "https://primary.example/dir".to_string(),
                "https://primary.example/dir".to_string(),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_fallback_issuer_is_tried_after_the_primary_fails_twice() {
        let calls = std::sync::Mutex::new(Vec::<String>::new());
        let n = std::sync::atomic::AtomicU32::new(0);
        let result = retry_issuance(&fast_policy(), "https://primary.example/dir", |url| {
            calls.lock().unwrap().push(url);
            let attempt = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(if attempt < 2 {
                Err(AcmeError::GaveUp)
            } else {
                Ok(())
            })
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                "https://primary.example/dir".to_string(),
                "https://primary.example/dir".to_string(),
                "https://fallback.example/dir".to_string(),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_retries_use_the_staging_directory() {
        let calls = std::sync::Mutex::new(Vec::<String>::new());
        let n = std::sync::atomic::AtomicU32::new(0);
        let result = retry_issuance(&fast_policy(), "https://primary.example/dir", |url| {
            calls.lock().unwrap().push(url);
            let attempt = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(if attempt < 4 {
                Err(AcmeError::GaveUp)
            } else {
                Ok(())
            })
        })
        .await;
        assert!(result.is_ok());
        let seen = calls.lock().unwrap();
        assert_eq!(seen[0], "https://primary.example/dir");
        assert_eq!(seen[1], "https://primary.example/dir");
        assert_eq!(seen[2], "https://fallback.example/dir");
        assert_eq!(seen[3], "https://staging.example/dir");
        assert_eq!(seen[4], "https://staging.example/dir");
    }

    #[tokio::test(start_paused = true)]
    async fn giving_up_stops_after_the_configured_window() {
        let policy = AcmeRetryPolicy {
            give_up_after: Duration::from_secs(150),
            ..fast_policy()
        };
        let result = retry_issuance(&policy, "https://primary.example/dir", |_url| {
            std::future::ready(Err(AcmeError::GaveUp))
        })
        .await;
        assert!(matches!(result, Err(AcmeError::GaveUp)));
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_fallback_or_staging_url_backoff_retries_the_primary() {
        let policy = AcmeRetryPolicy {
            fallback_directory_url: None,
            staging_directory_url: None,
            ..fast_policy()
        };
        let calls = std::sync::Mutex::new(Vec::<String>::new());
        let n = std::sync::atomic::AtomicU32::new(0);
        let result = retry_issuance(&policy, "https://primary.example/dir", |url| {
            calls.lock().unwrap().push(url);
            let attempt = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(if attempt < 3 {
                Err(AcmeError::GaveUp)
            } else {
                Ok(())
            })
        })
        .await;
        assert!(result.is_ok());
        for url in calls.lock().unwrap().iter() {
            assert_eq!(url, "https://primary.example/dir");
        }
    }
}
