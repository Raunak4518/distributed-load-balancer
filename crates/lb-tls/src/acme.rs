use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, ChallengeType,
    Error as AcmeProtocolError, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

#[derive(Debug)]
pub enum AcmeError {
    Protocol(AcmeProtocolError),
    Io(std::io::Error),
    Serde(serde_json::Error),
    ChallengeUnavailable,
    AuthorizationFailed(String),
    OrderNotReady(OrderStatus),
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
}
