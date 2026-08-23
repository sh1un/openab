use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;

const STORE_VERSION: u8 = 1;
const STATE_TTL: Duration = Duration::from_secs(10 * 60);
const GITHUB_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_API_URL: &str = "https://api.github.com";

#[derive(Clone)]
pub(crate) struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub store_path: PathBuf,
    pub store_key: [u8; 32],
    pub authorize_url: String,
    pub token_url: String,
    pub api_url: String,
}

impl OAuthConfig {
    pub fn from_env() -> Result<Option<Self>> {
        let client_id = optional_env("OPENAB_GITHUB_APP_CLIENT_ID");
        let client_secret = optional_env("OPENAB_GITHUB_APP_CLIENT_SECRET");
        let redirect_uri = optional_env("OPENAB_GITHUB_APP_REDIRECT_URI");
        let store_path = optional_env("OPENAB_GITHUB_BROKER_STORE_PATH");
        let store_key = optional_env("OPENAB_GITHUB_BROKER_STORE_KEY");
        let configured = [
            client_id.is_some(),
            client_secret.is_some(),
            redirect_uri.is_some(),
            store_path.is_some(),
            store_key.is_some(),
        ];
        if !configured.iter().any(|configured| *configured) {
            return Ok(None);
        }
        anyhow::ensure!(
            configured.iter().all(|configured| *configured),
            "GitHub OAuth requires OPENAB_GITHUB_APP_CLIENT_ID, OPENAB_GITHUB_APP_CLIENT_SECRET, OPENAB_GITHUB_APP_REDIRECT_URI, OPENAB_GITHUB_BROKER_STORE_PATH, and OPENAB_GITHUB_BROKER_STORE_KEY"
        );

        let redirect_uri = redirect_uri.expect("validated");
        let parsed_redirect = Url::parse(&redirect_uri).context("parse GitHub App redirect URI")?;
        anyhow::ensure!(
            parsed_redirect.scheme() == "https"
                || (parsed_redirect.scheme() == "http"
                    && matches!(parsed_redirect.host_str(), Some("localhost" | "127.0.0.1"))),
            "GitHub App redirect URI must use https (http is allowed only for loopback development)"
        );

        let decoded_key = STANDARD
            .decode(store_key.expect("validated"))
            .context("decode OPENAB_GITHUB_BROKER_STORE_KEY as base64")?;
        let store_key: [u8; 32] = decoded_key.try_into().map_err(|_| {
            anyhow!("OPENAB_GITHUB_BROKER_STORE_KEY must decode to exactly 32 bytes")
        })?;

        Ok(Some(Self {
            client_id: client_id.expect("validated"),
            client_secret: client_secret.expect("validated"),
            redirect_uri,
            store_path: PathBuf::from(store_path.expect("validated")),
            store_key,
            authorize_url: optional_env("OPENAB_GITHUB_AUTHORIZE_URL")
                .unwrap_or_else(|| GITHUB_AUTHORIZE_URL.into()),
            token_url: optional_env("OPENAB_GITHUB_TOKEN_URL")
                .unwrap_or_else(|| GITHUB_TOKEN_URL.into()),
            api_url: optional_env("OPENAB_GITHUB_API_URL").unwrap_or_else(|| GITHUB_API_URL.into()),
        }))
    }
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OAuthConnection {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
    refresh_token_expires_at: Option<u64>,
    pub github_user_id: u64,
    pub github_login: String,
    credential_version: u64,
}

impl OAuthConnection {
    fn access_token_is_fresh(&self) -> bool {
        self.expires_at
            .map(|expires_at| expires_at > now_epoch().saturating_add(60))
            .unwrap_or(true)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedEnvelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

struct EncryptedStore {
    path: PathBuf,
    key: LessSafeKey,
}

impl EncryptedStore {
    fn new(path: PathBuf, key: [u8; 32]) -> Result<Self> {
        let key = UnboundKey::new(&AES_256_GCM, &key)
            .map(LessSafeKey::new)
            .map_err(|_| anyhow!("initialize OAuth connection store encryption"))?;
        Ok(Self { path, key })
    }

    fn load(&self) -> Result<HashMap<String, OAuthConnection>> {
        if !self.path.exists() {
            return Ok(HashMap::new());
        }
        let envelope: EncryptedEnvelope = serde_json::from_slice(
            &fs::read(&self.path)
                .with_context(|| format!("read OAuth store {}", self.path.display()))?,
        )
        .context("decode OAuth store envelope")?;
        anyhow::ensure!(
            envelope.version == STORE_VERSION,
            "unsupported OAuth store version {}",
            envelope.version
        );
        let nonce_bytes = STANDARD
            .decode(envelope.nonce)
            .context("decode OAuth store nonce")?;
        let nonce_bytes: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| anyhow!("OAuth store nonce has an invalid length"))?;
        let mut plaintext = STANDARD
            .decode(envelope.ciphertext)
            .context("decode OAuth store ciphertext")?;
        let plaintext_len = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(STORE_VERSION.to_string().as_bytes()),
                &mut plaintext,
            )
            .map_err(|_| anyhow!("decrypt OAuth store (wrong key or corrupted file)"))?
            .len();
        plaintext.truncate(plaintext_len);
        serde_json::from_slice(&plaintext).context("decode decrypted OAuth connections")
    }

    fn save(&self, connections: &HashMap<String, OAuthConnection>) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create OAuth store directory {}", parent.display()))?;
        }
        let mut nonce_bytes = [0_u8; 12];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow!("generate OAuth store nonce"))?;
        let mut ciphertext = serde_json::to_vec(connections)?;
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(STORE_VERSION.to_string().as_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| anyhow!("encrypt OAuth connections"))?;
        let envelope = EncryptedEnvelope {
            version: STORE_VERSION,
            nonce: STANDARD.encode(nonce_bytes),
            ciphertext: STANDARD.encode(ciphertext),
        };
        let temporary = temporary_path(&self.path);
        fs::write(&temporary, serde_json::to_vec_pretty(&envelope)?)
            .with_context(|| format!("write OAuth store {}", temporary.display()))?;
        restrict_file_permissions(&temporary)?;
        fs::rename(&temporary, &self.path)
            .with_context(|| format!("replace OAuth store {}", self.path.display()))?;
        Ok(())
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut extension = path
        .extension()
        .map(|value| value.to_os_string())
        .unwrap_or_default();
    extension.push(".tmp");
    path.with_extension(extension)
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set OAuth store permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[derive(Clone)]
pub(crate) struct GithubOAuth {
    config: Arc<OAuthConfig>,
    http: reqwest::Client,
    store: Arc<EncryptedStore>,
    connections: Arc<Mutex<HashMap<String, OAuthConnection>>>,
    pending: Arc<Mutex<HashMap<String, PendingAuthorization>>>,
}

#[derive(Debug)]
struct PendingAuthorization {
    subject: String,
    code_verifier: String,
    created_at: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    refresh_token_expires_in: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubUser {
    id: u64,
    login: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

impl GithubOAuth {
    pub fn new(config: OAuthConfig) -> Result<Self> {
        validate_provider_url(&config.authorize_url, "GitHub authorize URL")?;
        validate_provider_url(&config.token_url, "GitHub token URL")?;
        validate_provider_url(&config.api_url, "GitHub API URL")?;
        let store = Arc::new(EncryptedStore::new(
            config.store_path.clone(),
            config.store_key,
        )?);
        let connections = store.load()?;
        let http = reqwest::Client::builder()
            .user_agent(concat!(
                "openab-github-mcp-broker/",
                env!("CARGO_PKG_VERSION")
            ))
            .timeout(Duration::from_secs(30))
            .build()
            .context("build GitHub OAuth HTTP client")?;
        Ok(Self {
            config: Arc::new(config),
            http,
            store,
            connections: Arc::new(Mutex::new(connections)),
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn is_connected(&self, subject: &str) -> bool {
        self.connections.lock().await.contains_key(subject)
    }

    pub async fn begin(&self, subject: String) -> Result<String> {
        let state = random_urlsafe(32)?;
        let code_verifier = random_urlsafe(32)?;
        let challenge = URL_SAFE_NO_PAD.encode(digest(&SHA256, code_verifier.as_bytes()));
        let mut authorize_url = Url::parse(&self.config.authorize_url)?;
        authorize_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let now = now_epoch();
        let mut pending = self.pending.lock().await;
        pending.retain(|_, authorization| {
            now.saturating_sub(authorization.created_at) <= STATE_TTL.as_secs()
                && authorization.subject != subject
        });
        pending.insert(
            state,
            PendingAuthorization {
                subject,
                code_verifier,
                created_at: now,
            },
        );
        Ok(authorize_url.into())
    }

    pub async fn access_token(&self, subject: &str) -> Result<String> {
        let mut connections = self.connections.lock().await;
        let connection = connections
            .get(subject)
            .cloned()
            .ok_or_else(|| anyhow!("GitHub account is not connected for subject {subject:?}"))?;
        if connection.access_token_is_fresh() {
            return Ok(connection.access_token);
        }
        let refresh_token = connection.refresh_token.as_deref().ok_or_else(|| {
            anyhow!("GitHub authorization expired for subject {subject:?}; reconnect GitHub")
        })?;
        if connection
            .refresh_token_expires_at
            .is_some_and(|expires_at| expires_at <= now_epoch().saturating_add(60))
        {
            bail!("GitHub refresh token expired for subject {subject:?}; reconnect GitHub");
        }
        let token = self.refresh(refresh_token).await?;
        let updated = connection_from_token(
            token,
            connection.github_user_id,
            connection.github_login,
            connection.credential_version + 1,
        )?;
        let access_token = updated.access_token.clone();
        connections.insert(subject.to_owned(), updated);
        self.store.save(&connections)?;
        tracing::info!(%subject, "refreshed delegated GitHub user access token");
        Ok(access_token)
    }

    pub async fn callback(&self, query: CallbackQuery) -> Result<String> {
        if let Some(error) = query.error {
            bail!(
                "GitHub authorization failed: {}",
                query.error_description.unwrap_or(error)
            );
        }
        let state = query.state.context("GitHub OAuth callback missing state")?;
        let code = query.code.context("GitHub OAuth callback missing code")?;
        let pending = self
            .pending
            .lock()
            .await
            .remove(&state)
            .context("GitHub OAuth state is invalid, expired, or already used")?;
        anyhow::ensure!(
            now_epoch().saturating_sub(pending.created_at) <= STATE_TTL.as_secs(),
            "GitHub OAuth state expired; start the connection again"
        );
        let token = self.exchange_code(&code, &pending.code_verifier).await?;
        let access_token = token
            .access_token
            .as_deref()
            .context("GitHub token response omitted access_token")?;
        let user = self.github_user(access_token).await?;
        let connection = connection_from_token(token, user.id, user.login.clone(), 1)?;
        let mut connections = self.connections.lock().await;
        connections.insert(pending.subject.clone(), connection);
        self.store.save(&connections)?;
        tracing::info!(subject = %pending.subject, github_user_id = user.id, github_login = %user.login, "connected delegated GitHub account");
        Ok(user.login)
    }

    async fn exchange_code(&self, code: &str, code_verifier: &str) -> Result<TokenResponse> {
        self.token_request(&[
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("code_verifier", code_verifier),
        ])
        .await
    }

    async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse> {
        self.token_request(&[
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .await
    }

    async fn token_request(&self, form: &[(&str, &str)]) -> Result<TokenResponse> {
        let response = self
            .http
            .post(&self.config.token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(form)
            .send()
            .await
            .context("call GitHub OAuth token endpoint")?;
        let status = response.status();
        let token: TokenResponse = response
            .json()
            .await
            .context("decode GitHub OAuth token response")?;
        if !status.is_success() || token.error.is_some() {
            bail!(
                "GitHub OAuth token exchange failed: {}",
                token
                    .error_description
                    .or(token.error)
                    .unwrap_or_else(|| status.to_string())
            );
        }
        Ok(token)
    }

    async fn github_user(&self, access_token: &str) -> Result<GithubUser> {
        let endpoint = format!("{}/user", self.config.api_url.trim_end_matches('/'));
        self.http
            .get(endpoint)
            .bearer_auth(access_token)
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .context("query connected GitHub user")?
            .error_for_status()
            .context("GitHub rejected connected user token")?
            .json()
            .await
            .context("decode connected GitHub user")
    }
}

fn connection_from_token(
    token: TokenResponse,
    github_user_id: u64,
    github_login: String,
    credential_version: u64,
) -> Result<OAuthConnection> {
    let now = now_epoch();
    Ok(OAuthConnection {
        access_token: token
            .access_token
            .context("GitHub token response omitted access_token")?,
        refresh_token: token.refresh_token,
        expires_at: token.expires_in.map(|seconds| now.saturating_add(seconds)),
        refresh_token_expires_at: token
            .refresh_token_expires_in
            .map(|seconds| now.saturating_add(seconds)),
        github_user_id,
        github_login,
        credential_version,
    })
}

fn validate_provider_url(value: &str, label: &str) -> Result<()> {
    let url = Url::parse(value).with_context(|| format!("parse {label}"))?;
    anyhow::ensure!(url.scheme() == "https", "{label} must use https");
    Ok(())
}

fn random_urlsafe(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| anyhow!("generate OAuth random value"))?;
    Ok(URL_SAFE_NO_PAD.encode(value))
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) async fn callback_response(oauth: GithubOAuth, query: CallbackQuery) -> Response {
    match oauth.callback(query).await {
        Ok(login) => Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>GitHub connected</title><h1>GitHub connected</h1><p>Account <strong>{}</strong> is now connected. You can close this tab and return to Slack.</p>",
            html_escape(&login)
        ))
        .into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "GitHub OAuth callback failed");
            (
                StatusCode::BAD_REQUEST,
                Html("<!doctype html><meta charset=\"utf-8\"><title>Connection failed</title><h1>GitHub connection failed</h1><p>The link may be expired or already used. Return to Slack and start again.</p>"),
            )
                .into_response()
        }
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_store_round_trip_and_no_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("connections.enc.json");
        let store = EncryptedStore::new(path.clone(), [7; 32]).unwrap();
        let connections = HashMap::from([(
            "employee-sh1un".to_owned(),
            OAuthConnection {
                access_token: "secret-access-token".into(),
                refresh_token: Some("secret-refresh-token".into()),
                expires_at: Some(4_102_444_800),
                refresh_token_expires_at: Some(4_102_444_900),
                github_user_id: 123,
                github_login: "sh1un".into(),
                credential_version: 1,
            },
        )]);
        store.save(&connections).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret-access-token"));
        assert!(!raw.contains("employee-sh1un"));
        let loaded = store.load().unwrap();
        assert_eq!(loaded["employee-sh1un"].github_login, "sh1un");
    }

    #[test]
    fn encrypted_store_rejects_wrong_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("connections.enc.json");
        EncryptedStore::new(path.clone(), [7; 32])
            .unwrap()
            .save(&HashMap::new())
            .unwrap();
        assert!(EncryptedStore::new(path, [8; 32]).unwrap().load().is_err());
    }

    #[test]
    fn html_output_is_escaped() {
        assert_eq!(html_escape("<user&\">"), "&lt;user&amp;&quot;&gt;");
    }
}
