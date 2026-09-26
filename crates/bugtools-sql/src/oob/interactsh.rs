//! Interactsh protocol client (brief §23).
//!
//! Interactsh (projectdiscovery/interactsh) is the de-facto open OOB collector:
//! a public or self-hosted server that records DNS/HTTP interactions and hands
//! them back end-to-end encrypted. This provider speaks its protocol directly,
//! so bugtools works out of the box against a public server *or* an operator's
//! own instance — no Burp, no manual polling.
//!
//! Wire protocol (as implemented by the reference server):
//!   register: POST /register  {"public-key": b64(PKIX PEM), "secret-key": uuid,
//!                              "correlation-id": <20 chars>}
//!   callback: <correlation-id(20)><rand(13)>.<server>   (a 33-char label)
//!   poll:     GET /poll?id=<correlation-id>&secret=<uuid>
//!             -> {"aes_key": b64(RSA-OAEP-SHA256-wrapped 32-byte AES key),
//!                 "data": [b64(ciphertext), ...]}
//!   each ciphertext = IV(16) || AES-256-CFB(plaintext); plaintext is a JSON
//!   interaction record ({"protocol","unique-id","full-id","remote-address",
//!   "timestamp", ...}).
//!
//! Only the correlator decides what counts as evidence: this client just
//! transports interactions and never treats mere traffic as proof.

use super::correlator::{InteractionType, OobInteraction};
use super::provider::{OobProvider, OobResult};
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use async_trait::async_trait;
use base64::Engine as _;
use rand::Rng;
use rsa::rand_core::OsRng;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

/// A public interactsh server used when the operator does not supply one.
/// Overridable with `--oob-interactsh-server` (self-host for sensitive scopes).
const DEFAULT_SERVER: &str = "oast.pro";

const CORRELATION_ID_LEN: usize = 20;
const RANDOM_LABEL_LEN: usize = 13;

type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;

/// A live registration against an interactsh server.
pub struct InteractshProvider {
    server: String,
    /// Optional bearer token for authenticated (self-hosted) servers.
    auth_token: Option<String>,
    /// PLAIN client — the collector is off-target infrastructure, never the
    /// scoped target, so it must NOT go through the scoped `SafeHttpClient`.
    client: reqwest::Client,
    private_key: RsaPrivateKey,
    public_key_b64: String,
    correlation_id: String,
    secret: String,
    /// The full 33-char label (`<correlation-id><rand>`) tokens attach to.
    subdomain: String,
}

#[derive(serde::Serialize)]
struct RegisterRequest {
    #[serde(rename = "public-key")]
    public_key: String,
    #[serde(rename = "secret-key")]
    secret_key: String,
    #[serde(rename = "correlation-id")]
    correlation_id: String,
}

#[derive(serde::Deserialize)]
struct PollResponse {
    aes_key: String,
    #[serde(default)]
    data: Vec<String>,
}

/// One decrypted interaction record as the server serializes it.
#[derive(serde::Deserialize)]
struct RawInteraction {
    protocol: String,
    #[serde(rename = "full-id", default)]
    full_id: String,
    #[serde(rename = "unique-id", default)]
    unique_id: String,
    #[serde(rename = "remote-address", default)]
    remote_address: String,
    #[serde(default)]
    timestamp: String,
}

impl InteractshProvider {
    /// Build a client, generating a fresh RSA-2048 keypair for this session.
    ///
    /// `server` defaults to a public interactsh host; pass a self-hosted host
    /// for sensitive engagements. `auth_token` is the server's optional bearer
    /// token (self-hosted `-token`).
    pub fn new(server: Option<String>, auth_token: Option<String>) -> OobResult<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| format!("interactsh: RSA keygen failed: {e}"))?;
        let public_key = RsaPublicKey::from(&private_key);
        // The server expects PKIX/SPKI PEM, base64-encoded as a whole.
        let pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| format!("interactsh: public key encode failed: {e}"))?;
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());

        let correlation_id = random_label(CORRELATION_ID_LEN);
        let random_tail = random_label(RANDOM_LABEL_LEN);
        let subdomain = format!("{correlation_id}{random_tail}");
        let secret = uuid::Uuid::new_v4().to_string();

        Ok(Self {
            server: server.unwrap_or_else(|| DEFAULT_SERVER.to_string()),
            auth_token,
            client: reqwest::Client::new(),
            private_key,
            public_key_b64,
            correlation_id,
            secret,
            subdomain,
        })
    }

    fn base_url(&self) -> String {
        // Accept a bare host or a full URL; normalize to an https origin.
        if self.server.starts_with("http://") || self.server.starts_with("https://") {
            self.server.trim_end_matches('/').to_string()
        } else {
            format!("https://{}", self.server.trim_end_matches('/'))
        }
    }

    /// The callback domain tokens attach to: `<33-char label>.<server-host>`.
    pub fn callback_domain(&self) -> String {
        format!("{}.{}", self.subdomain, self.server_host())
    }

    fn server_host(&self) -> String {
        self.server
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string()
    }

    /// Unwrap the RSA-OAEP(SHA-256) wrapped AES key.
    fn unwrap_aes_key(&self, aes_key_b64: &str) -> OobResult<Vec<u8>> {
        let wrapped = base64::engine::general_purpose::STANDARD
            .decode(aes_key_b64.trim())
            .map_err(|e| format!("interactsh: aes_key not base64: {e}"))?;
        let padding = Oaep::new::<sha2::Sha256>();
        let key = self
            .private_key
            .decrypt(padding, &wrapped)
            .map_err(|e| format!("interactsh: RSA unwrap failed: {e}"))?;
        Ok(key)
    }

    /// Decrypt one base64 `IV(16) || AES-256-CFB(ciphertext)` data entry into
    /// its JSON plaintext bytes. Exposed for the offline round-trip test.
    pub(crate) fn decrypt_entry(aes_key: &[u8], entry_b64: &str) -> OobResult<Vec<u8>> {
        let blob = base64::engine::general_purpose::STANDARD
            .decode(entry_b64.trim())
            .map_err(|e| format!("interactsh: data entry not base64: {e}"))?;
        if blob.len() <= 16 {
            return Err("interactsh: data entry too short for IV".into());
        }
        if aes_key.len() != 32 {
            return Err(format!("interactsh: expected 32-byte AES key, got {}", aes_key.len()).into());
        }
        let (iv, ciphertext) = blob.split_at(16);
        let cipher = Aes256CfbDec::new_from_slices(aes_key, iv)
            .map_err(|e| format!("interactsh: AES-CFB init failed: {e}"))?;
        let mut buf = ciphertext.to_vec();
        cipher.decrypt(&mut buf);
        Ok(buf)
    }

    /// Map a decrypted interaction record to our transport type. The token is
    /// the full observed subdomain (case-folded); the correlator locates the
    /// planted token inside it by containment.
    pub(crate) fn parse_interaction(plaintext: &[u8]) -> OobResult<OobInteraction> {
        let raw: RawInteraction = serde_json::from_slice(plaintext)
            .map_err(|e| format!("interactsh: interaction JSON parse failed: {e}"))?;
        let interaction_type = match raw.protocol.to_ascii_lowercase().as_str() {
            "dns" => InteractionType::Dns,
            "http" | "https" | "smtp" | "ldap" => InteractionType::Http,
            _ => InteractionType::Http,
        };
        // Prefer full-id (the whole queried subdomain, which carries our token);
        // fall back to unique-id if the server omitted it.
        let identifier = if raw.full_id.is_empty() {
            raw.unique_id.clone()
        } else {
            raw.full_id.clone()
        };
        let observed_at = parse_timestamp(&raw.timestamp);
        Ok(OobInteraction {
            token: identifier.to_ascii_lowercase(),
            interaction_type,
            observed_at,
            source: raw.remote_address,
        })
    }
}

/// Random lowercase alphanumeric label of `len` characters, matching the
/// character set interactsh uses for its correlation subdomain.
fn random_label(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// Parse an RFC3339 timestamp; fall back to "now" if the server omitted or
/// mangled it (the window check still guards attribution).
fn parse_timestamp(ts: &str) -> i64 {
    if ts.is_empty() {
        return chrono::Utc::now().timestamp();
    }
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.timestamp())
        .unwrap_or_else(|_| chrono::Utc::now().timestamp())
}

#[async_trait]
impl OobProvider for InteractshProvider {
    async fn register(&mut self) -> OobResult<String> {
        let body = RegisterRequest {
            public_key: self.public_key_b64.clone(),
            secret_key: self.secret.clone(),
            correlation_id: self.correlation_id.clone(),
        };
        let mut req = self
            .client
            .post(format!("{}/register", self.base_url()))
            .json(&body);
        if let Some(token) = &self.auth_token {
            req = req.header("Authorization", token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("interactsh: register request failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("interactsh: register returned HTTP {status}").into());
        }
        Ok(self.callback_domain())
    }

    async fn poll(&mut self) -> OobResult<Vec<OobInteraction>> {
        let mut req = self.client.get(format!(
            "{}/poll?id={}&secret={}",
            self.base_url(),
            self.correlation_id,
            self.secret
        ));
        if let Some(token) = &self.auth_token {
            req = req.header("Authorization", token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("interactsh: poll request failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("interactsh: poll returned HTTP {status}").into());
        }
        let parsed: PollResponse = resp
            .json()
            .await
            .map_err(|e| format!("interactsh: poll response parse failed: {e}"))?;
        if parsed.data.is_empty() {
            return Ok(Vec::new());
        }
        let aes_key = self.unwrap_aes_key(&parsed.aes_key)?;
        let mut interactions = Vec::new();
        for entry in &parsed.data {
            // A single malformed entry must not drop the rest of the poll.
            match Self::decrypt_entry(&aes_key, entry)
                .and_then(|pt| Self::parse_interaction(&pt))
            {
                Ok(i) => interactions.push(i),
                Err(e) => tracing::warn!("interactsh: skipping undecodable entry: {e}"),
            }
        }
        Ok(interactions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oob::correlator::{OobCorrelator, OobToken};
    use aes::cipher::AsyncStreamCipher;

    /// Encrypt a plaintext exactly as an interactsh server would, so the test
    /// exercises the real decrypt path without a network or a live server.
    fn server_encrypt(aes_key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> String {
        type Enc = cfb_mode::Encryptor<aes::Aes256>;
        let cipher = Enc::new_from_slices(aes_key, iv).unwrap();
        let mut buf = plaintext.to_vec();
        cipher.encrypt(&mut buf);
        let mut blob = iv.to_vec();
        blob.extend_from_slice(&buf);
        base64::engine::general_purpose::STANDARD.encode(blob)
    }

    #[test]
    fn callback_domain_has_expected_shape() {
        let p = InteractshProvider::new(Some("oast.example".into()), None).unwrap();
        let domain = p.callback_domain();
        // <20+13 char label>.<server>
        let label = domain.split('.').next().unwrap();
        assert_eq!(label.len(), CORRELATION_ID_LEN + RANDOM_LABEL_LEN);
        assert!(domain.ends_with(".oast.example"));
        assert!(label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn decrypt_and_parse_round_trip_correlates() {
        let provider = InteractshProvider::new(Some("oast.example".into()), None).unwrap();

        // A planted token bound to a request context.
        let token = OobToken::mint("bt", "example.test", "/api", "q", "query", 300);
        let observed = token.planted_at + 7;
        // The DB exfiltrates data as the leftmost label, our token next, then
        // the interactsh correlation subdomain: <data>.<token>.<sub>.<server>.
        let full_id = format!("5f8a.{}.{}", token.token, provider.subdomain);
        let record = format!(
            r#"{{"protocol":"dns","full-id":"{full_id}","unique-id":"{}","remote-address":"198.51.100.7","timestamp":"{}"}}"#,
            provider.subdomain,
            chrono::DateTime::from_timestamp(observed, 0)
                .unwrap()
                .to_rfc3339()
        );

        // Encrypt it the way the server does.
        let aes_key = [7u8; 32];
        let iv = [3u8; 16];
        let entry = server_encrypt(&aes_key, &iv, record.as_bytes());

        // Decrypt + parse through the provider's real code path.
        let pt = InteractshProvider::decrypt_entry(&aes_key, &entry).unwrap();
        let interaction = InteractshProvider::parse_interaction(&pt).unwrap();
        assert_eq!(interaction.interaction_type, InteractionType::Dns);
        assert!(interaction.token.contains(&token.token));
        assert_eq!(interaction.observed_at, observed);

        // And it correlates to the planted token by containment.
        let mut correlator = OobCorrelator::new();
        correlator.plant(token.clone());
        let (matched, unmatched) = correlator.correlate_batch_contains(&[interaction]);
        assert_eq!(matched.len(), 1, "planted token must correlate");
        assert!(unmatched.is_empty());
        assert_eq!(matched[0].parameter, "q");
        assert_eq!(matched[0].interaction_type, InteractionType::Dns);
    }

    #[test]
    fn foreign_interaction_never_correlates() {
        let provider = InteractshProvider::new(Some("oast.example".into()), None).unwrap();
        // An interaction with no planted token anywhere in the identifier.
        let record = format!(
            r#"{{"protocol":"http","full-id":"stray.{}","unique-id":"{}","remote-address":"9.9.9.9","timestamp":""}}"#,
            provider.subdomain, provider.subdomain
        );
        let aes_key = [1u8; 32];
        let iv = [2u8; 16];
        let entry = server_encrypt(&aes_key, &iv, record.as_bytes());
        let pt = InteractshProvider::decrypt_entry(&aes_key, &entry).unwrap();
        let interaction = InteractshProvider::parse_interaction(&pt).unwrap();

        // A token we planted for a *different* injection is not in this name.
        let other = OobToken::mint("bt", "example.test", "/other", "id", "query", 300);
        let mut correlator = OobCorrelator::new();
        correlator.plant(other);
        let (matched, unmatched) = correlator.correlate_batch_contains(&[interaction]);
        assert!(matched.is_empty(), "stray traffic is never evidence");
        assert_eq!(unmatched.len(), 1);
    }
}
