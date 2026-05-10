//! OAuth 2.0 Token Exchange (RFC 8693) — bootstrap an OIDC identity
//! from a different credential type.
//!
//! Use case: an AITP agent already holds an mTLS client certificate
//! (or a JWT-bearer assertion from another IdP, or a SAML token from
//! a corporate gateway) and wants to obtain an OIDC ID/access token
//! to present in an AITP handshake's `identity` field. RFC 8693
//! defines the exchange: the agent posts the existing credential to
//! the IdP's token endpoint with
//! `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, and
//! the IdP returns a fresh OIDC token bound to the agent's AID.
//!
//! This module is a thin wrapper around `reqwest`: it builds the
//! request, posts it, and parses the response. The caller supplies
//! the IdP's token endpoint URL and the credential being exchanged.
//! There is no policy or caching layer — those belong in the
//! application that holds the credential.
//!
//! See [RFC 8693 §2.1] for the request grammar and §2.2 for the
//! response shape.
//!
//! [RFC 8693 §2.1]: https://www.rfc-editor.org/rfc/rfc8693#section-2.1

use serde::{Deserialize, Serialize};
use url::Url;

/// `grant_type` constant per RFC 8693 §2.1.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Subject token type for an OIDC ID token (RFC 8693 §3 token-type
/// identifiers).
pub const SUBJECT_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

/// Subject token type for a JWT bearer token.
pub const SUBJECT_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// Subject token type for a SAML 2.0 assertion.
pub const SUBJECT_TYPE_SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";

/// Requested token type for a fresh OIDC access token.
pub const REQUESTED_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Errors from a token-exchange call.
///
/// Marked `#[non_exhaustive]` so adding new variants — for client
/// authentication failures, malformed claims, etc. — is not a
/// breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenExchangeError {
    /// HTTP transport error (connect, timeout, TLS).
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    /// IdP returned a non-2xx status with an OAuth-shaped error body.
    #[error("token-exchange rejected: {error} ({description})")]
    OAuth {
        /// `error` field from the response body.
        error: String,
        /// `error_description` field, or `<none>` if absent.
        description: String,
    },
    /// IdP returned a non-2xx status with a body that doesn't parse
    /// as the OAuth error shape.
    #[error("HTTP {status}: {body}")]
    UnexpectedStatus {
        /// HTTP status code.
        status: u16,
        /// Raw response body (truncated to ~512 bytes for the error message).
        body: String,
    },
    /// 2xx response but the body isn't a valid token-exchange
    /// response (RFC 8693 §2.2).
    #[error("malformed response body: {0}")]
    MalformedResponse(String),
}

/// Subject credential being exchanged (RFC 8693 §2.1
/// `subject_token` + `subject_token_type`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubjectCredential {
    /// The opaque token to exchange (JWT, SAML assertion, etc.).
    pub token: String,
    /// IANA token-type URI describing `token`. Use one of the
    /// `SUBJECT_TYPE_*` constants for common cases.
    pub token_type: String,
}

/// Client authentication scheme per RFC 6749 §2.3 / RFC 7521.
///
/// RFC 8693 §2.1 says: "Client authentication is required by this
/// specification." The token-exchange request must therefore carry
/// proof of the client's identity in addition to the subject token
/// being exchanged. The four production-realistic schemes:
#[derive(Debug, Clone)]
pub enum ClientAuthentication {
    /// HTTP Basic auth (RFC 6749 §2.3.1). Base64-encoded
    /// `client_id:client_secret` in the `Authorization` header.
    /// Most common for confidential clients with a static secret.
    HttpBasic {
        /// OAuth client identifier.
        client_id: String,
        /// OAuth client secret.
        client_secret: String,
    },
    /// `client_id` + `client_secret` carried in the form body
    /// (RFC 6749 §2.3.1, "client_secret_post"). Equivalent to
    /// HttpBasic but in the body — some IdPs require it.
    ClientSecretPost {
        /// OAuth client identifier.
        client_id: String,
        /// OAuth client secret.
        client_secret: String,
    },
    /// JWT bearer client assertion (RFC 7523 §2.2). The client
    /// signs a short-lived JWT proving its identity. AITP agents
    /// typically use this with `client_assertion_type =
    /// urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
    /// The JWT MUST be minted and signed by the caller.
    ClientAssertion {
        /// OAuth client identifier.
        client_id: String,
        /// Type URI for the assertion. Use
        /// [`CLIENT_ASSERTION_TYPE_JWT_BEARER`] for the common case.
        client_assertion_type: String,
        /// The signed JWT.
        client_assertion: String,
    },
    /// No client authentication. Public clients only — most IdPs
    /// reject token-exchange from public clients, so use this only
    /// when the IdP is explicitly configured for it.
    None,
}

/// `client_assertion_type` URI for JWT bearer client auth
/// (RFC 7523 §2.2).
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Token-exchange request body (RFC 8693 §2.1).
///
/// Only the subset of fields that AITP-bootstrapped agents
/// realistically need is exposed; the IdP MAY accept additional
/// optional fields not modeled here.
#[derive(Debug, Clone)]
pub struct TokenExchangeRequest {
    /// IdP token endpoint, e.g. `https://idp.example.com/oauth/token`.
    pub endpoint: Url,
    /// The credential being exchanged.
    pub subject: SubjectCredential,
    /// Client authentication for this request. RFC 8693 §2.1 says
    /// client authentication is required; defaults to
    /// [`ClientAuthentication::None`] only because some IdPs
    /// permit public clients. Production callers should set one
    /// of the explicit variants.
    pub client_auth: ClientAuthentication,
    /// Optional actor token if the request is on behalf of another
    /// principal (RFC 8693 §2.1 `actor_token` / `actor_token_type`).
    pub actor: Option<SubjectCredential>,
    /// Requested token type (default: access_token).
    pub requested_token_type: Option<String>,
    /// Audience the requested token is intended for.
    pub audience: Option<String>,
    /// Resource URI the requested token grants access to.
    pub resource: Option<Url>,
    /// Space-separated scope string requested for the new token.
    pub scope: Option<String>,
}

impl TokenExchangeRequest {
    /// Construct a minimal request: endpoint + subject credential.
    /// Defaults to [`ClientAuthentication::None`] — set
    /// [`Self::client_auth`] before posting in production.
    pub fn new(endpoint: Url, subject: SubjectCredential) -> Self {
        Self {
            endpoint,
            subject,
            client_auth: ClientAuthentication::None,
            actor: None,
            requested_token_type: None,
            audience: None,
            resource: None,
            scope: None,
        }
    }

    /// Set the client authentication scheme. Convenience builder
    /// over the public `client_auth` field.
    pub fn with_client_auth(mut self, auth: ClientAuthentication) -> Self {
        self.client_auth = auth;
        self
    }

    /// Build the application/x-www-form-urlencoded body. Form
    /// values for `client_secret_post` and `client_assertion`
    /// auth land here; HttpBasic auth is added as a header in
    /// [`exchange_token`] instead.
    fn form_body(&self) -> Vec<(&'static str, String)> {
        let mut body: Vec<(&'static str, String)> = Vec::with_capacity(10);
        body.push(("grant_type", TOKEN_EXCHANGE_GRANT_TYPE.into()));
        body.push(("subject_token", self.subject.token.clone()));
        body.push(("subject_token_type", self.subject.token_type.clone()));
        match &self.client_auth {
            ClientAuthentication::ClientSecretPost {
                client_id,
                client_secret,
            } => {
                body.push(("client_id", client_id.clone()));
                body.push(("client_secret", client_secret.clone()));
            }
            ClientAuthentication::ClientAssertion {
                client_id,
                client_assertion_type,
                client_assertion,
            } => {
                body.push(("client_id", client_id.clone()));
                body.push(("client_assertion_type", client_assertion_type.clone()));
                body.push(("client_assertion", client_assertion.clone()));
            }
            ClientAuthentication::HttpBasic { .. } | ClientAuthentication::None => {}
        }
        if let Some(actor) = &self.actor {
            body.push(("actor_token", actor.token.clone()));
            body.push(("actor_token_type", actor.token_type.clone()));
        }
        if let Some(t) = &self.requested_token_type {
            body.push(("requested_token_type", t.clone()));
        }
        if let Some(a) = &self.audience {
            body.push(("audience", a.clone()));
        }
        if let Some(r) = &self.resource {
            body.push(("resource", r.to_string()));
        }
        if let Some(s) = &self.scope {
            body.push(("scope", s.clone()));
        }
        body
    }
}

/// Token-exchange response body (RFC 8693 §2.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenExchangeResponse {
    /// The newly minted token.
    pub access_token: String,
    /// Type of `access_token` (e.g. `urn:ietf:params:oauth:token-type:jwt`).
    pub issued_token_type: String,
    /// Token-presentation type (e.g. `Bearer` or `DPoP`).
    pub token_type: String,
    /// Lifetime of `access_token` in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// Granted scope (may differ from the requested scope).
    #[serde(default)]
    pub scope: Option<String>,
    /// Refresh token, if the IdP issued one.
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OauthError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Execute an RFC 8693 token-exchange against `request.endpoint`,
/// returning the new token on 2xx.
///
/// The caller supplies a configured `reqwest::Client` so that
/// transport-layer concerns (TLS pinning, timeouts, proxies) live
/// in the application, not this helper.
pub async fn exchange_token(
    client: &reqwest::Client,
    request: &TokenExchangeRequest,
) -> Result<TokenExchangeResponse, TokenExchangeError> {
    let body = request.form_body();
    let mut builder = client
        .post(request.endpoint.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&body);
    // HttpBasic is the only scheme that lives outside the form
    // body — RFC 6749 §2.3.1 puts it in the Authorization header.
    if let ClientAuthentication::HttpBasic {
        client_id,
        client_secret,
    } = &request.client_auth
    {
        builder = builder.basic_auth(client_id, Some(client_secret));
    }
    let resp = builder.send().await?;

    let status = resp.status();
    let bytes = resp.bytes().await?;

    if status.is_success() {
        return serde_json::from_slice::<TokenExchangeResponse>(&bytes)
            .map_err(|e| TokenExchangeError::MalformedResponse(e.to_string()));
    }

    if let Ok(e) = serde_json::from_slice::<OauthError>(&bytes) {
        return Err(TokenExchangeError::OAuth {
            error: e.error,
            description: e.error_description.unwrap_or_else(|| "<none>".into()),
        });
    }

    let body_string = String::from_utf8_lossy(&bytes);
    Err(TokenExchangeError::UnexpectedStatus {
        status: status.as_u16(),
        body: body_string.chars().take(512).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep() -> Url {
        Url::parse("https://idp.example.com/oauth/token").unwrap()
    }

    #[test]
    fn form_body_minimal() {
        let req = TokenExchangeRequest::new(
            ep(),
            SubjectCredential {
                token: "the-jwt".into(),
                token_type: SUBJECT_TYPE_JWT.into(),
            },
        );
        let body = req.form_body();
        // grant_type + subject_token + subject_token_type
        assert_eq!(body.len(), 3);
        assert_eq!(body[0].0, "grant_type");
        assert_eq!(body[0].1, TOKEN_EXCHANGE_GRANT_TYPE);
        assert_eq!(body[1].0, "subject_token");
        assert_eq!(body[1].1, "the-jwt");
        assert_eq!(body[2].0, "subject_token_type");
        assert_eq!(body[2].1, SUBJECT_TYPE_JWT);
    }

    #[test]
    fn form_body_full() {
        let mut req = TokenExchangeRequest::new(
            ep(),
            SubjectCredential {
                token: "saml-blob".into(),
                token_type: SUBJECT_TYPE_SAML2.into(),
            },
        );
        req.actor = Some(SubjectCredential {
            token: "actor-jwt".into(),
            token_type: SUBJECT_TYPE_JWT.into(),
        });
        req.requested_token_type = Some(REQUESTED_TYPE_ACCESS_TOKEN.into());
        req.audience = Some("aid:pubkey:peer".into());
        req.resource = Some(Url::parse("https://api.example.com/work").unwrap());
        req.scope = Some("read write".into());
        let body = req.form_body();
        let keys: Vec<&str> = body.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"actor_token"));
        assert!(keys.contains(&"actor_token_type"));
        assert!(keys.contains(&"requested_token_type"));
        assert!(keys.contains(&"audience"));
        assert!(keys.contains(&"resource"));
        assert!(keys.contains(&"scope"));
    }

    #[test]
    fn response_parses_minimal_2xx() {
        let body = br#"{"access_token":"new-jwt","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#;
        let r: TokenExchangeResponse = serde_json::from_slice(body).unwrap();
        assert_eq!(r.access_token, "new-jwt");
        assert_eq!(r.token_type, "Bearer");
        assert_eq!(r.expires_in, Some(3600));
    }

    #[test]
    fn response_parses_with_optional_fields() {
        let body = br#"{
            "access_token":"new-jwt",
            "issued_token_type":"urn:ietf:params:oauth:token-type:jwt",
            "token_type":"DPoP",
            "expires_in":600,
            "scope":"read",
            "refresh_token":"rt"
        }"#;
        let r: TokenExchangeResponse = serde_json::from_slice(body).unwrap();
        assert_eq!(r.token_type, "DPoP");
        assert_eq!(r.scope, Some("read".into()));
        assert_eq!(r.refresh_token, Some("rt".into()));
    }
}
