# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### BREAKING

- The workspace now publishes three crates: `aitp`, `aitp-experimental` and `aitp-cli`. The internal crates are modules of `aitp`, each with its whole former API: `aitp-core` is `aitp::core`, `aitp-crypto` is `aitp::crypto`, `aitp-envelope` is `aitp::envelope`, `aitp-manifest` is `aitp::manifest`, `aitp-handshake` is `aitp::handshake`, `aitp-tct` is `aitp::tct`, `aitp-delegation` is `aitp::delegation` and `aitp-transport-http` is `aitp::transport`. Replace `aitp_tct::X` with `aitp::tct::X`, and so on; there are no aliases. Their old crates get a final 0.23.1 that points to `aitp` and are not yanked.
- `aitp` gains the features of the crates it absorbed: `source-ip`, `client-spki-pinning`, `metrics` and `test-util` (`aitp::crypto::testing`). The transport features `client` and `server` are `http-client` and `http-server`. `pinned-admission`, `metrics` and `source-ip` are now stable (STABILITY.md); `client-spki-pinning`, `test-util` and the `experimental-*` features carry no promise.
- Session Trust Bundles move to the new crate `aitp-experimental`, which carries no promise: `aitp::session_bundle` is `aitp_experimental::session_bundle`, and `SessionBundleServer`, `MAX_BUNDLE_BYTES` and `SESSION_BUNDLE_PATH` move from `aitp::transport` to it, behind its own `http-server` feature. The `experimental-session-bundle` feature is gone. Without `http-server`, `aitp-experimental` pulls in no HTTP stack.
- `aitp-rs-adapter` is merged into the unpublished `aitp-conformance`: the library is `aitp_conformance::rs_adapter`, and `cargo build -p aitp-conformance` builds both binaries. The binary keeps its name.
- The bindings (`aitp-py`, `aitp-node`) depend on `aitp` with `default-features = false`, and on `aitp-experimental` for `session-bundle`.
- `aitp-handshake` (re-exported as `aitp::handshake`): `JwkPublicKey.alg` is now `Option<JwsAlgorithm>`. It holds the JWK's own `alg` member, which pins the key to that algorithm (RFC 7517 §4.4); `None` allows any algorithm that fits the key type (`JwsAlgorithm::fits`). `from_jwk_json` used to ignore the member. It now rejects an `alg` that does not fit the key type. `JwsAlgorithm` gains `ES384`, `ES512`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512`, and `JwkKeyMaterial` gains `P384` and `P521`. `JwsVerifyError::AlgMismatch` keeps only the `header` field.
- `aitp`: every public struct and enum of the stable surface is now `#[non_exhaustive]` or has a private field, except six listed with their reasons in `docs/api-classification.md`: `Timestamp` and `BlockingSigner` (newtypes), `NoPinnedKeys` (a unit value), and the decisions `HandshakeRevocationDecision`, `RevocationOutcome` and `KeyResolutionOutcome`, whose callers must handle each outcome. Newly `#[non_exhaustive]`: the enums `DelegationRevocation`, `EnvelopeParseError`, `FacadeError`, `FetchError`, `IdentityMode`, `JwkKeyMaterial`, `JwksFetcherError`, `JwsAlgorithm`, `KeyResolutionFailMode`, `PresentedIdentity`, `RevocationFailMode`, `RevocationSource` and `TrustMode`, and the structs `AitpEnvelope`, `Cnf`, `CompletedHandshake`, `DelegationClaims`, `GrantVoucherClaims`, `IdentityDescriptor`, `IdentityHint`, `InvalidTag`, `IssuedTct`, `JwkPublicKey`, `Manifest`, `ManifestEnvelope`, `ManifestPop`, `MutualCommitAckPayload`, `MutualCommitPayload`, `MutualHelloAckPayload`, `MutualHelloPayload`, `OidcVerifyContext`, `PinnedKeyVerifyContext`, `PopChallenge`, `PopResponse`, `RateLimitConfig`, `RevocationEntry`, `RevocationList`, `RevocationListEnvelope`, `RevocationPolicy`, `Sender`, `SessionContext`, `TctClaims`, `VerifiedDelegation`, `VerifiedTct` and `VerifyManifestContext`. A `match` on one of these enums outside `aitp` needs a wildcard arm. A struct can no longer be built with a literal; its public fields can still be read and set. Build it with its constructor instead:
  - `AitpEnvelope::unsigned(sender_aid, message_type, payload, message_id, timestamp)`, then sign it; `Sender::new`.
  - `IdentityHint::new(kind, subject)` with `with_issuer` and `with_public_key`; `ManifestEnvelope::new`, `ManifestPop::new`, `VerifyManifestContext::at(now)`.
  - `PopChallenge::new(tct_jti, nonce, expires_at)`; `RevocationList::new(issuer, published_at, expires_at, entries)`; `RevocationEntry::new(jti, revoked_at)` with `with_reason`.
  - `JwkPublicKey::new(key)` with `with_kid` and `with_alg`; `OidcVerifyContext::new`; `IdentityDescriptor::pinned_key` and `oidc`; `PinnedKeyVerifyContext::new` with `with_subject`.
  - `RateLimitConfig::default()` with `with_requests_per_source_per_60s`, `with_requests_per_aid_per_60s` and `with_trusted_proxies`; `RevocationPolicy::default()` with `with_fail_mode`, `with_max_staleness_secs` and `with_cache_ttl_secs`.
  - The other structs are outputs of `aitp` (verified claims, handshake results, decoded payloads) and have no constructor.
- `aitp` no longer has a type from a pre-1.0 crate in its stable surface. `HandshakeServer::router` and `ManifestServer::router`, which returned an axum 0.8 `Router`, are gone. Host a server with `serve(listener)`, which takes a `tokio::net::TcpListener`, or with `serve_with(listener, config, shutdown)`, which takes a `ServeConfig` (`with_request_body_limit`, default `DEFAULT_REQUEST_BODY_LIMIT`) and returns once `shutdown` completes and the requests in flight finish. `HandshakeServer::serve` also serves its Manifest at `/.well-known/aitp-manifest`, so there is no need to merge a `ManifestServer`. Both pass the peer address to the rate limiter, which a router served with `into_make_service()` did not. To mount a server next to your own routes, enable the new `experimental-axum` feature, which carries no promise, and call `into_router()`. `with_request_body_limit` and `with_request_body_limit_default` move behind that feature too.
- `aitp` drops its chrono dependency, and `Timestamp` loses `From<chrono::DateTime<Utc>>`: use `Timestamp(dt.timestamp())`.
- Multi-hop delegation (RFC-AITP-0011) moves to `aitp_experimental::delegation`, which carries no promise. `aitp::delegation` loses `DelegationClaims::{jti, chain, chain_hash}`, `DelegationBuilder::{extending, extending_async, jti}`, `compute_chain_hash`, `DEFAULT_MAX_DELEGATION_HOPS`, `HopRevocationCheck`, `VerifyDelegationContext::{max_delegation_hops, hop_revocation_check}` with their `with_*` setters, and `DelegationError::{HopLimitExceeded, ChainHashMismatch, Canonicalization, JtiNotV4}`. In `aitp_experimental::delegation` they are `ChainedDelegationClaims`, `ChainedDelegationBuilder`, `compute_chain_hash`, `DEFAULT_MAX_DELEGATION_HOPS`, `HopRevocationCheck`, `VerifyChainContext`, `verify_chained_delegation` and `ChainedDelegationError`, whose `Delegation` variant wraps a `DelegationError`. `VerifyChainContext::new` sets a hop budget of `DEFAULT_MAX_DELEGATION_HOPS`; `with_max_delegation_hops(0)` rejects chains as `aitp` does. `aitp::delegation::verify_delegation` now rejects a token carrying a `chain` claim with `DelegationError::MultihopNotSupported` (`DELEGATION_MULTIHOP_NOT_SUPPORTED`) ahead of every other claim check, and one carrying `jti` or `chain_hash` with `DelegationError::ClaimsMalformed` (`INVALID_ENVELOPE`). A malformed `jti` used to give `DELEGATION_INVALID_SIGNATURE`, and a stray `chain_hash` on a single-hop token was accepted. The bindings' `multihop-delegation` feature now depends on `aitp-experimental`.
- TCT renewal (RFC-AITP-0013) moves to `aitp_experimental::renewal`, which carries no promise, and the `aitp` feature `experimental-renewal` is gone. `aitp` loses the `tct` renewal items (`TctRenewalPayload`, `renewal_pop_input`, `RENEWAL_POP_DOMAIN_TAG`, `build_renewal_request`, `parse_renewal_request`, `process_renewal_request`, `RenewalContext`, `RenewalGrantPolicyFn`, `renewal_error_code`, the response and error payloads and envelopes, `RenewalResponseContext`, `RenewedTct`, `RenewalResponseError`, `verify_renewal_response`), `TctError::{RenewalNonceMalformed, RenewalReplayed, RenewalGrantsWithdrawn, RenewalNonceStore, RenewalRequestMalformed}`, `facade::{renew_tct, renew_tct_with_insecure_localhost, RenewedTct}`, `FacadeError::{Renewal, RenewalNotAdvertised, RenewalResponse}`, `transport::{RENEW_URI_EXT, renew_uri_from_manifest}` and `HandshakeServer::{with_renewal_nonce_store, with_renewal_grant_policy}`; `HandshakeServer` no longer mounts a renewal route. In `aitp_experimental::renewal` the items keep their names; the issuer errors are the new `RenewalError` (`RequestMalformed`, `NonceMalformed`, `Replayed`, `GrantsWithdrawn`, `NonceStore`, and `Tct` wrapping a `TctError`), with `error_code()` in place of `renewal_error_code` and `is_local_fault()`. `TctRenewalPayload` is `#[non_exhaustive]` with `TctRenewalPayload::new`.
  - The renewal endpoint is `RenewalServer::new(signer, manifest, revocation, nonce_store)` (feature `http-server`), which refuses a signer whose AID is not the Manifest's. The revocation producer is required. `router()` mounts the route at the Manifest's `renew_uri` path and returns `RenewalServerError::NotAdvertised` or `PathCollision` instead of skipping the route. Merge it with `HandshakeServer::into_router()` (`experimental-axum`) and serve with `into_make_service_with_connect_info::<SocketAddr>()`.
  - `RenewalServer` rate limits per source by default with `RateLimitConfig::default()`, on counters separate from the handshake server's; `without_rate_limit()` turns it off. With the rate limit on, a request without a client address gets a retryable error envelope with HTTP 500, where all such requests used to share one bucket.
  - The holder client is `renew_tct` / `renew_tct_with_insecure_localhost` (feature `http-client`), returning `RenewClientError::{NotAdvertised, Http, Request, Response}`.
  - The bindings' `renewal` feature and the example's `experimental-renewal` feature now depend on `aitp-experimental`.
- SPIFFE identity (RFC-AITP-0002 §6) moves to `aitp_experimental::spiffe` (feature `spiffe-identity`), which carries no promise, and the `aitp` feature `experimental-spiffe-identity` is gone, with `aitp`'s `rustls-webpki` dependency. `aitp::handshake` loses `identity_spiffe`, `SpiffeBundle`, `SpiffeBundleStore`, `SpiffeConfigError`, `SpiffeVerifyContext`, `verify_spiffe`, `spiffe_x509_proof_input`, `SPIFFE_X509_PROOF_DOMAIN`, `PeerConfig::spiffe_bundles` and `PeerConfig::with_spiffe_bundles`; in `aitp_experimental::spiffe` they keep their names. `IdentityKind::Spiffe` and `IdentityHintKind::Spiffe` stay in `aitp`.
  - New in `aitp::handshake`: the trait `IdentityVerifier` (`handles(kind)`, `verify(identity, ctx)`, implemented for `&T`, `Arc<T>` and `Box<T>`), the `#[non_exhaustive]` `IdentityVerifyContext` (`peer_manifest`, `sender_aid`, `receiver_aid`, `message_id`, `timestamp`, `pop_nonce`, `now`), `PeerConfig::identity_verifier` and `PeerConfig::with_identity_verifier`. `bootstrap_verify_peer` passes an identity of a kind other than `oidc` and `pinned_key` to the attached verifier when `handles` returns true, returns its error unchanged, and otherwise fails with `INCOMPATIBLE_IDENTITY_TYPE`. On success the peer key is the sender AID's key.
  - Attach SPIFFE with `PeerConfig::with_identity_verifier(&SpiffeVerifier::new(&bundles))`. A `spiffe` peer with no verifier attached is `INCOMPATIBLE_IDENTITY_TYPE`; with the old feature on and no bundle store it was `IDENTITY_FAILED`.
- `aitp::core::ErrorCode` holds the core registry codes only. It loses the Draft codes `DelegationHopLimitExceeded` and `DelegationChainHashMismatch` (RFC-AITP-0011), and `BundleInvalidSignature`, `BundleVersionMismatch`, `BundleExpired`, `BundleExpiryWindowInvariant`, `BundleCoordinatorIssuerMismatch`, `BundleAudienceMismatch`, `BundleEmptyParticipants`, `BundleParticipantTctInvalid`, `BundleNotMember` and `SessionBundleInvalid` (RFC-AITP-0010). Their wire strings no longer deserialize into `ErrorCode`.
- The published SDKs (`aitp-sdk` on PyPI, `@agentidentitytrustprotocol/aitp` on npm) no longer include TCT renewal, Session Trust Bundles or multi-hop delegation. The binding features are renamed `experimental-renewal`, `experimental-session-bundle` and `experimental-multihop-delegation`, are off by default, and are enabled together by `experimental`; the default features are `spki-pinning` only.
  - Python: `build_renewal_request`, `process_renewal_request`, `SessionBundleBuilder`, `verify_session_bundle` and `verify_delegation_multihop` leave `aitp.pyi`; their stubs are in `bindings/aitp-py/aitp_experimental.pyi`, which the wheel does not ship.
  - Node: `buildRenewalRequest`, `processRenewalRequest`, `SessionBundleBuilder`, `verifySessionBundle` and `verifyDelegationMultihop` leave `index.js` and `index.d.ts`. `npm run build:experimental` writes `experimental.js` and `experimental.d.ts`, which are not in the published package.
- The SDKs raise their runtime floors: `aitp-sdk` requires CPython 3.10 (`requires-python = ">=3.10"`, one `cp310-abi3` wheel per platform, built with pyo3's `abi3-py310`) and `@agentidentitytrustprotocol/aitp` requires Node.js 20 (`engines.node`). The floors and platforms are listed in STABILITY.md.
- `aitp` drops items that had no use outside the crate or duplicated another path:
  - `aitp::core::AitpError` is gone; each module returns its own error type.
  - `AitpVerifyingKey::to_bytes` is gone: use `try_to_ed25519_bytes` or `to_compressed`.
  - `aitp::transport::common` and its re-exports `aitp::transport::{sign_envelope, sign_envelope_with, sign_envelope_async, sign_envelope_with_async, verify_envelope_signature}` are gone: use the same functions in `aitp::envelope`.
  - `IdentityMode::Oidc { issuer, subject, proof_jwt }`, which took a JWT minted before the handshake nonce existed, is gone, and `IdentityMode::OidcWithMintCallback` is renamed `IdentityMode::Oidc { issuer, subject, mint }`. `IdentityMode` loses its lifetime parameter.
  - `HandshakeServer::enforce_rate_limit` and `RateLimitOutcome` are crate-private. The handshake routes apply the configured `RateLimitConfig`.
  - `IdentityPresentationContext` is crate-private.
  - `BoxError` and `BoxFuture` are defined once, as `aitp::core::{BoxError, BoxFuture}`; `aitp::crypto::signer::{BoxError, BoxFuture}` and `aitp::core::nonce_store::{BoxError, BoxFuture}` are gone.
  - The duplicate constants are gone: `aitp::transport::DEFAULT_TIMESTAMP_TOLERANCE_SECS` (use `aitp::core::DEFAULT_TIMESTAMP_TOLERANCE_SECS`), `aitp::transport::REVOCATION_LIST_URI_EXT` (use `aitp::manifest::REVOCATION_LIST_URI_EXT`) and `aitp::core::nonce_store::NONCES_OUTSTANDING_GAUGE` (use `aitp::handshake::admission::metrics_names::NONCES_OUTSTANDING`).
  - `AitpSigner::as_signing_key`, `AsyncAitpSigner::as_signing_key` and `DynAsyncAitpSigner::as_signing_key` take an argument that only `aitp` can construct, so a signer outside `aitp` cannot implement them. They are hidden from the docs. A backend that overrode `as_signing_key` drops the override and is signed through `sign`.
  - `aitp::core::{check_members, from_serde_error, reject_duplicate_keys, UnknownField}`, the `aitp::core::unknown_field` module, `aitp::crypto::jws::{peek_typ, jose_alg}`, `aitp::handshake::{bootstrap_verify_peer, apply_peer_policy}` and `aitp::transport::server::DEFAULT_MAX_BODY_BYTES` leave the public API. The workspace's own crates reach the ones they use through a `#[doc(hidden)]` module with no semver promise.
  - SPIFFE leaves the stable surface: `SvidType` and the `IdentityDescriptor` fields `svid_type` and `x5c` are no longer public, and `aitp_experimental::spiffe` reads them. A `spiffe` descriptor serializes to the same bytes as before. `scripts/check-stable-experimental.py` also fails on `svid` and `x5c`.
  - Seam migration:
    - `aitp::core::nonce_store::BoxFuture` and `aitp::crypto::signer::BoxFuture` → `aitp::core::BoxFuture`.
- `aitp`'s handshake future and the configuration it holds are `Send`, so `run_initiator_handshake` can run in a spawned task:
  - `JwksResolver` requires `Send + Sync`.
  - `OidcMintJwtFn` is `dyn Fn(&str) -> Result<String, OidcMintError> + Send + Sync`. The new `OidcMintError` wraps the callback's error (`OidcMintError::new(e)` takes any error or message), where the callback used to return `String`. `PresentedIdentity::OidcMinter` takes the new `LocalOidcMintJwtFn`, the same callback without `Send + Sync`, which a `Box<OidcMintJwtFn>` coerces into.
  - The TCT `RevocationCheckFn` and the delegation `SourceRevocationCheck` require `Send + Sync`.
  - `tests/send_sync_probe.rs` fails to compile if one of these, `PeerConfig`, `InitiatorConfig` or the `HandshakeServer::serve` future stops being `Send`.
- `PeerConfig` and `IdentityVerifyContext` are no longer `Copy`; clone them.
- Every public type of `aitp` implements `Debug`. Signing keys, nonces, caches and callbacks are not printed.
- `aitp` errors carry typed causes:
  - The envelope signers (`aitp::envelope::sign_envelope`, `sign_envelope_with`, `sign_prepared_envelope` and their `_async` forms) return the new `EnvelopeError` in place of `String`. It has `UnsupportedVersion`, `MessageId`, `Structure`, `SenderMismatch`, `Canonicalization` and `Signer` variants. `FacadeError::Envelope` wraps it, where a signing failure used to be `FacadeError::Http`.
  - `check_envelope_structure` and `check_unsigned_envelope_structure` return the new `EnvelopeStructureError` (`PayloadNotObject`, `NegativeTimestamp`, `SignatureFormat`). `parse_envelope_wire` reports it as the new `EnvelopeParseError::Structure`, where it used to be `Malformed`.
  - `Network` on `FetchError`, `JwksFetcherError` and `RevocationError`, and `Rng` on `HandshakeError`, `AdmissionError` and `ManifestError`, carry a `#[source] BoxError` in place of `String`. `"message".into()` still builds one.
  - `Canonicalization` on `HandshakeError`, `TctError` and `ManifestError` carries the `JcsError` as its `#[source]`.
- `IdentityVerifier::verify` returns `Result<VerifiedIdentity, IdentityVerifyError>`:
  - `VerifiedIdentity::new(kind, subject)` states what the proof established. The handshake fails with `IDENTITY_FAILED` unless the kind and subject equal the presented descriptor's.
  - `IdentityVerifyError::Rejected` reports `IDENTITY_FAILED`, and `IdentityVerifyError::KeyUnavailable` reports `KEY_RESOLUTION_FAILED`. The handshake wraps it as the new `HandshakeError::IdentityVerifier`.
- `GrantPolicyFn` is `dyn Fn(&GrantPolicyContext<'_>) -> Result<Vec<String>, GrantPolicyError>`. `GrantPolicyContext` carries the peer identity, the peer AID, `candidate_grants` (`peer_requested ∩ offered`) and the clock. A returned capability outside the candidates is dropped. An error is the new `HandshakeError::GrantPolicy` (`POLICY_VIOLATION`).
- Seam migration: none. `seam_surface.rs` is unchanged.
- `aitp` has one revocation model, in `aitp::tct::revocation`, used by TCT, attestation, delegation and handshake verification:
  - A lookup is a `RevocationCheckFn`: `dyn Fn(&RevocationQuery<'_>) -> Result<RevocationStatus, RevocationUnavailable> + Send + Sync`. `RevocationQuery` carries `issuer`, `jti` and `now`. `RevocationStatus` is `Clear`, `Revoked` or `SoftFailSafeSubset { safe_grants }`, and is exhaustive. `RevocationUnavailable::new` wraps the cause.
  - `RevocationSource` is `Check(&RevocationCheckFn)` or `FailOpen`, and moves from `aitp::handshake` to `aitp::tct`. `TctVerifyContextBuilder` and `AttestationVerifyContextBuilder` take `.revocation(source)` in place of `revocation_check` and `accept_unchecked_revocation_dangerous`; `TctVerifyContext::revocation_check` and `AttestationVerifyContext::revocation_check` are `revocation`. `VerifyDelegationContext::new` and `PeerConfig::new` take a `RevocationSource`.
  - `aitp::tct::RevocationCheckFn`, which took a `&Uuid` and returned `Result<bool, TctError>`, takes the query and returns the status. Gone: `aitp::handshake::{HandshakeRevocationDecision, RevocationCheckFn}`, `aitp::delegation::{DelegationRevocation, SourceRevocationCheck}`, `aitp::transport::{RevocationCache, RevocationOutcome, apply_safe_subset, revocation_list_uri_from_manifest}` and `aitp::transport::revocation::DEFAULT_REVOCATION_CACHE_TTL`. On the consumer side `RevocationFetcher::prepare` returns a `PreparedRevocation` whose `decide(&query)` answers a `RevocationCheckFn`, and the new `RevocationFetcher::with_provider` reads snapshots from a `RevocationProvider` in place of HTTP. `RevocationProvider::fetch` and `RevocationListProducer::current` return a `BoxFuture`, and `current` returns a `Result`; an error from the producer answers HTTP 503.
  - `VerifiedTct`, `VerifiedDelegation`, `CompletedHandshake` and `SessionContext` gain `effective_grants`: the grants narrowed to the safe subset under `SoftFailSafeSubset`, else all of them. An empty intersection is the new `TctError::SafeSubsetEmpty` and `DelegationError::SafeSubsetEmpty` (`POLICY_VIOLATION`). `TctError::RevocationUnavailable` and `DelegationError::RevocationUnavailable` carry a `RevocationUnavailable` in place of `String`.
  - `aitp_experimental`: `RenewalContext::new` takes a `RevocationSource`, and the renewed grants are narrowed by a soft-fail subset. `HopRevocationCheck` is a `RevocationCheckFn` queried with each hop's issuer and `jti`, and `VerifiedChainedDelegation` gains `effective_grants`. `RenewalServer` fails closed when its producer errors.
  - Seam migration:
    - `TctVerifyContext::builder()…accept_unchecked_revocation_dangerous()` and `AttestationVerifyContext::builder()…accept_unchecked_revocation_dangerous()` → `.revocation(aitp::tct::RevocationSource::FailOpen)` (two call sites).
- Key resolution does no blocking I/O. `JwksResolver` gains `prefetch(&issuer) -> BoxFuture<'_, ()>`, with a default that does nothing, and `resolve` answers from what is cached or pinned. `KeyResolutionPolicy` fetches over the network only in `prefetch`, which `HandshakeServer` and `run_initiator_handshake` await for the peer's OIDC issuer before each synchronous handshake step. `KeyResolutionPolicyBuilder::with_fetcher` takes only the `Arc<JwksFetcher>`, with no tokio `Handle`, and `aitp::transport::AsyncJwksResolver` with its `resolve_async` is gone. A caller driving the handshake state machine itself awaits `prefetch` first; an issuer that is neither cached nor pinned fails with the retryable `KEY_RESOLUTION_FAILED`. Concurrent misses for one issuer are no longer coalesced into one fetch.
  - Seam migration: none.
- `HostGuard::default()` is `GuardMode::DenyPrivate`, where it was `WarnPrivate`. `ManifestFetcher`, `JwksFetcher`, `RevocationFetcher`, `InitiatorConfig`, `HandshakeServer`'s revocation fetcher, `aitp-cli` and the experimental renewal client inherit it, so a peer, IdP or revocation list on a loopback, RFC 1918, CGNAT or IPv6 unique-local address is refused unless the caller opts in. `HostGuard::strict()`, now the same as the default, and `HostGuard::permissive()` are gone: pass `HostGuard::new(GuardMode::WarnPrivate)` (allowed with a warning) or `HostGuard::new(GuardMode::AllowAll)` to `with_host_guard`.
  - The new `HostGuard::allow_loopback_dangerous()` admits loopback addresses (`127.0.0.0/8`, `::1`) and only those, in every mode. The fetchers' and `InitiatorConfig`'s `with_insecure_localhost_dangerous()` apply it to the guard they use, for the Manifest fetch, the handshake endpoint and the revocation list, so a local demo on `http://localhost` needs that one opt-in. `aitp-cli --insecure-localhost` and `renew_tct_with_insecure_localhost` apply it too. The SDKs make no outbound fetches and are unchanged.
  - Seam migration: none.
- `ManifestFetcher`'s cache holds only verified Manifests. `verify_manifest` returns the new `aitp::manifest::VerifiedManifest` in place of `()`; it has `manifest()` and `into_manifest()`, and only `verify_manifest` builds one. `ManifestFetcher::maybe_replace_inline` takes a `VerifiedManifest`, and `ManifestFetcher::fetch` and `ManifestFetcher::cached` return one: call `into_manifest()` where a `Manifest` was used.
  - Seam migration: none.
- Options that switch off or relax a check end in `_dangerous` and take no argument (STABILITY.md states the rule): `ManifestFetcher::with_insecure_localhost(bool)`, `RevocationFetcher::with_insecure_localhost(bool)` and `InitiatorConfig::with_insecure_localhost(bool)` are `with_insecure_localhost_dangerous()`, and `HandshakeServer::without_rate_limit()` is `without_rate_limit_dangerous()`. The public field `InitiatorConfig::allow_insecure_localhost` is private; set it with `with_insecure_localhost_dangerous()`. `with_insecure_localhost(false)` was the default and has no replacement call. The CLI flag `--insecure-localhost` and the SDK names are unchanged.
  - Seam migration: none.
- Verification results are read-only. `VerifiedTct`, `VerifiedDelegation`, `VerifiedAttestation`, `VerifiedPinnedKey`, `CompletedHandshake`, `SessionContext` and `Admitted` have private fields, a read accessor named after each former field (`token()`, `claims()`, `effective_grants()`, `voucher()`, `statement()`, `algorithm()`, `key()`, `aid()`, `tct()`, `grant_voucher()`, `peer_aid()`, `peer_pubkey()`, `held_tct()`, `subject()`, `message_id()`), and `into_parts()`, which returns the owned pieces as the new `#[non_exhaustive]` `VerifiedTctParts`, `VerifiedDelegationParts`, `VerifiedAttestationParts`, `VerifiedPinnedKeyParts`, `CompletedHandshakeParts`, `SessionContextParts` or `AdmittedParts`. Only `aitp` constructs them. `grant_voucher()` returns `Option<&str>`; `algorithm()` and `message_id()` return the value.
  - Seam migration:
    - `verify_attestation(..).statement` → `.statement()` (now `&Value`).
    - `verify_pinned_key(..).aid` → `.aid()` (now `&Aid`).
- The data-carrying variants of the exhaustive decision enums are `#[non_exhaustive]`, so a field can be added to them later: `RevocationStatus::SoftFailSafeSubset`, `KeyResolutionOutcome::Resolved` and `KeyResolutionOutcome::SoftFailDegraded`. Match them as `SoftFailSafeSubset { safe_grants, .. }`, `Resolved(keys, ..)` and `SoftFailDegraded { safe_grants, .. }`. A `RevocationCheckFn` builds the soft-fail answer with the new `RevocationStatus::soft_fail_safe_subset(safe_grants)`. The enums stay exhaustive.
  - Seam migration: none.
- Rust names that hid a fixed algorithm say it. The renames are `aitp::crypto::compute_jwk_thumbprint` → `compute_jwk_thumbprint_ed25519_sha256`, `compute_jwk_thumbprint_p256` → `compute_jwk_thumbprint_p256_sha256`, `AitpVerifyingKey::to_jwk_thumbprint` → `to_jwk_thumbprint_sha256`, `AitpVerifyingKey::from_bytes` → `from_ed25519_bytes`, `aitp::core::jcs::canonicalize_and_hash` → `canonicalize_and_hash_sha256`, `ChallengeSource::tls_client_cert` → `tls_client_cert_sha256` and `TransportId::TlsClientCert` → `TlsClientCertSha256`. `AitpSigningKey::generate()` and `AitpSigningKey::from_seed()`, the Ed25519-only twins of `generate_ed25519()` and `from_ed25519_seed()`, are gone. Thumbprints, wire members, error codes and the conformance op names are unchanged.
  - Seam migration: none.
- Instants are `aitp::core::Timestamp` and durations are `std::time::Duration` across the stable API. `TctBuilder::ttl`, `DelegationBuilder::ttl` and `ManifestBuilder::ttl` replace `ttl_secs(i64)`; `TctVerifyContextBuilder::clock_skew` and `AttestationVerifyContextBuilder::clock_skew` replace `clock_skew_secs` (and the context fields are `clock_skew: Duration`); `PinnedAdmissionBuilder::timestamp_tolerance` replaces `timestamp_tolerance_secs`; `EmptyRevocationProvider::with_ttl` replaces `with_ttl_secs`; `RevocationPolicy` has `max_staleness` / `cache_ttl` with `with_max_staleness` / `with_cache_ttl`; `RevocationError::Stale` carries `max_staleness: Duration`; `OidcVerifyContext` has `iat_tolerance: Duration` and `now: Timestamp`. `Timestamp::plus_secs` is replaced by `saturating_add(Duration)` and `saturating_sub(Duration)`, and `is_within_tolerance_of` takes a `Duration`. The constants are `DEFAULT_TCT_TTL`, `DEFAULT_DELEGATION_TTL`, `DEFAULT_MANIFEST_TTL` and `aitp::core::DEFAULT_TIMESTAMP_TOLERANCE`, all `Duration`. Durations count whole seconds; a fraction of a second is dropped. The wire encoding of every timestamp is unchanged.
  - Seam migration: `.ttl_secs(3_600)` → `.ttl(std::time::Duration::from_secs(3_600))` in the golden TCT test.
- Each protocol constant has one definition. `aitp::core::nonce_store::NONCE_LEN` is the decoded `pop_nonce` length, and `aitp::handshake::POP_NONCE_LEN` is gone. The RFC-AITP-0009 §3.1 recommended rates are `aitp::handshake::RECOMMENDED_REQUESTS_PER_SOURCE_PER_60S` and `RECOMMENDED_REQUESTS_PER_AID_PER_60S`, available under every feature set; `RateLimitConfig::RECOMMENDED_PER_SOURCE`, `RateLimitConfig::RECOMMENDED_PER_AID`, `RecommendedLimiter::PER_TRANSPORT_PER_MINUTE` and `RecommendedLimiter::PER_LABEL_PER_MINUTE` are gone. The values and both defaults are unchanged.
  - Seam migration: none.
- Contexts and policies with several inputs of the same type are built with a builder. `OidcVerifyContext::builder()` and `PinnedKeyVerifyContext::builder()` set each input by name, and `build()` returns `aitp::core::MissingFieldError` naming the first required input that was not set; `OidcVerifyContext::new`, `PinnedKeyVerifyContext::new` and `PinnedKeyVerifyContext::with_subject` are gone (the builder's `subject` sets the binding). `RetryPolicy::builder()` starts from the `conservative()` values and replaces `RetryPolicy::custom`; an attempt count of 0 counts as 1, and a multiplier below 1.0 counts as 1.0. `HandshakeServer::new` takes the session TTL and replay window from `with_session_ttl(Duration)` and `with_replay_window(Duration)`, which replace the `with_session_ttl` and `with_session_ttl_and_replay_window` constructors. `OidcVerifyContext` and `PinnedKeyVerifyContext` implement `Debug`.
  - Seam migration: `PinnedKeyVerifyContext::new(sender.aid(), &receiver, &message_id, NOW, &pop_nonce).with_subject(SubjectBinding::SenderAid)` → `PinnedKeyVerifyContext::builder().sender_aid(sender.aid()).receiver_aid(&receiver).message_id(&message_id).timestamp(NOW).pop_nonce(&pop_nonce).subject(SubjectBinding::SenderAid).build().unwrap()`.
- Verification contexts are named `<Input>VerifyContext`: `VerifyDelegationContext` → `DelegationVerifyContext`, `VerifyManifestContext` → `ManifestVerifyContext` and `VerifyRevocationListContext` → `RevocationListVerifyContext`, alongside `TctVerifyContext`, `AttestationVerifyContext`, `OidcVerifyContext` and `PinnedKeyVerifyContext`. Builder setters take the bare name and setters on a finished value take `with_`: `KeyResolutionPolicyBuilder`'s `with_pinned_issuer_store`, `with_fetcher`, `with_cache_ttl`, `with_negative_cache_ttl` and `with_fail_mode` are `pinned_issuer_store`, `fetcher`, `cache_ttl`, `negative_cache_ttl` and `fail_mode`, and `TokenBucketLimiter::max_sources` is `with_max_sources`. In `aitp-experimental`, `VerifyChainContext` is `ChainVerifyContext` and `VerifySessionBundleContext` is `SessionBundleVerifyContext`.
  - Seam migration: none.
- Identity types and extension slots are typed. `ManifestBuilder::accept_identity_type` and `check_identity_type_compatibility` take `aitp::handshake::IdentityKind`, and `ManifestError::IncompatibleIdentityType` carries one; the Manifest's `accepted_identity_types` stays the wire strings. `TctClaims::ext`, `GrantVoucherClaims::ext` and `DelegationClaims::ext` are `Option<aitp::core::ExtensionsMap>`, and `TctBuilder::ext` takes `impl Into<ExtensionsMap>`. `ExtensionsMap` gains `contains_key`, `From<serde_json::Map<String, Value>>` and `FromIterator`. An absent slot and an empty one still encode differently, and unknown members still round-trip byte-identically through JCS. The Python and Node `accepted_identity_types` / `acceptedIdentityTypes` options raise an error on an entry that is not `oidc`, `pinned_key` or `spiffe`.
  - Seam migration: none.
- Each item of the stable surface has one public path, the root of its feature module (STABILITY.md, "Public paths"). The modules the items are written in are private, each module root lists its items by name, and there is no prelude. The namespace modules `aitp::core::{base64url, ids, jcs, nonce_store}`, `aitp::crypto::jws`, `aitp::crypto::testing`, `aitp::handshake::admission` (with `metrics_names`) and `aitp::handshake::identity_pinned` keep their paths. No item's name, signature or behaviour changes. The removed paths are:
  - `aitp::prelude::*` → the item's module (`aitp::core::Aid`, `aitp::crypto::AitpSigningKey`, `aitp::tct::TctBuilder`, …).
  - `aitp::core::{aid, envelope, error, extensions, raw_url, time}::*` → `aitp::core::*`.
  - `aitp::core::{NonceStore, InMemoryNonceStore}` and `aitp::handshake::admission::{NonceStore, InMemoryNonceStore, Nonce, IssuedNonce, ConsumeOutcome, NonceStoreError}` → `aitp::core::nonce_store::*`.
  - `aitp::crypto::{digest, error, keys, signer, thumbprint}::*` → `aitp::crypto::*`.
  - `aitp::delegation::{builder, error, types, verifier}::*` → `aitp::delegation::*`.
  - `aitp::manifest::{builder, error, resolver, types, verifier}::*` → `aitp::manifest::*`.
  - `aitp::tct::{builder, error, pop, revocation, types, verifier}::*` → `aitp::tct::*`.
  - `aitp::handshake::{error, identity, identity_oidc, identity_verifier, jwk, payloads, state_machine}::*` and every item of `aitp::handshake::identity_pinned` except `PINNED_KEY_PROOF_DOMAIN` → `aitp::handshake::*`.
  - `aitp::transport::{client, client_config, key_resolution, net_guard, replay_store, retry, revocation, revocation_fetch, server, server_limits, source_ip, tls_pinning}::*` → `aitp::transport::*`. `DEFAULT_MAX_JWKS_BYTES`, `DEFAULT_MAX_MANIFEST_BYTES`, `DEFAULT_OIDC_DISCOVERY_TTL`, `DEFAULT_NEGATIVE_CACHE_TTL`, `DEFAULT_BODY_READ_TIMEOUT`, `DEFAULT_MAX_SESSIONS`, `DEFAULT_REPLAY_WINDOW`, `DEFAULT_SESSION_SWEEP_INTERVAL`, `REVOCATION_LIST_BODY_LIMIT` and `EmptyRevocationProvider`, which were only in those modules, are now at `aitp::transport`.
  - Seam migration: none.

### Added

- The npm package exports `__napiBindingTarget` (`'native'` or the WASI flavor the loader resolved), generated by `@napi-rs/cli` 3.10. `scripts/binding-api.py runtime` does not expect `__`-prefixed loader names from the addon itself.
- `scripts/check-single-path.py` (`make single-path-check`, CI) fails if an item of `public-api.stable.txt`, alone or with an unstable feature's additions from `public-api.experimental.txt`, is reachable at more than one public path.
- `HandshakeServer::with_identity_verifier` attaches an `IdentityVerifier` (for example SPIFFE) to the server's handshakes, and `HandshakeServer::with_grant_policy` attaches a `GrantPolicyFn` that chooses the grants issued to each peer.
- `ErrorCode` has `as_str()`, `Display`, `FromStr` (error `UnknownErrorCode`) and `ErrorCode::ALL`. These give the registered wire string without a serde round trip.
- Both SDKs publish Linux musl binaries for x86_64 and aarch64: `musllinux_1_2` wheels for `aitp-sdk`, and the npm packages `@agentidentitytrustprotocol/aitp-linux-x64-musl` and `@agentidentitytrustprotocol/aitp-linux-arm64-musl`. Windows binaries are built on demand only.
- `bindings/aitp-py/api.txt` and `bindings/aitp-node/api.txt` snapshot the SDKs' declared API, one item per line with its signature, generated by `scripts/binding-api.py` from `aitp.pyi` and `index.d.ts`. CI fails when a snapshot is out of date (`make binding-api-check`; regenerate with `make binding-api`), and when a built default binding exports a name its snapshot does not list. This replaces `scripts/check-binding-surface.py` and `make binding-surface-check`. A pull request that touches a binding runs its release workflow as a dry run, building and smoke-testing every platform binary without publishing.
- `scripts/check-stable-deps.py` (`make stable-deps-check`, CI) fails if `public-api.stable.txt` names a type from a crate below 1.0.0 in `aitp`'s dependency graph.
- `scripts/check-stable-experimental.py` (`make stable-experimental-check`, CI) fails if `public-api.stable.txt` names TCT renewal, Session Trust Bundles, SPIFFE or multi-hop delegation, apart from the `spiffe` identity-type wire names.
- `scripts/check-binding-surface.py` (`make binding-surface-check`, CI) fails if `aitp.pyi`, `index.d.ts` or `index.js` declares an experimental symbol; its `runtime` mode checks the built default module in `bindings.yml` and in both release workflows before upload. New `aitp-py-experimental` and `aitp-node-experimental` jobs build `--features experimental` with `AITP_EXPECT_EXPERIMENTAL=1`, under which a missing experimental feature fails the tests instead of skipping them; the interop job builds with `AITP_BINDING_FEATURES=experimental`.
- `xcheck-ts` installs the TypeScript verifier's conformance adapter from npm (`@agentidentitytrustprotocol/verifier`, the exact version locked in `tests/xcheck-verifier-ts/`, bumped by Dependabot) instead of building it from a SHA checkout. The mint → verify step still uses the checkout pinned by `tests/AITP_VERIFIER_TS_VERSION`, because the package does not ship `scripts/xcheck-verify.mjs` (#384).
- `xcheck-go`, a required CI job: aitp-rs mints and [`aitp-verifier-go`](https://github.com/agentidentitytrustprotocol/aitp-verifier-go) verifies the same bytes, then both adapters run the fixtures and the reports must agree. The Go verifier is pinned by commit in `tests/AITP_VERIFIER_GO_VERSION`, and `bump-verifier-go.yml` opens the held bump PR. A new `notify-verifiers.yml` sends `aitp-released` to aitp-verifier-ts and aitp-verifier-go on each `aitp-v*` tag. The TypeScript verifier used to be told from the npm publish in `bindings-release.yml`, which a crates-only release never ran (#405).
- `docs/api-classification.md` classifies every public struct and enum of the stable surface as `non_exhaustive`, `private fields` or `exhaustive`, with a reason for each exhaustive one. `scripts/api-classification.py` generates the table from rustdoc JSON, and CI (`make api-classification-check`) fails on an unclassified type, a wrong class or an exhaustive type without a reason.
- `IdentityDescriptor::pinned_key` and `IdentityDescriptor::oidc` build an identity descriptor, and `PinnedKeyVerifyContext::new` with `with_subject` builds a pinned-key verification context, so an embedder no longer fills their fields by hand.
- A `feature matrix` CI job builds, lints and tests `aitp` and `aitp-experimental` with each feature on its own (`cargo hack --each-feature`). `scripts/check-dep-surface.sh` checks that `pinned-admission` alone pulls in no reqwest, axum, hyper or tokio `net`, and that `source-ip` and `aitp-experimental` without `http-server` pull in no axum, hyper or tokio. `tests/seam_surface.rs` exercises the embedded-admission seam through public paths, with a golden self-attestation token.
- Generating the stable API snapshot fails if a stable signature names an `aitp` type that no public path reaches.
- The public API snapshot now has signatures, and the semver gate sees breaks inside re-exported types. `crates/aitp/public-api.txt` is replaced by two snapshots that `scripts/public-api.py` writes. `public-api.stable.txt` covers the default features plus `http-client` and `http-server`, and expands every item the facade re-exports from an internal crate into its fields, variants, methods and impls, under its `aitp` path. `public-api.experimental.txt` lists what each `experimental-*` feature and `pinned-admission` adds. `semver.yml` now also generates the stable snapshot for the PR head and compares it with the base. It is blocking, and fails on a removed or changed line and on a field or variant added to a type without `#[non_exhaustive]`. cargo-semver-checks could not see a changed field type in a type re-exported from an internal crate.
- `bindings-release` also dispatches `aitp-released` to aitp-verifier-ts, whose `bump-aitp-rs` workflow moves its pin of the conformance runner to the new release. Until now it found a release only through a daily schedule.
- `deploy/interop-peer/deploy.sh` deploys the public interop peer to Railway. It has four modes: `--dry-run` (the default), `--apply [--ref R]`, `--previous` and `--rollback`, and each takes `--environment`. The peer key is piped from Doppler and never printed. While the custom domain lacks its CNAME or the `_railway-verify` TXT record, the script prints the missing record. The peer is live at `https://interop.agentidentitytrustprotocol.io`; see `docs/interop-peer.md`.
- Spec pin `ddec9f1`. The conformance runner and `aitp-rs-adapter` load the OIDC test-issuer keys from the spec's `known-answer/oidc-test-issuers.json` (`kat-oidc-issuer-001`, `kat-oidc-issuer-002-unknown`), vendored at the pin, instead of private seed constants. A test checks that each seed derives to its published public key, and another that the adapter resolves only the trusted key.
- The README has a hello world that CI executes (`readme-smoke.yml`). On every pull request it runs against a peer built from the checkout, as the required check `README hello world (local peer)`. A daily job runs it against the public peer, reports the time from `cargo install` to verified echo, and keeps one `readme-smoke` issue open while that job fails.
- Spec pin `3a78a8f`, which adds the RFC-AITP-0002 §6.3 "Key match" rule that the JWT-SVID fix below implements. No schema changes.
- A fuzz target, `svid_verify`, feeds arbitrary descriptors, JWT-SVIDs and X.509 leaf DER to `verify_spiffe` (`aitp_experimental::spiffe`). The target holds a bundle with a JWT-SVID key and an X.509 CA, so the input gets past the bundle lookup into the parsers.
- The `xcheck` job runs the conformance fixtures through `aitp-conformance` against `aitp-verifier-py`'s own adapter (`python -m aitp_verifier.adapter`), installed from PyPI at the exact version in `tests/xcheck-verifier-requirements.txt`, currently `aitp-verifier==0.1.2`, without `AITP_SPEC` set. It is the first non-Rust adapter through the runner. The job fails unless the verifier passes the `AITP v0.3` core claim and every fixture has the same outcome as under `aitp-rs-adapter`. A divergence can be listed as known until the verifier fixes it, and the entry fails the job once it agrees again; none are listed. Both reports are uploaded.
- Four fuzz targets for the parsers that face network input: `handshake_payload_decode` (the four Mutual Handshake payloads), `oidc_verify`, `session_bundle_verify` and `pinned_admission`. `scripts/fuzz-seed-corpus.py` seeds their corpora from the spec's conformance fixtures. The nightly `fuzz.yml` run now gives every target 5 minutes from those seeds, caps input at 64 KiB, and files a `fuzz-crash` issue on a crash. `fuzz/README.md` documents the targets.
- A new CI job, `xcheck-ts` (`cross-impl acceptance (aitp-verifier-ts)`), runs both cross-implementation checks against the TypeScript verifier: aitp-rs-minted artifacts verified by its `scripts/xcheck-verify.mjs`, and its adapter through `aitp-conformance`, gated like the Python verifier's (it passes the core claim and agrees with `aitp-rs-adapter` on every fixture). The verifier is unpublished, so it is built from the commit pinned in `tests/AITP_VERIFIER_TS_VERSION`, currently `aea3ab7`. `scripts/xcheck-compare-reports.py` takes `--verifier NAME` for its messages. The job is a required check on `main`, and `bump-verifier-ts.yml` opens a held PR each week when `aitp-verifier-ts` `main` moves past the pin, as `bump-verifier-py.yml` does for the Python verifier.
- Spec pin `8dc2a5c`, whose handshake fixtures `mh-002`–`mh-005`, `mh-007` and `mh-008` state the receiver's `self_aid`. No schema changes.
- `STABILITY.md` states the compatibility policy. The `aitp` facade follows semver, and while pre-1.0 a breaking change bumps the minor digit. MSRV bumps happen only in a minor release. The internal crates, the `experimental-*` features and `aitp-unstable` carry no promise. `cargo-semver-checks` now has its own workflow, `semver.yml`. On `aitp` it blocks and on the internal crates it is advisory. A `semver-break-approved` label lets an intentional break through, provided `[Unreleased]` has a `### BREAKING` entry.

### Changed

- `crates/aitp/public-api.stable.txt` now lists every impl except blanket impls: derived traits, `From` conversions and the auto traits (`Send`, `Sync`, `Unpin`, `UnwindSafe`, `RefUnwindSafe`). Losing one of them now fails the snapshot check and shows in `scripts/public-api.py breaks`, and `check-stable-deps.py` sees a pre-1.0 type behind a `From` impl.
- `STABILITY.md` states the 1.x policy, in sections Covered (the `aitp` stable surface and the npm and PyPI SDKs), Not covered, MSRV and Support window. From 1.0 a breaking change is a major release. A spec-aligning change an application can observe is a fix only when it closes a security hole; otherwise it waits for a major. The MSRV is at most N-2 and moves only in a minor. The latest minor gets bug and security fixes; the previous minor gets security fixes for 6 months. `SECURITY.md` matches.
- TCT renewal (no promise) follows RFC-AITP-0013 Draft at spec `6a21782`:
  - The holder's `pop_signature` is over `sha256("aitp-renewal-pop-v1\0" || iss || "\0" || jti || "\0" || nonce)`, with `iss` and `jti` from the current TCT and the 16 decoded nonce bytes (`aitp::tct::renewal_pop_input`). It was over `sha256(nonce)`.
  - The issuer runs, in order: parse (`parse_renewal_request`), `verify_tct` with `aud` equal to `sub`, the PoP, revocation, the replay guard, the grant re-evaluation and the mint. Revocation used to run before the PoP. A grant the policy hook returns outside its input is dropped.
  - The renewal route answers with a signed `tct` envelope whose payload is `{tct, grant_voucher, pop_nonce_echo}` (`renewal_response_envelope`), and refuses with a signed `error` envelope whose payload is `{code, reason, retryable}` (`renewal_error_envelope`). It used to answer with a plain `{tct, grant_voucher}` body and refuse with a `{"error": …}` body.
  - Codes (`renewal_error_code`): a malformed request or `pop_nonce`, including an unknown request member, is `POP_RESPONSE_INVALID`; a replayed nonce is `REPLAY_DETECTED`; no grant left is `POLICY_VIOLATION`; a TCT whose `aud` is not its `sub` is `TCT_SIGNATURE_INVALID`. `TctError` gains `RenewalRequestMalformed`.
  - `verify_renewal_response` runs the holder's checks (RFC-AITP-0013 §6.1) and returns a `RenewedTct` holding the `VerifiedTct`. `facade::renew_tct` runs it, so it returns a verified TCT, and an issuer refusal is `FacadeError::RenewalResponse(RenewalResponseError::Refused { code, .. })`.
  - The conformance adapter answers `renew_tct` and `verify_renewal_response`; the runner checks `renewed_tct_claims`, `renewed_jti_differs` and `response` against the envelope the adapter returns; the `conformance` CI job runs the `ren-*` fixtures with `--feature experimental-renewal`; `TCT_RENEWAL_NOT_SUPPORTED` no longer negates a fixture.
- The upgrade guides `docs/upgrading-0.14.md` to `docs/upgrading-0.19.md` and the stale `PROGRESS.md` are deleted. Older CHANGELOG entries link to the guides at the `aitp-v0.23.0` tag.
- `docs/conformance.md` and `adapters/README.md` link to the spec's [`schemas/conformance/ADAPTER.md`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/ADAPTER.md) for the adapter protocol instead of defining it, and correct what they said: request ids are `req-N`, the runner never reads `supported_features`, `OP_NOT_SUPPORTED` from a declared op is a SKIP, and a timeout fails the step without killing the adapter. The Python template reads `params["tct_token"]`, as the fixtures spell it, and the README's run command passes `--bin aitp-conformance`.

### Fixed

- The initiator now checks that MUTUAL_HELLO_ACK comes from the peer it addressed, and a different sender fails with the new code `PEER_MISMATCH` (`ErrorCode::PeerMismatch`, `HandshakeError::PeerMismatch`; RFC-AITP-0004 §5.2 step 3). It used to report `INVALID_ENVELOPE`. A Manifest whose AID is not the sender's is still `INVALID_ENVELOPE` (step 4). The conformance adapter applies the check when a fixture supplies `peer_aid` (`mh-015`), and the vendored spec pin moves to `af9c409`, which adds that fixture.
- A body limit set with `with_request_body_limit` now applies to the handshake routes. They read the raw body, which axum's `DefaultBodyLimit` does not reach, so they kept their fixed 256 KiB cap. An oversized handshake body is refused with `INVALID_ENVELOPE` (RFC-AITP-0009 §3.1).
- `TokenBucketLimiter` no longer panics when built with a `per_second` of 0, a negative rate or NaN. Such a rate is clamped to the smallest positive one, and a refusal's retry-after overflowed `Duration::from_secs_f64`. It now saturates at `Duration::MAX`. An infinite rate never refuses.
- The semver gate's `breaks` check read every line starting with `#` as a comment, including `#[non_exhaustive]` items, so removing a `#[non_exhaustive]` type was reported only through its members.
- `aitp serve --interop` now reads and discards the rest of an over-limit request body (up to 1 MiB) before it sends the 413. It used to answer over unread bytes and then close the socket, and the resulting TCP reset could destroy the 413 before the client read it (RFC 9112 §9.6). That also made the `oversized_bodies_get_413` test flaky ([#380](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/380)). A declared `Content-Length` over 1 MiB is still refused straight from the headers.
- The JWT-SVID verifier accepts all nine `alg` values RFC-AITP-0002 §6.3 lists: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384` and `PS512`. Before this fix, only `ES256` and `RS256` verified; the other seven passed the allow-list and then failed the signature check. `verify_jws_signature` now dispatches RSA PKCS#1 v1.5 and PSS and ES384 through `ring`, and ES512 through RustCrypto `p521`. OIDC ID tokens use the same verifier, so they also verify under these algorithms.
- `aitp-conformance` no longer sends `*_claims` minting companions to the implementation under test. Before this fix they survived in envelope payloads (`envelope.payload.tct_claims`) and session-bundle participants, so a strict verifier rejected `mh-006`..`mh-008`, `mh-success-001` and five `bundle-*` fixtures with `UNKNOWN_FIELD`. Every op request is now stripped at every depth before it is sent, and CI walks every request the whole pinned corpus produces to keep it that way.
- `aitp-manifest`: `verify_manifest` now verifies the proof of possession before the Manifest signature, in RFC-AITP-0003 §5 order (steps 4 and 5). A Manifest that fails both checks is now rejected with `MANIFEST_POP_FAILED`; before this fix it got `MANIFEST_SIGNATURE_INVALID`. The old order was only there because `mh-002`'s attacker PoP was never validly signed. The conformance runner now loads every KAT signing key from `known-answer/keypairs.json`, including `kat-keypair-006-attacker`, so mh-002's PoP verifies and the fixture reaches the signature check it targets.

## [0.23.0] — 2026-10-25

### BREAKING

- `aitp-transport-http`: `RevocationFailMode` has a new variant, `FailOpenIfUnadvertised`, so an exhaustive `match` on it must add an arm. With it, `RevocationFetcher` accepts a TCT whose issuer's verified Manifest advertises no `ListRevoked` URL, and logs each such acceptance at info. A list that is advertised but can't be fetched, verified or kept fresh still fails closed, and `RevocationCache` treats the mode as `FailClosed`. Use it only for TCTs that authorise nothing, such as the ones the interop peer receives from initiators and discards.

### Added

- `aitp serve --interop` (the CLI's `serve` feature) runs a public pinned-key AITP responder. It serves its Manifest, the handshake and its own empty revocation list. `/enroll/challenge` and `/enroll` register a key into `pinned_keys` (RFC-AITP-0002 §3.2) with a 24 h TTL, a 10k cap and per-IP token buckets, and grant only `aitp.interop.echo`. `/echo/challenge` and `/echo` check a presented TCT the way an issuer acting as resource server does (RFC-AITP-0005 §10.5). Each challenge is a signed `pop_challenge` bound to the token's `jti` and is consumed by any answer, and revocation is checked last. `--trusted-proxies` and `--client-ip-header` make the rate limits key on the real client behind an edge such as Railway's, which writes it into `X-Real-IP`. See `docs/interop-peer.md`. `deploy/interop-peer` holds the container image, and `scripts/interop-peer-smoke.sh` holds the smoke test.
- `aitp enroll <url>` registers the agent's key with an interop peer, and `aitp echo <url>` handshakes, then proves possession of the TCT and prints the verified claims. `enroll` creates a default key at `$XDG_CONFIG_HOME/aitp/agent.key` (else `~/.config/aitp/agent.key`). `echo` uses that key, as does `handshake` when `--key` is omitted.
- The `aitp` facade re-exports `parse_envelope_wire` and `CheckedJson`.
- A fuzz target, `interop_enroll`, covers the enrolment request parser.
- `aitp-cli` is published to crates.io (`cargo install aitp-cli`; the binary is `aitp`) and versioned in lockstep with the library crates. Each `aitp-cli-v*` GitHub Release carries prebuilt binaries for Linux x86_64 and arm64, macOS arm64 and x86_64, and Windows x86_64, each with a `.sha256`. CI installs the crate in a clean `rust:1.90-slim` container and runs `aitp --version`.
- `aitp handshake <url> (--key <file> | --ephemeral) [--grant <cap>]... [--offer <cap>]... [--peer-aid <aid>]` runs the Mutual Handshake as initiator over HTTP and prints the verified claims of the TCT the peer issues, as JSON on stdout. Without `--peer-aid` the peer's Manifest AID is trusted on first use, with a note on stderr. Revocation is `fail_closed` unless `--revocation-fail-open` is given. A failure exits 1 and starts its stderr line with the AITP error code when it has one, e.g. `aitp: error: IDENTITY_FAILED: …`. A peer's `IDENTITY_FAILED` against an `--ephemeral` key adds a hint to enrol a persistent key; a `POLICY_VIOLATION` adds a hint about `--grant` or `--offer`.
- `aitp manifest fetch <url>` fetches and verifies a peer's Manifest and prints the envelope, which pipes into `aitp manifest verify`.
- Both run behind the CLI's new `http-client` feature (on by default): rustls with `webpki-roots`, and `HTTPS_PROXY` / `NO_PROXY` honoured. `--no-default-features` builds the offline commands only. See `docs/cli.md`.

## [0.22.0] — 2026-10-25

### BREAKING

- `IdentityDescriptor` has two new public fields, `svid_type: Option<SvidType>` and `x5c: Option<Vec<String>>` (RFC-AITP-0002 §6.1). A struct literal must now set both, `None` for `oidc` and `pinned_key`. `bootstrap_verify_peer` rejects an `oidc` or `pinned_key` descriptor that carries either with `IDENTITY_FAILED`.

- RFC-AITP-0004 §5.1 step 8 (and §5.2) is enforced for every identity type, not just `spiffe`. The peer's `identity.type` must appear in the verifier's own `accepted_identity_types`, and an absent field means `["oidc"]`. A pinned-key agent whose Manifest omits `pinned_key` now rejects pinned-key peers with `INCOMPATIBLE_IDENTITY_TYPE`, so list it with `ManifestBuilder::accept_identity_type("pinned_key")`. The new `apply_peer_policy` runs the check, and `Initiator::on_hello_ack` and `Responder::on_hello` call it after `bootstrap_verify_peer` (the step 6 proof) and the envelope signature (step 7). In that frozen order a payload that fails both the proof and the type check reports `IDENTITY_FAILED` (`mh-014`). One exception: the OIDC trust-anchor check stays inside the proof, before any JWKS fetch, so an `oidc` peer from an untrusted issuer gets `INCOMPATIBLE_TRUST_ANCHORS` even if its type is also unaccepted. `ErrorCode::IncompatibleIdentityType` is new, and `aitp-transport-http` returns it instead of `IDENTITY_FAILED`. The conformance adapter's `issue_manifest` takes an optional `accepted_identity_types`. `verify_handshake_payload` honours `self_accepted_identity_types` and `self_trust_anchors`, and the runner supplies the default `["oidc"]` for `mh-*` fixtures that omit it.

### Added

- `HandshakeError::error_code()` returns the registered wire code for a handshake failure; `aitp-transport-http` now uses it. In both bindings a handshake state-machine failure in `build_hello`, `process_hello`, `process_hello_ack` or `process_commit` carries `.code`, e.g. `IDENTITY_FAILED` or `INCOMPATIBLE_IDENTITY_TYPE`, not only `TCT_REVOKED`.
- The Python and Node release workflows load each native wheel and addon right after building it, so a binary that builds but fails to dlopen never publishes. A local release build with Apple's Darwin 27 linker hits this ("mis-aligned LINKEDIT string pool"); the 0.21.0 wheels and addons built in CI load fine.
- Spec pin `314fe42`: core fixtures `mh-010` to `mh-014` (identity-type policy and its order after the proof) pass. When a fixture omits `self_trust_anchors`, the conformance adapter's handshake verifier now trusts only the runner-minted OIDC test issuer `https://auth.openai.com` (it used to add `auth.anthropic.com` and `idp.example.com`), and its synthesized Manifest lists the same anchors.
- `build_manifest` / `buildManifest` in both bindings take `accepted_identity_types` / `acceptedIdentityTypes`, the peer identity types the agent accepts (RFC-AITP-0004 §5.1 step 8). It defaults to the agent's own `identity_type`; `[]` accepts nothing. An agent that handshakes with a peer of a different type must list both, e.g. `["pinned_key", "oidc"]`.
- **Experimental SPIFFE identity (RFC-AITP-0002 §6), behind the `experimental-spiffe-identity` feature** of `aitp-handshake` (and of the `aitp` facade). `spiffe` is at registry status Proposed and OQ-7 is open, so the API can change in any release. New: `IdentityKind::Spiffe`, `IdentityHintKind::Spiffe` (`issuer` and `public_key` must be absent), `SvidType`, and the `identity_spiffe` module with `SpiffeBundleStore`, `verify_spiffe` and `spiffe_x509_proof_input`. `PeerConfig::with_spiffe_bundles` supplies the verifier's bundle store, keyed by trust domain; a duplicate or non-canonical trust domain is a configuration error.
  - The subject must be a canonical SPIFFE ID with a workload path. Its trust domain picks the one bundle used. The descriptor, trust domain, bundle and key-`use` checks all run before any signature is verified (§6.5).
  - A JWT-SVID must carry `kid`, which selects exactly one `jwt-svid` key. Its header may hold only `alg`, `kid` and `typ`. `EdDSA`, `none` and `HS*` are rejected; `ES256` and `RS256` are verifiable. It needs a single `aud` equal to the verifier's AID, an unexpired `exp`, `iat` within 300 s, `nonce` equal to `pop_nonce`, and `cnf.jkt` equal to the sender AID's thumbprint.
  - An X509-SVID chain is path-validated (RFC 5280, rustls-webpki) against that trust domain's `x509-svid` CAs only, with intermediates only from `x5c[1..]` and no revocation. The leaf needs exactly one URI SAN equal to the subject byte for byte, must not be a CA, needs `digitalSignature` without `keyCertSign` or `cRLSign`, and must have an Ed25519 or P-256 key. The §6.4.1 proof must verify under the leaf key.
  - Every failure is `IDENTITY_FAILED`. A verifier built without the feature rejects a `spiffe` peer with `INCOMPATIBLE_IDENTITY_TYPE` even when its Manifest lists `spiffe` (§6.6).
- The conformance adapter accepts `spiffe` and loads `trust_anchors_config.spiffe_bundles` when the runner enables `experimental-spiffe-identity`. The runner mints the SPIFFE test authorities, JWT-SVIDs, X509-SVID leaves and §6.4.1 proofs. Draft fixtures `id-024` to `id-030` pass, CI's opt-in conformance run enables the feature, and a test pins `kat-spiffe-x509-proof-001`.

- Spec pin `a37a767` (RFC-AITP-0005 §10.5, issuer as resource server). The conformance adapter has a new op, `verify_tct_as_issuer`. The issuer verifies a TCT it issued under its own key, with `aud` == `sub`. It takes the presenter AID only from a `pop_response` that answers an outstanding challenge for the token's `jti`, requires the envelope sender to be `sub`, and checks revocation last. Core fixtures `tct-026` to `tct-029` pass.

## [0.21.0] — 2026-10-25

### BREAKING

- Spec pin `0ad4bf2` renames the fixture key `required_for_v0_2` to `required_for_core`, with no alias. The runner reads only the new key, and the conformance report's results carry `required_for_core`. `aitp-conformance run --profile v0.2` is now `--profile core` (the default); `v0.2` is rejected, and `v0.1` is unchanged.

### Added

- Spec pin `9f9cdd9` (RFC-AITP-0014, A2A Agent Card security scheme). The six `a2a-*` fixtures are draft and need feature `aitp-a2a-agent-card`, which aitp-rs does not claim, so the runner skips them; there is no A2A binding yet. A test pins that the registered `rfc-aitp-0014.a2a_interfaces` Manifest extension key passes strict parsing and verification.

- `aitp-conformance run --report <PATH>` writes the spec's conformance report (`aitp-conformance-report.schema.json`, `report_version` "1"). It holds per-fixture results with `status`, `feature` and `required_for_core`, `totals`, the listing-based `fixtures_dir_digest` and a `gates[]` entry per RFC-AITP-0001 §10 claim. A core fixture skipped because a draft feature negates it blocks the `AITP v0.3` claim. `spec.commit` comes from `--spec-commit`, then a `SPEC_VERSION` file, then a clean spec checkout; it is never guessed. The adapter init reply may now carry `repository` and `commit`; `aitp-rs-adapter` sends `repository`. CI validates the report against the schema and the spec's `check-conformance-report.py`, and uploads it as the `conformance-report` artifact. (#302)

- **Downstream proof of possession in both bindings (RFC-AITP-0005 §6).** `AitpAgent.new_pop_challenge` / `newPopChallenge` issues a `pop_challenge` with a CSPRNG 128-bit nonce. `AitpAgent.sign_pop_response` / `signPopResponse` signs it with the holder's key. `verify_pop_response` / `verifyPopResponse` runs every §6.2 step and returns the proven holder AID. `verify_tct` and `verify_tct_cached` take `pop=(challenge, response)` (Node: `pop: { challenge, response }`), which verifies the TCT and the PoP response together and pins the audience to the TCT's `sub`. It excludes `expected_audience` and is now the documented presented-TCT path. Failures carry `.code` `POP_CHALLENGE_INVALID` (malformed or stale challenge) or `POP_RESPONSE_INVALID`. Nonce single use (RFC-AITP-0001 §5.5) stays with the caller. The `expected_audience` docs now say the presenter's AID must come from an authenticated source, never from the token's own `aud`. (agentidentitytrustprotocol#120)

### Fixed

- PoP failures now carry the RFC-AITP-0005 §6.2 code split. A stale challenge (`TctError::PopChallengeExpired`) or an unparseable challenge is `POP_CHALLENGE_INVALID`. A nonce, jti or signature failure, or an unparseable response, is `POP_RESPONSE_INVALID`. This applies in `aitp-rs-adapter` and in `aitp-transport-http`'s error mapping, which previously reported the non-signature PoP failures as `TCT_SIGNATURE_INVALID`.
- `aitp tct verify` without `--audience` now prints `audience taken from the token (not authenticated)`. The default is an inspection convenience, not an audience check.

## [0.20.0] — 2026-10-24

### BREAKING

- **0.20.0: fail-closed revocation, spec `v0.3.2-draft`, a curated
  facade, and no DPoP or token exchange.** Revocation is `fail_closed`
  by default in Rust and in both bindings, with `fail_open` as an
  explicit opt-out. The spec pin is `e78ee4b` and the schema namespace is
  `https://agentidentitytrustprotocol.io/schema/v0.3/`, a strict cutover
  of every schema `$id` with no `aitp.dev` alias. The `aitp` facade re-exports a curated
  surface that `crates/aitp/public-api.txt` freezes. DPoP and OAuth 2.0
  Token Exchange are removed. There are no aliases, deprecations or
  migration guide; each entry below says what changed and what to use
  instead. The bindings can now advertise a revocation list URI in the
  Manifest, which fail-closed verifiers need from every TCT issuer.

- **`aitp_handshake::PeerConfig` is `#[non_exhaustive]`** (RS1.1). A
  struct literal no longer compiles outside `aitp-handshake`. Build it
  with `PeerConfig::new(signing_key, manifest, jwks_resolver,
  pinned_key_store, revocation, now)` and set the optional parts with
  `.with_trust_anchors(..)` and `.with_grant_policy(..)` (the
  `revocation` argument is RS1.2, below). The fields stay public, so they can still
  be read and assigned, and the struct is now `Clone + Copy`, which
  replaces `..base` struct-update syntax. `aitp::facade::InitiatorConfig`
  was already `#[non_exhaustive]`. Doctests now pin both behaviours.
- **Revocation is `fail_closed` by default** (RS1.2, #290,
  RFC-AITP-0008 §3.1). A verifier that cannot determine a TCT's
  revocation status treats it as revoked. The wire code is `TCT_REVOKED`
  for a TCT and `DELEGATION_SOURCE_TCT_REVOKED` for a delegation, and
  the message says "revocation source unavailable" so the case stays
  distinguishable from a listed `jti`. `fail_open` is an explicit
  opt-out everywhere:
  - **`aitp-tct`.** `RevocationCheckFn` returns `Result<bool, TctError>`;
    a hook that cannot answer returns the new
    `TctError::RevocationUnavailable` (code `TCT_REVOKED`).
    `TctVerifyContext::now` and `TctVerifyContext::permissive_at` are
    removed: use `TctVerifyContext::builder(..)`, which requires
    `.revocation_check(..)` or `.accept_unchecked_revocation_dangerous()`.
  - **`aitp-handshake`.** `PeerConfig::new` takes a `RevocationSource`
    (`Check(&hook)` or `FailOpen`) before `now`, and
    `PeerConfig::with_revocation_check` is removed. `FailOpen` logs a
    warning once per process. `Initiator` and `Responder` gain
    `peer_aid()` and `peer_revocation_list_uri()` so a caller can fetch
    the peer's list before verifying its TCT.
  - **`aitp-delegation`.** `VerifyDelegationContext::new(verifier, now,
    revocation)` takes a `DelegationRevocation` (`Check(&hook)` or
    `FailOpen`), replacing `with_revocation_check`. The source hook
    (`SourceRevocationCheck`) and `HopRevocationCheck` return
    `Result<bool, DelegationError>`; the new
    `DelegationError::RevocationUnavailable` maps to
    `DELEGATION_SOURCE_TCT_REVOKED`. A multi-hop chain verified without a
    hop hook is rejected with `RevocationUnavailable` unless the context
    is `FailOpen`.
  - **`aitp-transport-http` / `aitp` facade.** `HandshakeServer` (at
    COMMIT) and `run_initiator_handshake` fetch the peer's advertised
    `ListRevoked` snapshot through the new `RevocationFetcher` and
    default to `RevocationFailMode::FailClosed`. Configure with
    `HandshakeServer::with_revocation_policy` /
    `with_revocation_fetcher` and `InitiatorConfig::with_revocation_policy`.
    The `server` feature now enables `client`.
  - **Bindings (Python and Node).** `verify_tct` / `verifyTct`,
    `verify_tct_cached` / `verifyTctCached`, `verify_delegation` /
    `verifyDelegation`, `verify_delegation_multihop` /
    `verifyDelegationMultihop`, and the session `complete` and
    `process_commit` / `processCommit` take `revoked_jtis` /
    `revokedJtis` and a `revocation` argument (`"fail_closed"`, the
    default, or `"fail_open"`; any other value throws). Without a list
    every call fails closed. A supplied list is always authoritative,
    even under `fail_open`, and `[]` means "nothing revoked": in Node an
    empty array no longer waives the check. Revocation failures carry
    `.code` / `code` `TCT_REVOKED` or `DELEGATION_SOURCE_TCT_REVOKED`.
  - **Downstream.** A peer that completes a handshake with a 0.20
    `HandshakeServer` or facade initiator must advertise a reachable
    `rfc-aitp-0008.revocation_list_uri` in its Manifest
    (`ManifestBuilder::revocation_list_uri(origin.join(REVOCATION_LIST_PATH)?)`;
    the server already serves the route), or the verifier must opt into
    `fail_open`. A pure client that serves no list is refused by a
    default server.
- **Spec pin `deee6a9` → `e78ee4b` (`v0.3.2-draft`); schema namespace
  is `https://agentidentitytrustprotocol.io/schema/v0.3/`** (RS1.3, #313).
  Every vendored schema's `$id` moves off `aitp.dev`, a strict cutover
  with no alias. The schema bodies are otherwise unchanged. A tool that
  resolves AITP schemas by `$id` must use the new namespace. The new
  core fixtures `tct-024` (no revocation source, default `fail_closed`),
  `tct-025` (explicit `fail_open`) and `rev-011` (a third-party-signed
  snapshot is discarded) pass. Totals: 86 pass / 25 skip strict and
  109 pass / 2 skip with all features, of 111.
- **The `aitp` facade re-exports a curated surface** (RS1.5, #293).
  `aitp::{core, crypto, tct, manifest, handshake, delegation, transport}`
  were whole-crate aliases (`pub use aitp_tct as tct`). They are now
  modules that name each item, frozen in `crates/aitp/public-api.txt`.
  The CI job `aitp public API snapshot` (`make public-api-check`) fails
  on any change that isn't regenerated with `make public-api`. Every root
  type, trait, builder, context, verify function, error and constant a
  consumer needs stays at the same path, e.g. `aitp::tct::verify_tct` and
  `aitp::transport::HandshakeServer`. `aitp::crypto::jws` and
  `aitp::core::base64url` stay as modules, `aitp::handshake::GrantPolicyFn`
  is new, and `aitp::core::{NonceStore, InMemoryNonceStore}` move up from
  `nonce_store`. Removed from `aitp` (use the internal crate if you must,
  without a stability promise):
  - Every internal-crate submodule path, e.g. `aitp::tct::verifier::*`,
    `aitp::handshake::state_machine::*`, `aitp::core::envelope::*`,
    `aitp::crypto::testing`, `aitp::transport::server::*`.
  - Wire-level helpers: the `*_MEMBERS` constants,
    `aitp::core::{envelope_signing_input, check_envelope_structure,
    check_unsigned_envelope_structure, parse_envelope_wire,
    ENVELOPE_SIGNING_DOMAIN_TAG, check_members, from_serde_error,
    reject_duplicate_keys, CheckedJson, CheckedJsonError, UnknownField}`,
    `aitp::tct::{parse_revocation_snapshot_wire, revocation_signing_bytes}`,
    `aitp::manifest::{parse_manifest_wire,
    check_identity_type_compatibility}`,
    `aitp::handshake::{bootstrap_verify_peer, pinned_key_proof_input,
    POP_NONCE_LEN}`, `aitp::delegation::compute_chain_hash` and
    `aitp::transport::apply_safe_subset`.
  - `aitp::transport::{SpkiHash, SpkiPinVerifier,
    build_pinning_client_config, compute_spki_hash}`: `aitp` has no
    `client-spki-pinning` feature, so these were only reachable by
    feature unification.

  `aitp::session_bundle` and `aitp::handshake::admission` stay whole and
  experimental. The internal crates' rustdoc now says "no stability
  promise; use `aitp`". The `facade_renewal` test now also requires
  `http-server`. No in-repo consumer (examples, `aitp-cli`, e2e-llm)
  needed a change. Downstream repos use the Python and Node bindings,
  not the Rust facade.
- **DPoP and OAuth 2.0 Token Exchange are removed** (RS1.4). No AITP RFC
  specifies either, and both were documented as unsupported (#151).
  `aitp_transport_http::dpop` and `aitp_transport_http::token_exchange`
  are gone, along with every root re-export: `verify_dpop_proof_full`,
  `DpopError`, `DpopHeader`, `DpopProof`, `DpopReplayCache`,
  `DpopVerifyContext`, `exchange_token`, `ClientAuthentication`,
  `SubjectCredential`, `TokenExchangeError`, `TokenExchangeRequest`,
  `TokenExchangeResponse` and the `CLIENT_ASSERTION_TYPE_JWT_BEARER`,
  `REQUESTED_TYPE_ACCESS_TOKEN`, `SUBJECT_TYPE_*` and
  `TOKEN_EXCHANGE_GRANT_TYPE` constants. `DpopPolicy`,
  `HandshakeServer::with_dpop_policy` and
  `HandshakeServer::verify_dpop_request` are removed too. There is no
  replacement; a future identity-provider bridge would start from an RFC.

### Added

- **Bindings can advertise a revocation list URI.** Python
  `AitpAgent.build_manifest(..., revocation_list_uri=None)` and Node
  `buildManifest({ ..., revocationListUri })` put
  `rfc-aitp-0008.revocation_list_uri` in the signed Manifest, as
  RFC-AITP-0005 §11 and RFC-AITP-0008 §1.4 require of every TCT issuer.
  Without it, a fail-closed verifier that discovers lists through the
  Manifest rejects every binding-built issuer with `TCT_REVOKED`. An
  invalid URL raises `ValueError` or throws. Both bindings also export
  `REVOCATION_LIST_PATH` (`/.well-known/aitp-revocation-list`), the path
  the Rust `HandshakeServer` serves. The Manifest still carries an
  explicit absolute URL.

## [0.19.0] — 2026-10-20

### BREAKING

- **0.19.0: binding UUID handling and the adapter's revocation snapshot
  rule.** Spec pin `299f89a` → `59407d2`
  ([#280](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/280)
  and this release's notes PR). The bindings sign only canonical UUID v4
  ids and normalize `revoked_jtis`, which fixes a Python revocation
  bypass (#272). The conformance adapter treats a discarded revocation
  snapshot as absent and applies `revocation_policy.mode` (#271). The Rust
  crates' API and the wire format are unchanged, so 0.19 interoperates
  with 0.18 peers. See [`docs/upgrading-0.19.md`](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/aitp-v0.23.0/docs/upgrading-0.19.md)
  for who is affected and how to migrate.
- **Bindings: wire-bound UUID inputs are strict, and `revoked_jtis`
  lookups normalize and fail closed**
  ([#272](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/272)).
  This finishes what #268 started for revocation `entries[].jti`. Python
  and Node behave identically, and both use `aitp_core::ids`. A binding
  user who passed non-canonical ids is affected; the Rust crates and the
  wire format are not. Under the pre-1.0 convention this bumps the minor
  version. Three things change:
  - **Strict.** Node `signEnvelope` `opts.messageId` / Python
    `sign_envelope(message_id=)`, and `SessionBundleBuilder.sessionId()` /
    `.session_id()`, parse with `aitp_core::ids::parse_v4`. Both values
    are signed, and the spec schemas require the lowercase hyphenated v4
    form. These calls used to accept uppercase, braced, `urn:uuid:` and
    unhyphenated input and sign it lowercased, so the signed id differed
    from the one the caller held. A bundle `session_id` of any UUID
    version was signed too, which the bundle schema rejects. Now any
    non-canonical form throws (Node) or raises `ValueError` (Python),
    with `message_id is not a lowercase UUID v4: …` or
    `session_id is not a lowercase UUID v4: …`. Pass `randomUUID()` /
    `str(uuid.uuid4())` output unchanged.
  - **Lenient, now in both bindings.** Each `revoked_jtis` / `revokedJtis`
    deny list (`verifyTct` / `verify_tct`, the `Cached` variants,
    `processRenewalRequest` / `process_renewal_request`,
    `verifyDelegation` / `verify_delegation` and their multihop variants)
    is a lookup key, so each entry is normalized: any RFC 9562 text form
    matches the canonical `jti`. Node and renewal already normalized.
    Python's TCT and delegation checks compared strings, so an uppercase
    or braced entry never matched and the TCT it named was **accepted**.
    That is fixed. The behaviour is now documented in the docstrings,
    `index.d.ts`, `aitp.pyi` and both READMEs.
  - **Fail closed on garbage.** A `revoked_jtis` entry that is not a UUID
    at all now throws / raises `ValueError`
    (`revoked_jtis entry is not a UUID: …`). Node's TCT and delegation
    checks used to drop it, and Python's never matched it, so a list made
    only of bad entries quietly turned the gate off. Renewal already
    refused such an entry.

### Fixed

- **The conformance adapter no longer ignores a revocation snapshot it
  cannot use**
  ([#271](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/271)).
  Before, a snapshot supplied to `verify_tct` or `verify_delegation_token`
  that failed signature, expiry or issuer verification was skipped, so the
  token verified as if nothing were revoked. The adapter now follows
  RFC-AITP-0008 §1.5 / §3.1 (0.3.1-draft): a snapshot discarded for any
  reason (structure, unknown member, version, signature, expiry, issuer,
  staleness) counts as absent, and `revocation_policy.mode` decides.
  - `verify_tct`: `fail_closed` (the default) rejects with `TCT_REVOKED`,
    `fail_open` accepts, and `soft_fail` narrows the grants to
    `safe_grants` (`POLICY_VIOLATION` when nothing is left; fails closed
    with no subset). A snapshot that does not parse used to report its own
    code (for example `UNKNOWN_FIELD`); it now follows the same rule. The
    snapshot is now checked against the TCT's issuer, not its own
    `issuer` field.
  - Multi-hop `verify_delegation_token` (RFC-AITP-0011 §6): a hop
    issuer's discarded snapshot makes that issuer's hops revoked
    (`DELEGATION_SOURCE_TCT_REVOKED`) unless the mode is `fail_open`.
  - The verifier's own deny list (RFC-AITP-0006 §4 step 7) is local state
    that the policy does not govern. A snapshot for it that fails
    verification is now an error with the snapshot's code
    (`REVOCATION_SNAPSHOT_SIGNATURE_INVALID` / `REVOCATION_SNAPSHOT_INVALID`
    / `UNKNOWN_FIELD`). Before, only a parse failure was.
  - A `revocation_snapshots[]` entry with no `issuer_aid`, a malformed
    one, or no `snapshot` is `INVALID_REQUEST`. Before, it was skipped.

  `verify_revocation_snapshot` still reports the snapshot's own code. The
  library paths needed no change: `aitp_transport_http::RevocationCache`
  already applies the fail mode to every snapshot failure. The adapter is
  not published, so this does not change any library API or behaviour.

## [0.18.0] — 2026-10-20

### BREAKING

- **0.18.0: revocation snapshot fixes.** Spec pin `597efbd` → `299f89a`
  ([#266](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/266),
  [#270](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/270)).
  An unknown snapshot version reports `REVOCATION_SNAPSHOT_INVALID`
  (#265), and revocation signing refuses a `jti` that is not a lowercase
  UUID v4 (#268). The wire format is unchanged, so 0.18 interoperates
  with 0.17 peers. See
  [`docs/upgrading-0.18.md`](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/aitp-v0.23.0/docs/upgrading-0.18.md) for who is affected
  and how to migrate.
- **A revocation snapshot with an unknown `version` now reports
  `REVOCATION_SNAPSHOT_INVALID`**
  ([#265](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/265)).
  Spec `VERSIONING.md` (`597efbd`) gives each artifact its own
  unknown-version code, and a snapshot's is `REVOCATION_SNAPSHOT_INVALID`.
  0.17.0 reported `UNKNOWN_VERSION`. Two places change:
  - The conformance adapter's `verify_revocation_snapshot` op reports
    `REVOCATION_SNAPSHOT_INVALID`.
  - `aitp_transport_http::RevocationCache` returns
    `RevocationError::Malformed`, the `REVOCATION_SNAPSHOT_INVALID` case.
    It used to return `RevocationError::SignatureInvalid(TctError::VersionUnknown)`.
    Under `FailClosed` the snapshot is still rejected; only the variant
    changes. A caller that matched the old variant must match `Malformed`.

  `version` is still checked before the signature, so a validly signed
  snapshot or session bundle whose `version` is changed afterwards
  reports the version code, not a signature failure. The spec's
  `rev-010-version-unknown` and `bundle-008-version-unknown` fixtures
  have that shape and both pass. New unit tests pin it too. The bindings' `verify_revocation_list`
  keeps its lowercase `version_unknown` cause code; the SDK docs now say
  it is the spec's `REVOCATION_SNAPSHOT_INVALID`. The table in
  `docs/upgrading-0.17.md` (removed in 0.20.0) section 1 is
  corrected.

- **Revocation signing refuses a non-v4 `entries[].jti`, and every
  deserialization of `RevocationEntry` takes the strict wire form**
  ([#268](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/268)).
  The verifier already rejected such a list, so 0.17.0 could sign
  snapshots nobody would accept. Four things change:
  - `aitp_tct::revocation_signing_bytes`, and through it
    `sign_revocation_list`, return `TctError::JtiNotV4` for an entry
    whose `jti` is not a UUID v4 with the RFC 9562 variant. This is the
    same check the delegation builder runs. `verify_revocation_list`
    goes through the same function, so an envelope built in code with
    a non-v4 `jti` is rejected too (`REVOCATION_SNAPSHOT_INVALID` in the
    adapter).
  - `RevocationEntry::jti` deserializes through
    `aitp_core::ids::serde_v4`. Plain `serde_json::from_*` of a
    `RevocationListEnvelope` now refuses an uppercase, braced, URN,
    simple or non-v4 `jti`, as `parse_revocation_snapshot_wire` already
    did. `parse_revocation_snapshot_wire` checks `jti` before the serde
    step, so it still reports `JtiNotV4`. The serialized form is
    unchanged, and so are the signing bytes.
  - Node `AitpAgent.signRevocationList` and Python
    `AitpAgent.sign_revocation_list` parse `jti` with the strict wire
    parser. They used to accept any UUID version and any case, and
    signed an uppercase input lowercased. That is why an uppercase
    `jti` appeared to verify through `verifyRevocationList`. Verify was
    already strict: an uppercase `jti` on the wire is `malformed`. Pass
    `randomUUID()` / `str(uuid.uuid4())` output unchanged.
  - The claim in [`docs/upgrading-0.15.md`](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/aitp-v0.23.0/docs/upgrading-0.15.md)
    section 2 that the revocation signing-bytes entry points apply the
    wire parser's `jti` check now holds for the Rust function as well.

### Changed

- **Spec pin `597efbd` → `4bbda67`** (spec #94), which adds the core
  fixture `rev-010-version-unknown` (`REVOCATION_SNAPSHOT_INVALID`) and
  the draft fixture `bundle-008-version-unknown`
  (`BUNDLE_VERSION_MISMATCH`, `experimental-session-bundle`). The vendored
  schemas and known-answer vectors are unchanged. Conformance at the pin:
  a strict run gives 80 pass / 0 fail / 24 skip of 104, and a run with
  all four features gives 102 pass / 0 fail / 2 skip (see
  [`docs/conformance.md`](docs/conformance.md)).
- **The cross-implementation acceptance job (`xcheck`) pins
  aitp-verifier-py at `e335348`** (its #66), up from `f335f4f`. That
  verifier rejects a negative envelope timestamp and a malformed
  signature as `INVALID_ENVELOPE`, and caps a session bundle's TCT
  expiry only when a coordinator Manifest is supplied. It also reports
  `REVOCATION_SNAPSHOT_INVALID` for an unknown snapshot version, which
  agrees with #265.
- **Spec pin `4bbda67` → `299f89a`**
  ([#270](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/270)),
  spec #95 and #96. They change only spec docs (`VERSIONING.md`, the
  media-type registry, the implementer quickstart) and are not
  normative. No schema, vector or fixture changes, so the conformance
  counts above still hold.

### Security

- **Lockfile bump for RUSTSEC-2026-0381 and RUSTSEC-2026-0382**
  ([#275](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/275)).
  `Cargo.lock` moves to `rustls-webpki` 0.103.16 and `webpki-roots`
  1.0.10. This changes only the lockfile, and a published crate does not
  ship its lockfile, so if you depend on the crates from crates.io, run
  `cargo update -p rustls-webpki -p webpki-roots` in your own project.

## [0.17.0] — 2026-10-20

### BREAKING

- **0.17.0: protocol revision `aitp/0.3`, with envelope signing input v2
  and a strict cutover from `aitp/0.2`.** Spec pin `ab214d2` → `bf00e75`
  ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/253),
  [#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254)).
  0.17 does not interoperate with 0.16 peers. It also ships the HTTP
  server receive order (#259), stricter envelope parsing (#262) and
  envelope signing and verification in the bindings (#260). See
  `docs/upgrading-0.17.md` (removed in 0.20.0) for every change and
  how to migrate.
- **Strict `aitp/0.2` → `aitp/0.3` cutover.** `aitp_core::PROTOCOL_VERSION`
  is `"aitp/0.3"`, and every producer and checker uses it. An `aitp/0.2`
  artifact is rejected on its version, with no dual-accept window:
  envelopes, TCTs, grant vouchers, delegation tokens and revocation
  snapshots with `UNKNOWN_VERSION`, Manifests with
  `MANIFEST_VERSION_UNKNOWN` and session bundles with
  `BUNDLE_VERSION_MISMATCH`.
- **Envelope signing input v2** (RFC-AITP-0001 §5.4). The envelope
  signature is over `sha256("aitp-envelope-v2" || 0x00 ||
  JCS(envelope minus signature))`. `version`, `message_type` and
  `extensions` are now sender-authenticated. The pipe-composed 0.16 input
  is gone, and an envelope signed over it fails with `INVALID_SIGNATURE`.
  `extensions` must be attached before signing.
- **`aitp_core::envelope_signing_input` and `envelope_signing_digest`
  take `&AitpEnvelope`** and ignore its `signature`. They used to take
  `(message_id, timestamp, sender_aid, payload)`.
- **`EnvelopeParseError::UnknownVersion(String)` is new.** An exhaustive
  `match` must add the arm.
- **Envelope check order** (RFC-AITP-0001 §5.4). `parse_envelope_wire`
  checks `version` (`UNKNOWN_VERSION`) before the member set
  (`UNKNOWN_FIELD`) and structure (`INVALID_ENVELOPE`). The caller then
  checks the signature (`INVALID_SIGNATURE`). An envelope with no
  `version`, `{}` included, is now `UNKNOWN_VERSION`, not
  `INVALID_ENVELOPE`. The Python and Node handshake entry points reject a
  non-`aitp/0.3` envelope with `unknown protocol version …`.
- **HTTP handshake server receive order** (RFC-AITP-0009 §3.1,
  [#255](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/255),
  [#259](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/259)).
  The hello and commit routes of `HandshakeServer` now check the replay
  deny list, the rate limit and the timestamp window before Content-Type
  and the envelope's version and structure. There is no API change. What
  changes is the response:
  - A replayed or stale envelope gets `REPLAY_DETECTED` /
    `TIMESTAMP_EXPIRED` even when it also has an unknown version, an
    unknown member, a bad structure or `message_type`, or the wrong
    Content-Type.
  - A `message_id`, `timestamp` or `sender.agent_id` that cannot be read
    (not a UUID, not an `i64` integer, not a valid AID) skips the step
    that needs it, and the structural check reports it.
  - Malformed requests now count against the rate limit, and are answered
    HTTP 429 with an empty body once the budget is spent.
  - A malformed envelope with a readable `message_id` consumes that id.
  - Deviation: the 256 KiB body-size limit is applied while the body is
    read, before the §3.1 steps 1 to 3, not at step 4.
- **The envelope parser enforces the schema rules for `payload`,
  `timestamp`, `signature` and `extensions`**
  ([#261](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/261),
  [#262](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/262)).
  `parse_envelope_wire` now rejects these as
  `EnvelopeParseError::Malformed` (`INVALID_ENVELOPE`), after the version
  and member-set checks:
  - a `payload` that is not a JSON object;
  - a negative `timestamp`;
  - a `signature` outside `^((ed25519|p256)\.)?[A-Za-z0-9_-]{86}$`,
    which used to be `INVALID_SIGNATURE`;
  - `"extensions": null`, which used to be read as absent.

  Every receive path changes, Python and Node `verify_envelope` included.
  On the HTTP server a negative `timestamp` is still `TIMESTAMP_EXPIRED`,
  because the timestamp window runs first.
- **The envelope signer refuses a non-object `payload` and a negative
  `timestamp`.** `sign_prepared_envelope*` and `sign_envelope*` return
  `Err`, and the binding `sign_envelope` / `signEnvelope` raise or throw.

### Added

- `aitp_envelope::sign_prepared_envelope` and
  `sign_prepared_envelope_async` sign an envelope the caller assembled,
  for example one with `extensions`. They refuse a `version` other than
  `PROTOCOL_VERSION`, a non-v4 `message_id`, a non-object `payload`, a
  negative `timestamp`, and a sender that is not the signer.
- `aitp_core::ENVELOPE_SIGNING_DOMAIN_TAG` (`b"aitp-envelope-v2"`).
- `aitp_core::check_envelope_structure` checks the `payload`, `timestamp`
  and `signature` schema rules on a typed envelope.
  `aitp_core::check_unsigned_envelope_structure` checks `payload` and
  `timestamp` only, for an envelope that is not signed yet (#262).
- **Envelope signing and verification in the Python and Node bindings**
  ([#256](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/256),
  [#260](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/260)).
  - **Verify:** Python `aitp.verify_envelope(envelope_json,
    expected_sender_aid)` raises `aitp.EnvelopeVerificationError`, a
    `RuntimeError` subclass, with `.code`. Node `verifyEnvelope` throws an
    `Error` with `.code`.
  - **Codes, in RFC-AITP-0001 §5.4 order:** `UNKNOWN_VERSION`,
    `UNKNOWN_FIELD` / `INVALID_ENVELOPE`, then `INVALID_SIGNATURE`. A
    sender other than the pinned AID is `INVALID_SIGNATURE`.
  - **Scope:** callers own the replay and timestamp checks; these
    functions do not run them.
  - **Sign:** Python `AitpAgent.sign_envelope(message_type, payload_json,
    extensions_json=None, message_id=None, timestamp=None)` and Node
    `agent.signEnvelope(messageType, payloadJson, opts?)` sign over input
    v2, `extensions` included. They refuse a non-object payload and a
    negative timestamp.
- The envelope KATs `kat-envelope-001-p256` (re-minted) and
  `kat-envelope-002-ed25519` (new, with `extensions`) are reproduced byte
  for byte, and their v1 signatures are asserted not to verify. Spec
  fixtures env-008 to env-011 pass, and env-007 now carries a real
  signature.

### Changed

- The spec pin moves to `bf00e75`, and `tests/schemas/` holds the full
  `schemas/` tree at that commit. Every signed vector and fixture was
  re-minted by the spec. The JSON Schema `$id` namespace is
  `https://aitp.dev/schema/v0.3/`.
- The aitp-verifier-py pin moves from `43cf702` to `f335f4f`, which
  speaks `aitp/0.3`. `tests/xcheck-fixtures/session-bundle/kat-keypair-001-bundle.json`
  is re-minted. The old bundle is kept as
  `kat-keypair-001-bundle-aitp-0.2.json`, and a test asserts that it is
  refused.
- The conformance runner's `--profile v0.2` and the fixture key
  `required_for_v0_2` keep their names. For `aitp/0.3` they mean the core
  tier. At `bf00e75` the strict run is 79 pass / 0 fail / 23 skip, and
  the all-features run is 100 pass / 0 fail / 2 skip.

### Security

- `version`, `message_type` and `extensions` can no longer be changed in
  transit without breaking the envelope signature. This closes the gap
  the v0.2 erratum in 0.16 documented.
- A relay can no longer add `"extensions": null` to an envelope without
  it being rejected (#262).
- The optional `ed25519.` / `p256.` tag is part of `signature`, which the
  signature does not cover. An Ed25519 signature verifies with or without
  `ed25519.`, so do not identify or deduplicate envelopes by their
  `signature` string. A P-256 signature without `p256.` fails.

## [0.16.0] — 2026-10-19

### BREAKING

- **0.16.0: single-hop delegation keys resolved from Manifests, and the
  coordinator Manifest required for session bundles in the bindings.**
  Spec pin `cfd2f16` → `ab214d2`. See
  [`docs/upgrading-0.16.md`](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/aitp-v0.23.0/docs/upgrading-0.16.md) for every change and
  how to migrate.
- **Single-hop delegation verifies under the issuer's Manifest key**
  (RFC-AITP-0006 §4 step 1,
  [#237](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/237),
  [#246](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/246)).
  `verify_delegation` needs the delegator's Manifest through
  `VerifyDelegationContext::with_issuer_manifests` for every token, not
  only for multi-hop chains. Without it the token fails with
  `DelegationError::KeyResolutionFailed` (`KEY_RESOLUTION_FAILED`).
  Python `verify_delegation(token, verifier_aid, issuer_manifests,
  revoked_jtis=None)` and Node `verifyDelegation(token, verifierAid,
  issuerManifests, revokedJtis?)` take the Manifests as a required third
  argument, so `revoked_jtis` / `revokedJtis` moves to fourth.
- **The bindings and the conformance adapter require the coordinator
  Manifest to verify a session bundle** (RFC-AITP-0010 §5 step 5,
  [#238](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/238),
  [#247](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/247)).
  Python `verify_session_bundle(bundle_json, verifier_aid,
  coordinator_manifest_json, now_unix_secs=None, revocation_check=None)`
  and Node `verifySessionBundle(bundleJson, verifierAid,
  coordinatorManifestJson, nowUnixSecs?, revocationCheck?)` take it as a
  required third argument. There is no AID-only fallback. Because a
  Manifest is now always supplied, its `expires_at` caps every
  participant TCT (RFC-AITP-0005 §10.4). Callers of the 0.15 no-Manifest
  path never hit that check. The adapter reports a missing Manifest, or
  one for another AID, as `KEY_RESOLUTION_FAILED`. The Rust API is
  unchanged, and `CoordinatorKeySource::UnverifiedAidDangerous` stays.

### Added

- Python `DelegationVerified.cnf_jkt`, the delegatee's `cnf.jkt`. Node
  already called it `cnfJkt`
  ([#240](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/240),
  [#244](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/244)).
- The new spec fixture `del-mh-005` passes, and `bundle-007` now runs and
  passes
  ([#246](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/246),
  [#247](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/247)).

### Changed

- The spec pin moves to `55bafe0`, whose delegation fixtures carry
  `input.issuer_manifests`
  ([#239](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/239),
  [#246](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/246)),
  and then to `ab214d2`
  ([#248](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/248)).
  `ab214d2` is a text-only v0.2 erratum to RFC-AITP-0001 §5.4. The
  `aitp/0.2` envelope signing input covers only `message_id`,
  `timestamp`, `sender.agent_id` and `payload`. Receivers MUST NOT treat
  `version`, `message_type` or `extensions` as sender-authenticated, and
  MUST NOT base a trust decision on envelope `extensions`. `aitp-rs`
  already complies, so no code changed.
- The conformance adapter no longer synthesizes stand-in Manifests for
  the delegation fixtures. The fixtures' `issuer_manifests` are its only
  source
  ([#239](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/239),
  [#246](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/246)).
- `SubprocessAdapter` turns a per-request `OP_NOT_SUPPORTED` into a SKIP,
  as `InProcessAdapter` already did. A skipped required fixture still
  fails the gate
  ([#246](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/246)).

### Deprecated

- Python `DelegationVerified.cnf`. It still returns the thumbprint but
  emits a `DeprecationWarning`. Use `cnf_jkt`
  ([#244](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/244)).

### Security

- Single-hop delegation tokens are verified under the key the issuer's
  verified Manifest designates. A delegator with no valid Manifest is
  rejected
  ([#246](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/246)).
- The bindings can no longer verify a session bundle without the
  coordinator's verified Manifest
  ([#247](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/247)).

## [0.15.0] — 2026-10-18

### BREAKING

- **0.15.0: checked wire JSON, ListRevoked by default, RFC-AITP-0009 §3.1
  handshake defaults, the RFC-AITP-0010 §5 session-bundle order,
  Manifest-resolved multi-hop keys, hardened renewal and a v0.2
  conformance gate.** Spec pin `db7d860` → `cfd2f16`. See
  [`docs/upgrading-0.15.md`](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/aitp-v0.23.0/docs/upgrading-0.15.md) for every change and
  how to migrate.
- **`parse_*_wire` and `PinnedAdmission::admit_wire` / `admit_wire_at`
  take `&CheckedJson`** instead of `&serde_json::Value`
  ([#146](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/146),
  [#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227)).
  The new `aitp_core::CheckedJson` is built from bytes or text
  (`CheckedJson::from_slice`, `FromStr`) and has already rejected
  duplicate keys (RFC-AITP-0001 §5.4.5), so every caller gets that
  check. This covers `parse_envelope_wire`, `parse_manifest_wire`,
  `parse_revocation_snapshot_wire` and `parse_session_bundle_wire`.
- **The bindings run peer JSON through the hardened wire parsers and
  report `unknown_field`**
  ([#152](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/152),
  [#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227)).
  `verifyManifestJson` / `verify_manifest_json` and
  `verifyRevocationList` / `verify_revocation_list` report a member
  outside the schema as `unknown_field`. It was `malformed`, or a
  `ValueError` in Python's Manifest path. The revocation entry points and
  the four handshake-envelope entry points now apply the wire parsers'
  member-set and UUID v4 checks.
- **Pinned admission answers a rate limit with 429 and a refusal with
  503** (spec `cfd2f16`, RFC-AITP-0002 §3.4,
  [#226](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/226),
  [#229](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/229)).
  A rate-limited `challenge()` returns `AdmissionError::RateLimited`,
  not `ChallengeRefused`. `RefusalCause::RateLimited` is removed.
  `http_status()` is `Some(503)` for `ChallengeRefused`, and the new
  `AdmissionError::retry_after()` and `http_body()` give the
  `Retry-After` value and the `{"error":"CHALLENGE_REFUSED"}` body.
- **`HandshakeServer::router()` always serves
  `GET /.well-known/aitp-revocation-list`** (spec `876e124`,
  [#225](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/225),
  [#230](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/230)).
  With no `RevocationListProducer` it serves an empty snapshot signed by
  the server key (RFC-AITP-0008 §1.5). RFC-AITP-0005 §11 requires
  advertising it: use the new `ManifestBuilder::revocation_list_uri`.
  `router()` warns when the Manifest lacks it. A handler you mounted at
  that path yourself now overlaps the built-in route.
- **Handshake defaults follow RFC-AITP-0009 §3.1 and RFC-AITP-0003 §4.1**
  ([#198](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/198),
  [#231](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/231)).
  `router()` starts the session sweeper (opt out with
  `without_session_sweeper()`), `DEFAULT_MAX_SESSIONS` is 1 000 (was
  10 000), and `ManifestFetcher` rejects `http://localhost` unless
  `.with_insecure_localhost(true)`. `InitiatorConfig` gains the same
  opt-in.
- **Bindings parity**
  ([#199](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/199),
  [#232](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/232)).
  Node `processRenewalRequest` and `issueTctForDelegatee` return
  `{ tct, grantVoucher }` instead of a string. Python
  `build_renewal_request(current_tct_envelope_json=…)` becomes
  `current_tct_token=…`, and `process_hello_ack(…, _session_id=…)`
  becomes `session_id=…`.
- **Session bundle verification follows RFC-AITP-0010 §5**
  ([#197](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/197),
  [#195](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/195),
  [#233](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/233)).
  `VerifySessionBundleContext` gains the required
  `coordinator_key: CoordinatorKeySource` (`Manifest(&m)` or
  `UnverifiedAidDangerous`). A supplied coordinator Manifest is verified,
  must match `bundle.coordinator`, and caps participant TCT expiry.
  `SessionBundleError` gains `CoordinatorManifest` and
  `CoordinatorManifestMismatch`. Self-membership is now checked last, so
  a forged bundle that omits the verifier reports
  `BUNDLE_INVALID_SIGNATURE`. `POST /aitp/session/bundle` rejects a bare
  body with `SESSION_BUNDLE_INVALID`.
- **Multi-hop delegation resolves each hop's key from the issuer's
  Manifest** (RFC-AITP-0011 §3,
  [#202](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/202),
  [#234](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/234)).
  Pass the Manifests with
  `VerifyDelegationContext::with_issuer_manifests`, or a chain fails with
  the new `DelegationError::KeyResolutionFailed` (`KEY_RESOLUTION_FAILED`).
  The Python and Node multi-hop verifiers take a required
  `issuer_manifests` / `issuerManifests` third argument.
- **TCT renewal is replay-guarded and re-evaluated** (RFC-AITP-0004 §8.1,
  [#196](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/196),
  [#235](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/235)).
  `process_renewal_request` is async and takes a `RenewalContext`. The
  `pop_nonce` must be 16 bytes and is single use. The presented TCT is
  checked for revocation and the Manifest expiry cap, and its grants are
  re-evaluated. `HandshakeServer` no longer mounts
  `/aitp/handshake/renew`; it mounts the route at the path of the
  Manifest's `rfc-aitp-0005.renew_uri` (`RENEW_URI_EXT`). Failures return
  specific codes instead of `TCT_SIGNATURE_INVALID`.
  `aitp::facade::renew_tct` takes the issuer Manifest, posts only to an
  advertised `https` `renew_uri`, and otherwise returns
  `FacadeError::RenewalNotAdvertised`. The Python and Node
  `process_renewal_request` need `build_manifest()` first and refuse
  replays.
- **`aitp-conformance run` gates on `required_for_v0_2` by default**
  ([#194](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/194),
  [#236](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/236)).
  A required fixture that fails or is skipped fails the run. Use
  `--profile v0.1` for the old gate.

### Added

- `aitp_core::CheckedJson` and `CheckedJsonError`
  ([#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227)).
- `aitp_manifest::ManifestBuilder::revocation_list_uri`,
  `aitp_transport_http::REVOCATION_LIST_PATH` and
  `RevocationCache::for_issuer_manifest`. `REVOCATION_LIST_URI_EXT` moves
  to `aitp_manifest` and is re-exported from `aitp_transport_http`
  ([#230](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/230)).
- `HandshakeServer::without_session_sweeper`,
  `HandshakeServer::with_session_sweep_interval` and
  `InitiatorConfig::with_insecure_localhost`
  ([#231](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/231)).
- `aitp_session_bundle::parse_session_bundle_envelope`,
  `advertise_bundle_uri` and `bundle_uri_from_manifest`, plus
  `SessionBundleServer::bundle_uri` and `SESSION_BUNDLE_PATH`
  (RFC-AITP-0010 §4.3.1). The Python and Node `verify_session_bundle`
  take an optional coordinator Manifest
  ([#233](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/233)).
- `aitp_manifest::ManifestResolver`, `resolve_verified_manifest` and
  `ManifestError::NotFound` (`MANIFEST_NOT_FOUND`)
  ([#234](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/234)).
- Renewal: `RenewalContext`, `RenewalGrantPolicyFn`, the `TctError`
  variants `RenewalNonceMalformed`, `RenewalReplayed`,
  `RenewalGrantsWithdrawn` and `RenewalNonceStore`,
  `HandshakeServer::with_renewal_nonce_store` and
  `with_renewal_grant_policy`, `RENEW_URI_EXT`, `renew_uri_from_manifest`
  and `aitp::facade::renew_tct_with_insecure_localhost`. `NonceStore`
  moves to `aitp_core::nonce_store` (still re-exported from
  `aitp_handshake::admission`), and `aitp-core` gains a `metrics` feature
  ([#235](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/235)).
- `aitp-conformance run --profile v0.1|v0.2`. Feature-negation
  exemptions are listed on stderr, and CI adds a strict conformance step
  with no `--feature` flags
  ([#236](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/236)).
- `bindings/aitp-py/tests/test_stub_signatures.py` checks every
  `aitp.pyi` signature against the compiled extension
  ([#232](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/232)).
- A weekly `bump-verifier-py` workflow opens a PR when
  `tests/AITP_VERIFIER_PY_VERSION` falls behind `aitp-verifier-py` `main`
  ([#149](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/149),
  [#228](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/228)).
- The new spec fixtures `id-023` and `tct-021` pass with no code change
  ([#229](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/229)).

### Changed

- The root `CHANGELOG.md` is split into one section per release
  ([#201](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/201),
  [#220](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/220)).
- `aitp-delegation` now depends on `aitp-manifest`
  ([#234](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/234)).
- `aitp.pyi` types `revoked_jtis` on the delegation verifiers as
  `set[str] | frozenset[str]`, and the `process_commit` docstring now
  gives the right direction
  ([#232](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/232)).

### Fixed

- Stale rustdoc and help text in `aitp-transport-http`, `aitp-delegation`
  and the conformance runner. A new `aitp-transport-http` README marks
  DPoP and token exchange as unsupported
  ([#200](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/200),
  [#151](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/151),
  [#219](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/219)).
- Node renewal and delegatee issuance no longer drop the grant voucher
  (RFC-AITP-0005 §8,
  [#232](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/232)).

### Security

- Every binding entry point that reads peer JSON now rejects duplicate
  keys and unknown members
  ([#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227)).
- A renewal request can no longer be replayed, renew a revoked TCT, or
  carry a withdrawn grant forward
  ([#235](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/235)).
- Multi-hop hops are verified under the key the issuer's Manifest
  designates, not the key encoded in the AID
  ([#234](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/234)).
- Plain-HTTP localhost Manifest fetches are off by default
  ([#231](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/231)).

## [0.14.0] — 2026-10-18

### BREAKING

- **0.14.0: P-256 signing input, required pinned-key trust store,
  pluggable signers, strict UUID v4 ids, self-attestations and
  pinned-key admission** (spec proposal
  [agentidentitytrustprotocol#72](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/pull/72),
  [#205](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/205)).
  P-256 JCS signatures made by 0.13 do not verify under 0.14, and the
  reverse. Every builder takes `&dyn AitpSigner`, `verify_pinned_key`
  takes a required `&dyn PinnedKeyStore`, and `jti`, `src_jti`,
  `message_id`, delegation hop `jti` and revocation `entries[].jti` must
  be lowercase UUID v4 (spec PR C, 35aeb84). The P-256 single-hash and strict-verification
  vectors and fixture tct-017 are vendored from spec PR A (b022013). The
  pinned-key P-256 and tagged-Ed25519 vectors and fixtures id-010 to id-018
  are vendored from spec PR B (652cdb9); the conformance runner now mints
  every negative placeholder as a real artifact and FAILs any fixture
  that uses a placeholder it cannot mint (spec #77). Third-party JOSE (IdP ID
  tokens, DPoP proofs) accepts high-S ES256; AITP artifacts stay low-S
  only (RFC-AITP-0001 §5.4.7 scope). `HandshakeServer` rate limiting is on by
  default, keyed on the transport source, and believes forwarding
  headers only from `RateLimitConfig::trusted_proxies` (RFC-AITP-0009
  §3.1, spec #73). For Seam (#205 A-1 to A-4), `NonceStoreError::AtCapacity`
  gains `retry_after`, and in-memory nonce expiry is amortised. Also new:
  the public `resolve_source_ip` and `TrustedProxy` (feature `source-ip`,
  which needs only `http` 1.x, not axum) and `TokenBucketLimiter::check_key_at`,
  and admission metrics behind `aitp-handshake/metrics`. Spec PR D
  (a2a24da) and PR E (35eb687, the KAT statement key
  `io.agentidentitytrustprotocol.kat`) are vendored, at pin db7d860 (spec #81, which closes #77 and is doc-only). Pinned-key admission follows the RFC-AITP-0002
  §3.4 check order: a `message_id` deny list (`MessageIdDenyList`,
  `REPLAY_DETECTED`) is checked first, then a per-source presentation
  rate limit that answers HTTP 429 with no AITP code. The presentation
  payload is exactly `{identity, pop_nonce}`. `admit` and the new
  `admit_wire` take the `&ChallengeSource`. The conformance adapter runs
  the `aitp-pinned-admission` and `aitp-self-attestation` fixtures (94
  fixtures: 92 pass and 2 skip with every feature; 74 pass and 20 skip
  strict), and `tests/proposal-kats` is gone: every vector comes from the
  vendored spec. See
  [`docs/upgrading-0.14.md`](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/aitp-v0.23.0/docs/upgrading-0.14.md) for every change and
  how to migrate.

## [0.13.2] — 2026-10-08

### Fixed

- **A malformed manifest `identity_hint` now reports `MANIFEST_INVALID`,
  not `IDENTITY_FAILED`** (issue
  [#179](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/179);
  the conformance adapter in
  [#184](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/184),
  the HTTP transport's `handshake_error_code` in
  [#185](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/185),
  released in 0.13.2). `ManifestError::IdentityHintMalformed` now maps to
  `MANIFEST_INVALID` in both places. This supersedes the
  `IdentityHintMalformed` → `IDENTITY_FAILED` mapping described in the
  #144 entry under "Fixed" below. `IncompatibleIdentityType` is unchanged
  (`IDENTITY_FAILED` in the HTTP transport, `INCOMPATIBLE_IDENTITY_TYPE` in
  the adapter).

## [0.13.1] — 2026-09-27

### Added

- **Committed manifest fixture now covered by cross-implementation
  acceptance**
  ([#148](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/148)).
  `scripts/xcheck-verify.py` already verified freshly-minted manifests
  through `aitp-verifier-py`'s real `verify_manifest` (issue #148's
  original, mostly-stale premise — that half already shipped via PR #141),
  but never the already-committed, spec-vendored reference fixture
  (`kat-keypair-001-manifest.json`). Two fresh mints agreeing with each
  other only proves the two implementations agree on *a* convention, not
  that either agrees with the spec's actual committed bytes — the same trap
  this script's own module docstring names as its reason for existing. The
  script now verifies the committed fixture through `aitp-verifier-py`,
  with a paired negative confirming its signature does not verify over the
  wrapped `{"manifest": ...}` form — both reuse `verify_manifest`'s own
  internal primitives, nothing is re-signed on either side. Also fully
  closes issue #150's CI path-filter defect (this fix's own coverage
  depended on it): `.github/workflows/ci.yml`'s `changes` job now
  triggers the `rust` output (and `xcheck`/`conformance`/`wasm`/
  `e2e-llm-build`) on `scripts/**` and `tools/**`, not just
  `crates/**`/`tests/**`. Issue #150's second, unrelated defect (Direction
  (b) printing `ok` unconditionally) remains open. Test/CI tooling only —
  no public API, no schema, no wire-behavior change.

- **Manifest signing now has a single, shared signing-view derivation, and
  a production-funnel regression test to prove it**
  ([#147](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/147)).
  `ManifestBuilder::build()` and `verify_manifest()` previously each
  hand-built their own `ManifestSigningView`, independently — a symmetric
  mistake at both call sites (e.g. both canonicalizing the wrapped
  `{"manifest": ...}` form instead of the inner body) would be
  self-consistent and pass `cargo test -p aitp-manifest` green but for one
  incidental failure unrelated to the wrapper convention itself, the same
  bug class already fixed for the revocation snapshot (PR #168) and still
  present in the session bundle. Both call sites now derive the
  view through a single `impl From<&Manifest> for ManifestSigningView`, so
  there is exactly one place that can get the derivation wrong, not two
  that could disagree. New tests in `signing_input_kat.rs` drive the
  committed, spec-vendored fixture through the real `parse_manifest_wire` +
  `verify_manifest` funnel (not a local re-canonicalization), plus a
  from-scratch wrapped-form-signature rejection test and a byte-pinned KAT
  test against the spec's `kat-manifest-001` vector. `ManifestSigningView`
  and its `From` impl are `pub(crate)` only — no public API or wire-behavior
  change.

## [0.13.0] — 2026-09-23

### BREAKING

- **`RevocationError` gains a `Malformed` variant and is now
  `#[non_exhaustive]`** (`aitp-transport-http`, released in 0.13.0,
  [#168](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/168)).
  A fetched revocation snapshot whose member set is intact but has a
  missing or mistyped required member (`aitp_tct::TctError::ClaimsMalformed`)
  now surfaces as `RevocationError::Malformed` — the
  `REVOCATION_SNAPSHOT_INVALID` case — instead of being folded into
  `RevocationError::SignatureInvalid` by `RevocationCache`. The conformance
  adapter reports `REVOCATION_SNAPSHOT_INVALID` for the same input.
  Downstream code that matches `RevocationError` exhaustively needs a
  wildcard arm. `RevocationProvider` implementations should map
  `ClaimsMalformed` to the new variant.

## [0.12.0] — 2026-09-20

### BREAKING

- **`cargo-semver-checks` reports four major findings from the
  `UNKNOWN_FIELD` work above**, all expected and absorbed by this
  already-breaking release: `constructible_struct_adds_field` on
  `AitpEnvelope` (new `extensions` field) and on `RevocationList` (new
  `extensions` field); the same finding on `Manifest`, plus a field-type
  change on `Manifest::extensions` from `ExtensionsMap` to
  `Option<ExtensionsMap>` (fixing a latent bug where a manifest's literal
  `"extensions":{}` was indistinguishable from an absent `extensions` key,
  which could silently change the reconstructed JCS signing input); and
  `enum_variant_added` on `SessionBundleError` (new `UnknownField` variant)
  — the one artifact error enum in this codebase that is not
  `#[non_exhaustive]`, so the addition is semver-major rather than
  transparent to matching callers. A fifth major finding, unrelated to
  the `UNKNOWN_FIELD` work, is disclosed separately under issue #144's
  `IdentityDescriptor.extensions` entry above.

### Added

- **A new `UNKNOWN_FIELD` error code, surfaced for every AITP artifact that
  reserves an `extensions`/`ext` namespace**
  ([#140](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/140),
  spec
  [agentidentitytrustprotocol/agentidentitytrustprotocol#41](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/pull/41)).
  RFC-AITP-0001 §7's forward-compatibility rule is deliberately asymmetric,
  and this release makes both halves of it hold everywhere the schema
  declares an `extensions`/`ext` slot: a top-level member that is **not**
  in the schema-declared member set — a sibling of `extensions`/`ext`, not
  a key inside it — is now rejected with `UNKNOWN_FIELD` naming the
  offending member (`UnknownField { field, object }`), replacing a bare
  `serde` deserialize failure that previously surfaced as a generic
  `INVALID_ENVELOPE`/`MALFORMED_REQUEST`-family code with no indication of
  which field or which object was at fault. A key found **inside**
  `extensions`/`ext`, at any nesting depth, is always ignored — never
  rejected, regardless of shape — because that namespace is the one place
  the spec asks implementations to tolerate content they don't understand.
  These two behaviors were previously inconsistent across artifacts: some
  over-rejected content inside `extensions` that should have been
  tolerated, others under-rejected a stray top-level member that should
  have been a hard failure. Every artifact's member-set check is now
  anchored directly to `tests/schemas/*.schema.json` rather than a
  hand-maintained list, so a future spec revision that adds a member
  cannot silently start rejecting it here.

  Three groups of types gain a new `extensions` slot they did not
  previously have, closing the gap between what the vendored JSON schemas
  already declared and what these Rust types accepted: the envelope
  (`AitpEnvelope`), the revocation snapshot (`RevocationList`), and all
  four Mutual Handshake payloads (`MutualHelloPayload`,
  `MutualHelloAckPayload`, `MutualCommitPayload`, `MutualCommitAckPayload`).
  **No existing signing input moved, and nothing needs re-signing.** Every
  one of these new fields is `Option<ExtensionsMap>` with
  `#[serde(default, skip_serializing_if = "Option::is_none")]`, so an
  artifact that never sets the field serializes to exactly the same bytes
  as before this change — the new member is opt-in on the wire, not a
  default-populated one.

  Two spec notes worth recording so they aren't rediscovered: RFC-AITP-0001
  §5.1's prose says the envelope's `extensions` is "covered by the
  envelope signature like any other member", but §5.4's actual envelope
  signing input is the fixed four-tuple
  `message_id|timestamp|sender.agent_id|hex(sha256(JCS(payload)))`, which
  never canonicalizes `extensions` at all — this implementation follows
  the signing-input definition, not the prose, and the discrepancy has
  been raised upstream rather than "fixed" here toward stale text. And
  this release was pinned to spec commit `5063c08`, under which
  `IdentityDescriptor` (nested inside a handshake payload) had no
  `extensions` slot of its own even though the canonical identity schema
  already declared one — the entry below, bumping the pin to `ea22c71`,
  resolves that disagreement and closes the gap described here.

  Versioning note: this is a minor-*class*, patch-*position* change per
  the spec's own pre-1.0 mapping — the affected RFCs move `0.2.x` →
  `0.2.x+1`, the protocol literal stays `aitp/0.2`, and the schema
  namespace stays `https://aitp.dev/schema/v0.2/`. No `aitp-rs` crate
  version is bumped by this entry; that is release-plz's job at release
  time, computed from the `!`/`BREAKING CHANGE` footers below.

- **Three new `ErrorCode` variants distinguish a structural
  (non-cryptographic) rejection from a cryptographic one, for the two
  JCS-profile artifacts that previously had no dedicated code for it**
  ([#144](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/144),
  spec
  [agentidentitytrustprotocol/agentidentitytrustprotocol#42](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/pull/42),
  bumping the vendored spec pin `5063c08` → `ea22c71`). A manifest that
  fails to parse at all (missing required member, wrong type — an
  unknown top-level member is the distinct `UNKNOWN_FIELD` case from the
  entry above) now reports the new `MANIFEST_INVALID`; a revocation
  snapshot with the same class of defect reports the new
  `REVOCATION_SNAPSHOT_INVALID`; a revocation snapshot whose signature
  specifically fails reports the new `REVOCATION_SNAPSHOT_SIGNATURE_INVALID`.
  What each replaces differs by call site, since the two crates in this
  repo that map these errors to wire codes, the published
  `crates/aitp-transport-http` and the unpublished conformance harness's
  `aitp-rs-adapter`, previously disagreed with each other: the HTTP
  transport collapsed every manifest defect into the signature-family
  `MANIFEST_SIGNATURE_INVALID` (see the `### Fixed` entry below), while
  the adapter mapped a malformed manifest to the generic
  `INVALID_ENVELOPE` and a malformed revocation snapshot to the generic
  `INVALID_ENVELOPE` as well — `REVOCATION_SNAPSHOT_SIGNATURE_INVALID`
  is the one variant that uniformly replaces a genuine signature-family
  code (`TCT_SIGNATURE_INVALID`) on every call site, since a revocation
  snapshot's own signature check was previously sharing a mapper with
  the TCT it lists. TCT, grant-voucher, and delegation artifacts are
  deliberately **unchanged** — the registry keeps them on their existing
  signature-family codes, since those artifacts are JWS-profile, not
  JCS-profile, and the spec's structural-rejection carve-out is
  JCS-specific. Note that both `REVOCATION_SNAPSHOT_*` codes are, today,
  reachable only through the unpublished conformance adapter — no
  published crate's own error type currently has a call site that
  produces them as a typed `ErrorCode` (a deliberate scope decision, not
  an oversight: see the plan's Open Question 3 at
  `plans/manifest-revocation-error-codes.md` for the pre-existing,
  separate gap this surfaced but does not fix).

  `IdentityDescriptor` (the identity proof nested inside the
  `mutual_hello` / `mutual_hello_ack` handshake payloads) also gains the
  `extensions` slot the canonical identity schema already declared but
  the handshake schema's own copy of the descriptor was missing —
  closing the gap called out as an open item in the `UNKNOWN_FIELD`
  entry above. A `mutual_hello`/`mutual_hello_ack` payload whose
  `identity.extensions` carries an unrecognized key now verifies and
  succeeds (`id-009`), matching every other artifact's `extensions`
  namespace behavior; a member outside the namespace on the identity
  descriptor itself continues to fail (`id-008`, unchanged). **This is a
  breaking change to `aitp-handshake`'s public API** (major version bump
  on next release): `IdentityDescriptor` has neither `#[non_exhaustive]`
  nor `Default`, so every existing struct-literal construction of it —
  in a custom identity-verification caller, a test fixture — needs the
  new `extensions` field added (every in-repo call site was updated as
  part of this change). `cargo-semver-checks` flags exactly this one
  finding (`constructible_struct_adds_field`) for this change, distinct
  from the four `aitp-handshake`/`aitp-core` findings the
  `cargo-semver-checks` entry further down this section discloses for
  the separate `UNKNOWN_FIELD` work.

- **Conformance harness gains a real OIDC test-issuer key** (issue #144).
  `aitp-rs-adapter`'s `verify_handshake_payload_op` previously used a
  `NoOpResolver` that never returned any JWKS key, so no fixture using
  the `__VALID_JWT__` placeholder could ever reach a successful OIDC
  verification — `id-009` (the identity descriptor's `extensions`
  accept-side fixture) needs exactly that to exercise the `extensions`
  fix above end-to-end. The adapter now resolves a real, fixed test key
  for the one issuer the corpus uses (`https://auth.openai.com`), and
  the conformance harness mints a genuinely verifiable JWT for it. This
  is a conformance-test-harness fix, not a change to `aitp-handshake`'s
  public library behavior — `verify_oidc` itself is untouched.

### Fixed

- **The HTTP transport's `handshake_error_code` no longer collapses
  every `ManifestError` variant into `MANIFEST_SIGNATURE_INVALID`**
  ([#144](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/144)).
  `crates/aitp-transport-http/src/server.rs`'s error-code mapper
  previously mapped every `HandshakeError::Manifest(_)` variant to the
  same signature-failure code via a single wildcard arm; it now matches
  each variant individually, mirroring the pre-existing `HandshakeError::Tct`
  arm right above it. This is a behavior change for real deployed
  traffic, not only the conformance fixture corpus: the manifest this
  code path actually verifies has already passed structural parsing by
  the time it reaches here (`bootstrap_verify_peer` calls `verify_manifest`,
  the signature/expiry path, not the wire-parsing path), so the classes
  a live HTTP handshake can actually surface through it are `Expired` →
  `MANIFEST_EXPIRED`, `PopFailed` → `MANIFEST_POP_FAILED`,
  `VersionUnknown` → `MANIFEST_VERSION_UNKNOWN`, and
  `IdentityHintMalformed` → `IDENTITY_FAILED` — each now its own correct
  code instead of a misleading signature failure. `UnknownField`,
  `Malformed` (→ the new `MANIFEST_INVALID`), and `IncompatibleIdentityType`
  (→ `IDENTITY_FAILED`, the closest registered code — `ErrorCode` has no
  dedicated variant for it, a separate pre-existing registry gap) are
  also mapped correctly for completeness and for any future caller of
  this same match, but aren't reachable through this exact call path
  today. Any downstream consumer pattern-matching on the literal string
  `MANIFEST_SIGNATURE_INVALID` (rather than treating it as "manifest
  verification failed, see message") will see it far less often
  post-upgrade. `HandshakeError::GrantOverflow` — previously falling
  through to the generic `INVALID_ENVELOPE` catch-all — now also
  reports its own dedicated `GRANT_OVERFLOW` code.

- **Duplicate top-level JSON keys are rejected again on every wire-parsing
  path this release touches** (RFC-AITP-0001 §5.4.5), closing a regression
  introduced by the `UNKNOWN_FIELD` work above rather than a pre-existing
  gap. Checking a member set ahead of a typed deserialize requires first
  parsing into an untyped `serde_json::Value` — but `Value`'s object
  representation is last-write-wins on a repeated key, so by the time a
  `Value` exists, the automatic duplicate-field rejection every
  `serde`-derived struct normally provides (independent of
  `deny_unknown_fields`) is already gone, at every nesting level. This
  silently affected the envelope, manifest, revocation snapshot, session
  bundle, handshake payload, and TCT/voucher/delegation claim parsing paths
  wherever this release routed them through a member-set check, and
  reached the live HTTP server and client facade — not just the
  conformance adapter — before being caught. Fixed with a new
  `aitp_core::reject_duplicate_keys`, which detects a repeated key
  anywhere in a JSON document (every nesting level, including inside
  arrays) directly from raw bytes, via `serde`'s own
  `Deserializer`/`Visitor`/`DeserializeSeed` traits, without ever
  constructing a `Value`; every affected entry point now calls it against
  the original bytes before any `Value` is built. No conformance fixture
  exercises a duplicate key, so this was undetected by the corpus; a new
  regression test exists per affected artifact, including a live HTTP
  test.

## [0.11.0] — 2026-08-30

### BREAKING

- **Pinned-key proof `timestamp` is now encoded as ASCII-decimal, not
  8-byte big-endian binary** (RFC-AITP-0002 §3.1 erratum, spec issue #17).
  `identity_pinned::pinned_key_proof_input` (used by both
  `sign_pinned_key_proof` and `verify_pinned_key`) previously packed the
  envelope `timestamp` field into the proof-input bytes as a signed
  8-byte big-endian integer. Per the §3.1 erratum, it MUST instead be the
  timestamp's base-10 ASCII-decimal string (e.g. `1711900000` → UTF-8
  bytes `"1711900000"`), matching how `message_id` is already
  string-encoded in the same construction. This is a wire-visible change:
  **a pinned-key proof minted by aitp-rs at the old encoding will not
  verify against the fixed version, and vice versa.** The fix is now
  machine-checked against the spec's `kat-pinned-key-proof-001` KAT
  vector. It also brings `aitp-rs` in line with the reference Python
  implementation, `aitp-verifier-py`, which has always used the
  ASCII-decimal form — this closes a previously-existing, undetected
  interop gap between the two implementations rather than introducing a
  new incompatibility with a pairing that previously worked. The gap went
  undetected by this repo's own conformance suite because the only
  fixture exercising this code path (`id-007`) is rejected earlier, at
  the trust-store gate (RFC-AITP-0002 §3.2 step 1), before the signature
  is ever checked.

### Changed

- **`bindings/aitp-node` migrates `napi` / `napi-derive` `2.16` → `3.x`**
  (`@napi-rs/cli` `^2.18.0` → `^3.8.6`). `compat-mode`, which napi-derive 3
  no longer defaults on, retired the four types this binding used
  (`JsFunction`, `JsUnknown`, `JsString`, `JsBoolean`); the hand-rolled
  `JsFnRef` Drop guard in `src/helpers.rs` is deleted outright in favor of
  napi 3's own `FunctionRef<Args, Return>`, a Drop-safe typed function
  reference. `oidcMintJwt` and `revocationCheck` callback parameters move
  from `Option<JsFunction>` to `Option<FunctionRef<String, String>>` /
  `Option<FunctionRef<String, bool>>`; `JwksProvider`'s `unknown`-typed
  constructor/`upsert` arguments move to napi 3's `Unknown<'_>`, and
  JSON-stringifying them now goes through napi 3's `JSON::stringify`
  helper instead of a hand-rolled `JSON.stringify` JS round-trip. No
  runtime behavior change for correctly-typed callers.

  The generated `index.d.ts` narrows the `oidcMintJwt` and
  `revocationCheck` callback types from `(...args: any[]) => any` to
  `(arg: string) => string` and `(arg: string) => boolean` respectively —
  a real (if minor) type-level improvement for consumers with strict
  TypeScript checking. `keys?: unknown` on `JwksProvider` is unchanged.

  CI: `.github/workflows/bindings-release.yml` renames three
  `@napi-rs/cli` v3 CLI invocations (`napi create-npm-dir -t .` →
  `napi create-npm-dirs`, `napi artifacts --dir` → `--output-dir`,
  `napi prepublish --skip-gh-release` → `--no-gh-release`) and bumps
  `node-version` from `'20'` to `'22'` to match the CLI's own devDependency
  floor. `.github/workflows/bindings.yml`'s generated-file freshness gate
  now also covers `index.js`, which napi 3's CLI bakes
  `package.json`'s version into (guarded by
  `NAPI_RS_ENFORCE_VERSION_CHECK`) and which ships to npm verbatim
  alongside `index.d.ts`. The published package's `engines.node` floor is
  unchanged (`>=16`) — the CLI's own Node ≥20.17 requirement is a
  contributor/build-time constraint, not a consumer-facing one.

### Fixed

- **Conformance adapter now enforces the pinned-key trust store**
  (RFC-AITP-0002 §3.2 step 1). `aitp-rs-adapter`'s
  `verify_handshake_payload_op` always configured `PeerConfig::pinned_key_store`
  as `None` — a documented no-op in `aitp-handshake` meaning "no local
  trust store enforced" — so fixtures could never actually exercise the
  gate that rejects a pinned-key proof whose signer key is not locally
  trusted, even though the underlying gate in
  `aitp_handshake::state_machine::bootstrap_verify_peer` was already
  implemented correctly. This went undetected because the one fixture
  exercising it, `id-007-pinned-untrusted-key-rejected`, coincidentally
  still failed for an unrelated reason: the pinned-key proof timestamp
  encoding bug above meant its signature never verified in the first
  place, masking the missing trust-store check behind a different
  rejection. Fixing the timestamp encoding surfaced this as a real CI
  regression (`id-007` unexpectedly passing) rather than a coincidental
  pass. The adapter now builds a `StaticPinnedKeyStore` from the
  fixture's `trust_store` field when present, so `id-007` is now
  correctly rejected with `IDENTITY_FAILED` for the right reason. This
  is a conformance-test-harness fix, not a change to
  `aitp-handshake`'s public library behavior.

- **Vendored schemas re-synced to spec commit
  `43f9d3937238a2cf9d727c9b5ca1b631060ecbc8`.** Picks up the RFC-AITP-0002
  §3.1 pinned-key proof-input known-answer vector
  (`kat-pinned-key-proof-001`), a new attacker keypair vector
  (`kat-keypair-006-attacker`), a new session-bundle signed example, and two
  new draft conformance fixtures (`bundle-004-signature-sibling-rejected`,
  `bundle-005-extensions-accepted`). Also picked up: `oidc_issuers` in the
  Manifest schema drops `minItems: 1`, and the Mutual Handshake schema's
  root `oneOf` becomes `anyOf` (no runtime impact — this repo only ever
  validates that schema's `$defs` sub-schemas, never its document root).
  The separately-tracked RFC-AITP-0002 §3.1 pinned-key proof timestamp
  encoding erratum is **not** part of this pin bump; it lands separately
  pending a cross-implementation compatibility check.

- **`verify_session_bundle` accepted the pre-erratum sibling-signature wire
  shape**, silently discarding a `signature` sent as a SIBLING of the
  `{"session_bundle": …}` transport wrapper instead of as a member of the
  wrapped body, and then reporting the resulting deserialize failure as the
  generic `INVALID_REQUEST` rather than a bundle-specific code.
  RFC-AITP-0010 §3 fixes `signature` as a member of the signed body, never
  a sibling of the wrapper, because a bundle is redistributable and must
  carry its own proof across any hop that strips the transport wrapper
  (RFC-AITP-0001 §5.4.1) — conformance fixture
  `bundle-004-signature-sibling-rejected` pins this. A new
  `aitp_session_bundle::parse_session_bundle_wire` routes both the
  unwrap and the `additionalProperties: false` rejection through
  `SessionBundleEnvelope`'s existing `deny_unknown_fields`, surfacing a new
  `SessionBundleError::WireFormInvalid` variant that
  `aitp-rs-adapter::bundle_error_code` maps to `SESSION_BUNDLE_INVALID`
  (`ErrorCode::SessionBundleInvalid` already existed; only the mapping was
  missing). `crates/aitp-transport-http/src/session_bundle_server.rs`
  already rejected this shape with HTTP 400 via the same
  `deny_unknown_fields` and needed no change — only a regression test.

- **OIDC identity-binding verification reported every issuer-key-resolution
  failure as `IDENTITY_FAILED`, including the case where the issuer's key
  couldn't be resolved at all.** `verify_oidc` (`crates/aitp-handshake/src/identity_oidc.rs`)
  mapped both "the JWKS couldn't be fetched/resolved" and "candidates were
  resolved but none matched the token's `kid`" to the same
  `HandshakeError::Identity`. RFC-AITP-0001 §5.4.3 says the distinction is
  load-bearing: `KEY_RESOLUTION_FAILED` is retryable (§5.7) while
  `IDENTITY_FAILED`-family codes are not, and RFC-AITP-0007 §3's
  `fail_closed` mode explicitly requires `KEY_RESOLUTION_FAILED` when the
  issuer's key can't be resolved. Reporting the wrong one invites a caller
  to retry a request that can never succeed, or to give up on one that
  would succeed once the transient resolution issue clears.

  A new `HandshakeError::KeyResolutionFailed { issuer, reason }` variant now
  covers the "no key available for this issuer at all" case — the
  `JwksResolver` returned an error, or resolved successfully but produced
  zero candidate keys. A `kid`/`alg` mismatch against a non-empty candidate
  set, or an invalid signature, remains `HandshakeError::Identity`: the
  proof itself is what's wrong there, not the resolution process.
  `HandshakeError` is `#[non_exhaustive]`, so matching callers keep
  compiling; `cargo-semver-checks` confirms adding this variant is not a
  breaking change. Both wire-code mapping sites now route the new variant
  to `KEY_RESOLUTION_FAILED` (`crates/aitp-rs-adapter/src/lib.rs`'s
  `handshake_error_code`, and `crates/aitp-transport-http/src/server.rs`'s
  `handshake_error_code`) — previously the transport-http mapper's
  `#[non_exhaustive]` catch-all would have defaulted an unmatched new
  variant to `INVALID_ENVELOPE`. The adapter's separate `env-003`
  conformance-fixture path (`verify_envelope_key_resolution`) already
  returned `KEY_RESOLUTION_FAILED` for its fixture-shaped scenario and is
  unaffected — it doesn't go through `verify_oidc`.

## [0.10.0] — 2026-08-29

### BREAKING

- **`aitp_handshake::JwkPublicKey` no longer exposes `jsonwebtoken` types**
  (closes #99). `pub alg: jsonwebtoken::Algorithm` and
  `pub key: jsonwebtoken::DecodingKey` are replaced with owned,
  library-independent types: `pub alg: JwsAlgorithm` (`EdDSA` / `ES256` /
  `RS256`) and `pub key: JwkKeyMaterial` (`Ed25519 { x }` / `P256 { x, y }` /
  `Rsa { n, e }`, all raw key bytes). `JwkPublicKey` now derives
  `PartialEq`/`Eq` — it no longer needs to avoid equality because a
  `DecodingKey` field hid internals. This is a breaking change to
  `aitp-handshake`'s public API (major version bump on next release). Any
  caller constructing a `JwkPublicKey` directly (custom `JwksResolver`
  impls, test fixtures) must switch to the new fields; every in-repo call
  site did.

  New helpers land alongside: `JwkPublicKey::from_jwk_json` (a single
  shared RFC 7517 JWK parser, replacing four duplicated hand-rolled ones
  in `aitp-transport-http` and both language bindings) and
  `verify_jws_signature` (JWS/DPoP signature verification against a
  `JwkPublicKey`, replacing `jsonwebtoken`'s `decode`/`Validation`).
  `aitp_crypto::AitpVerifyingKey::verify_raw` is now `pub` and a new
  `AitpVerifyingKey::from_p256_affine(x, y)` constructor accepts the
  separate affine coordinates JWKs carry for `EC` keys (as opposed to
  `from_compressed`'s SEC1-compressed form).

### Security

- **`bindings/aitp-py` bumps pyo3 `0.22` → `0.29`**, closing
  [RUSTSEC-2025-0020](https://rustsec.org/advisories/RUSTSEC-2025-0020) and
  [RUSTSEC-2026-0177](https://rustsec.org/advisories/RUSTSEC-2026-0177), both
  unfixable in the 0.22.x line and previously suppressed via `deny.toml` /
  `cargo audit --ignore` pending this migration
  ([#104](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/104)).
  Mechanical only — `Python::with_gil` → `Python::attach`, the `_bound`-suffixed
  constructor/accessor methods dropped their suffix, and
  `PyAnyMethods::downcast` → `Bound::cast` — no public API or behavior change.

### Removed

- **`jsonwebtoken` is dropped from every runtime dependency graph**
  (issue #99). It remains only as a dev-dependency (differential test
  oracle in `crates/aitp-transport-http/tests/jose_backend_tripwire.rs`
  and `crates/aitp-crypto`'s JWS KATs). `aitp-handshake` and
  `aitp-transport-http` no longer depend on it at all, in either
  direction (both bindings dropped it too).

  Upstream's current `jsonwebtoken` 11.0.0 `rust_crypto` backend still
  pins the pre-bump RustCrypto stack (ed25519-dalek 2.1 / p256 0.13 /
  sha2 0.10) and depends on `rsa` 0.9, which carries RUSTSEC-2023-0071
  (the Marvin timing sidechannel) with no patched release — a closed,
  passively-maintained upstream line staying on 9.x could not fix.
  EdDSA/ES256 verification now goes through this workspace's own
  KAT-tested `aitp-crypto` JWS primitives (`verify_raw`); RS256
  verification goes directly through `ring`'s
  `RsaPublicKeyComponents::verify` with `RSA_PKCS1_2048_8192_SHA256` —
  the same code path `jsonwebtoken` 9's RS256 support used internally, so
  this is not new cryptography, just the wrapper removed. Verification is
  unaffected by RUSTSEC-2023-0071, which is a signing/decryption padding
  timing issue, not a verification one. Ed25519 verification runs through
  dalek's `verify_strict` (already the case via `verify_raw`), which is
  strictly *more* rejecting than `ring`'s prior path — it additionally
  rejects non-canonical signatures.

## [0.9.0] — 2026-08-28

No root-changelog entries were recorded for this release; see the
release-plz-generated `crates/*/CHANGELOG.md` files.

## [0.8.0] — 2026-08-28

No root-changelog entries were recorded for this release; see the
release-plz-generated `crates/*/CHANGELOG.md` files.

## [0.7.0] — 2026-08-26

### Added

- **Delegation revocation is reachable from the SDKs.** `verify_delegation` and
  `verify_delegation_multihop` built their context with
  `VerifyDelegationContext::new`, which hardcodes `revocation_check` and
  `hop_revocation_check` to `None`, and neither binding exposed a parameter to
  override them. The hooks were unreachable from Python and Node, so every
  delegation redeemed through an SDK skipped **RFC-AITP-0006 §4 step 7** (a
  revoked `voucher.src_jti` MUST be rejected) and **RFC-AITP-0011 §6** (a
  revoked hop MUST reject the whole chain). Not bookkeeping: redeeming a
  delegation mints a *fresh TCT* for the delegatee, so a revoked grant kept
  minting credentials for a third party the grantor never re-authorized.

  The Rust core was already correct — both hooks, tests for each, and the
  `del-mh-004-revoked-hop` conformance fixture — so this is purely the binding
  layer and no crate changed.
  - Python: `verify_delegation(token, verifier_aid, revoked_jtis=None)` and
    `verify_delegation_multihop(token, verifier_aid, max_delegation_hops=3,
    revoked_jtis=None)`.
  - Node: `verifyDelegation(token, verifierAid, revokedJtis?)` and
    `verifyDelegationMultihop(token, verifierAid, maxDelegationHops?,
    revokedJtis?)`.

  The set is captured up front rather than wrapping a caller-supplied
  callable, following `verify_tct`. A callback cannot report a raise through
  `Fn(&Uuid) -> bool`, so the error would have to be swallowed as "not
  revoked" — failing open on a MUST. Omitting the set still waives the check,
  matching `verify_tct`; that default is now pinned by a test.

  One deviation is documented rather than hidden: §6 specifies each hop `jti`
  be checked against the deny list of *that hop's issuer*, which a flat set
  cannot express, so it applies to every hop. That can only reject more, never
  accept a revoked hop — but a set aggregated across issuers lets any
  contributor revoke any hop.

- **`verify_manifest_json` raises a typed error with a stable `code`**, in both
  bindings — Python `aitp.ManifestVerificationError`, Node an `Error` whose
  `code` property carries the cause. Causes: `signature_invalid`,
  `pop_failed`, `aid_mismatch`, `expired`, `version_unknown`,
  `identity_hint_malformed`, `incompatible_identity_type`, `malformed`.

  0.6.0 gave the *revocation* verify path a machine-readable cause and left
  the manifest path raising bare prose. That asymmetry is the same shape as
  the defect 0.6.0 set out to fix — one artifact has the surface, its sibling
  does not — and it forced at least one downstream consumer to classify
  "expired" by substring-matching an exception message, which is precisely the
  pin-the-program-output pattern the typed errors exist to remove.

  **Not breaking.** Both `ManifestVerificationError` and
  `RevocationVerificationError` now inherit `RuntimeError`, which is what these
  paths raised before they were typed, so a caller already catching the failure
  keeps working and gains `.code`.

## [0.6.0] — 2026-08-26

### Added

- **`verify_revocation_list` is bound in the Python and Node SDKs.** Both
  bindings shipped `sign_revocation_list` and neither shipped its counterpart,
  even though `verify_revocation_snapshot` is a Tier C conformance operation
  the Rust adapter implements (`docs/conformance.md`) and the spec's schema
  requires conformant implementations to verify the committed signed example
  "as committed, without re-minting". Every Python or Node consumer of AITP
  revocation was therefore structurally unable to be a conformant verifier.
  Downstream, three repos did the locally-reasonable thing — one hand-rolled a
  verifier in a test, one skipped verification entirely, one rendered "signed
  by CP" from the presence of a JSON key — and the 0.5.0 signing-input change
  crossed the whole release family with a single accidental interlock in its
  way. That was one missing binding, three times.
  - Python: `aitp.verify_revocation_list(envelope_json, expected_issuer_aid,
    now_unix_secs=None)`, raising `aitp.RevocationVerificationError` with a
    stable `.code`.
  - Node: `verifyRevocationList(envelopeJson, expectedIssuerAid, nowUnixSecs?)`,
    throwing an `Error` whose stable `code` property carries the cause.

- **`revocation_signing_bytes` / `revocationSigningBytes` are bound**, so a
  caller needing the exact signed bytes obtains them instead of reconstructing
  `JCS(revocation_list)` at the call site. Reconstructing that shape is how
  signer, verifier and conformance fixture drifted apart before 0.5.0 — and
  the callers who most needed it were on the far side of a binding that did
  not exist.

- **A typed error with a machine-readable cause.** The Python binding
  previously registered no exception classes at all: every failure was an
  untyped `RuntimeError`/`ValueError` carrying prose, so the only way to tell
  "wrong issuer" from "bad signature" was to string-match a message — pinning
  program output as an expected value, which is precisely the bug class the
  0.5.0 change exposed. Causes are now `signature_invalid`, `issuer_mismatch`,
  `version_unknown`, `expired`, `malformed`.

### Fixed

- **`verify_revocation_list` reported an issuer mismatch as
  `TctError::CnfMalformed`.** The code carried a comment explaining the
  variant was "chosen rather than introducing a new error variant for v0.1" —
  stale, because `TctError::IssuerMismatch` was added later for TCTs and
  documents exactly this case (RFC-AITP-0008 §3.3's issuer-key binding). It
  now returns `IssuerMismatch`. This makes "this snapshot is signed by the
  wrong issuer" distinguishable from "this snapshot is garbage" — an attacker
  serving their own correctly-signed list and a corrupt fetch are different
  events, and a caller that cannot separate them cannot alert on the first
  without drowning in the second. `TctError` is `#[non_exhaustive]`, so
  matching callers keep compiling. One emitted value does change: the
  conformance adapter maps this error through `tct_error_code`, so a revocation
  issuer mismatch now reports `TCT_SIGNATURE_INVALID` rather than
  `INVALID_ENVELOPE` (`crates/aitp-rs-adapter/src/lib.rs`). No conformance
  fixture pins that case — `rev-001`..`rev-004` cover staleness, soft-fail,
  success and lookup ordering — so nothing breaks, but the wire code moved.

### Note on scope

`VerifyRevocationListContext` deliberately gains **no** staleness knob. It
remains `{expected_issuer, now}`: verification establishes authenticity and
non-expiry, and RFC-AITP-0008 §3 puts freshness policy at the consuming peer.
Collapsing authenticity and freshness into one switch is how a `soft_fail`
mode ends up reporting a *forged* snapshot as not-revoked. The binding
documents that `published_at` staleness belongs to the caller.

## [0.5.0] — 2026-08-24

### BREAKING

- **The JCS signing input is now the inner artifact body, not the transport
  wrapper** (spec [`5f8e588`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/commit/5f8e588),
  RFC-AITP-0001 §5.4.1). The **revocation snapshot** and **session trust
  bundle** signatures previously covered `{"revocation_list": {…}}` /
  `{"session_bundle": {…}}`; they now cover the inner body. The **manifest**
  is unchanged — it already signed inner, and is the control case.

  **An artifact signed by ≤0.4.x will not verify here, and an artifact signed
  here will not verify against ≤0.4.x.** Failure is fail-closed
  (`TCT_SIGNATURE_INVALID` / `BUNDLE_INVALID_SIGNATURE`), never fail-open —
  but under a `fail_closed` revocation policy that surfaces as a spurious
  `TCT_REVOKED`. Roll issuers and verifiers close together.

  The values below are the same ones the spec's CHANGELOG publishes, so you
  can identify which convention a pinned version emits:

  | Vector | Before | After |
  |---|---|---|
  | `kat-manifest-001` | 636 B · `cef51854…46c5ae` | 623 B · `b93915e9…5884af` |
  | `kat-revocation-001` | 241 B · `739feb36…97e0d9` | 221 B · `dad7eb6d…008bfb` |
  | `kat-session-bundle-001` | 941 B · `dc99e725…4f2640` | 922 B · `c577854d…1aa5e5` |

  Signatures: `kat-session-bundle-001.coordinator_signature_b64url`
  `Su2JiXGi…2M2_AA` → `czzmjpVf…Tg_TBw`; the committed revocation snapshot
  `2OYmur9N…sPF1DQ` → `DTmCoELd…BfKkCQ`.

  No dual-accept is implemented. RFC-AITP-0008 §1.5 permits accepting either
  shape during a transition window, but RFC-AITP-0010 grants no such
  allowance for the session bundle, so a half-measure would leave the two
  artifacts inconsistent; accepting two byte strings under one signature
  would also mask exactly the divergence this release fixes.

  The protocol version literal stays `aitp/0.2` — no message shape changed.
  RFC-AITP-0001/0003/0008/0010 moved `0.2.0-draft` → `0.2.1-draft`.

- **`max_hops` → `max_delegation_hops`**, the name RFC-AITP-0011 §2 uses:
  - Rust: `VerifyDelegationContext.max_hops` → `.max_delegation_hops`;
    `DEFAULT_MAX_HOPS` → `DEFAULT_MAX_DELEGATION_HOPS`; `.with_max_hops()` →
    `.with_max_delegation_hops()`
  - Node: `verifyDelegationMultihop(_, _, maxHops)` → `maxDelegationHops`
  - Python: `verify_delegation_multihop(…, max_hops=)` → `max_delegation_hops=`

- **`VerifyRevocationListContext` and `VerifyDelegationContext` are
  `#[non_exhaustive]`.** Build them with `::new()` plus the builder methods
  instead of a struct literal. New: `VerifyRevocationListContext::new`,
  `VerifyDelegationContext::with_revocation_check` /
  `::with_hop_revocation_check`.

### Added

- `aitp_tct::revocation_signing_bytes` — the single definition of a
  revocation snapshot's signing input, so callers needing the exact signed
  bytes do not reconstruct the shape themselves.

- **Cross-implementation acceptance in CI** (`cross-impl acceptance
  (aitp-verifier-py)`): `aitp-rs` mints a revocation snapshot and a session
  bundle; [`aitp-verifier-py`](https://github.com/agentidentitytrustprotocol/aitp-verifier-py)
  — an implementation written from the RFC texts alone, sharing no code with
  this workspace — verifies those exact bytes, with no re-minting on either
  side. Pinned by SHA in `tests/AITP_VERIFIER_PY_VERSION`.

- Known-answer coverage for every JCS-profile artifact: canonical bytes, the
  committed signature verified **as committed**, and a **negative** test that
  the signature fails over the wrong shape. The session bundle had no KAT at
  all before; the negative column was empty for all three artifacts.

- The spec's own `verify-known-answer.mjs` (50 checks, independent JCS/JOSE
  stack) now runs in CI.

### Fixed

- `scripts/sync-schemas.sh` now **mirrors** rather than copies. A file deleted
  upstream previously lingered in `tests/schemas/` *and* left `git diff`
  clean, so the "vendored schemas in sync" drift check reported green over a
  file that no longer existed in the spec.

- `crates/aitp-core/tests/kat.rs` no longer selects which shape to
  canonicalize by inspecting the pinned answer — it asserts the vector's
  declared `signing_input`, so it can actually fail. `tools/mint-conformance-fixtures`
  and `crates/aitp-conformance`'s placeholder signer also minted the wrapped
  form; because that harness both mints and checks, every implementation
  passed against its own convention while disagreeing on the wire.

## [0.4.1] — 2026-07-10

### Added

- **`aitp` CLI** (`aitp-cli` crate): an offline command-line tool for the
  common build/debug tasks — `keygen`, `aid`, `tct inspect`, `tct verify`,
  and `manifest verify` (stdin-friendly, non-zero exit on failure). Ships
  in-repo (`cargo run -p aitp-cli`); not yet published to crates.io.

- **Tests**: direct integration suites for `aitp-rs-adapter` (dispatch +
  raw NDJSON protocol), P-256 envelope coverage, session-bundle error
  variants, CLI negative/manifest cases, `proptest` suites mirroring the
  `envelope_parse`/`manifest_parse` fuzz targets, runnable doctests on the
  facade / `TctVerifyContext::builder` / `HostGuard::strict`, and Node SDK
  `manifest-verify` + `revocation` suites for Python parity.

- **CI**: the full spec conformance corpus now runs in CI (new `conformance`
  job against the pinned spec commit); a `wasm32-wasip1` portability
  build-check over the pure crates; the `test` job runs `cargo-nextest` plus
  a dedicated doctest pass; a `dorny/paths-filter` fast-path lets docs-only
  PRs skip the heavy net-new jobs. All GitHub Actions are SHA-pinned; added
  `CODEOWNERS` and CI-parity `make` targets (`deny`/`audit`/`msrv`/`semver`/
  `coverage`/`ci`).

### Changed

- **Docs**: refreshed for 0.4 — corrected the session-bundle binding
  feature name (`session-bundle`), unified the TCT-renewal citation on
  RFC-AITP-0013, fixed stale `0.2.0` version strings, added an install
  section + badges to the README, and added a `docs/testing.md` guide.

### Removed

- Dropped the declared-but-unused `insta` dev-dependency.

## [SDK 0.4.1] — bindings (2026-07)

> Bindings-only patch. The `aitp-sdk` (PyPI) and
> `@agentidentitytrustprotocol/aitp` (npm) SDKs bump **0.4.0 → 0.4.1** to
> carry the 0.4.0-crate **security hardening**. The SDK public API and the
> on-the-wire protocol (`aitp/0.2`) are unchanged, so this is drop-in —
> consumers on `^0.4.0` / `>=0.4.0` pick it up on the next install.

### Changed

- The SDKs now build against the hardened 0.4.0 crates: **canonical low-S
  P-256** signatures (high-S rejected on verify), an **RSA-2048 floor** on
  the OIDC/DPoP verification paths, and the strict `TctVerifyContext`
  verification path (behavior-preserving at the SDK boundary — the bindings
  still supply an explicit revocation set and waive the manifest-expiry
  cap, exactly as before). **No SDK function signatures changed.**

## [0.4.0] — Security hardening (2026-07)

Rust crates **0.3.0 → 0.4.0**. Implements a 2026-07 protocol + runtime
security review. The on-the-wire protocol is unchanged (`aitp/0.2`); this
is an API + hardening release. Per-item detail is in the sections below.

### Added

- **SSRF guard** (`net_guard`): peer-derived fetches (Manifest,
  JWKS/discovery/`aitp-keys`, facade handshake+renew POST) reject
  redirects, classify resolved addresses (link-local/metadata always
  denied; private ranges warn), and pin vetted addresses to defeat DNS
  rebinding. Configurable via `with_host_guard(HostGuard::strict())`.
- **Pluggable replay store** (`ReplayGuard` trait + `InMemoryReplayGuard`
  default) for envelope `message_id` / DPoP `jti` dedup — supply a shared
  backend (e.g. Redis) for clustered deployments. `HandshakeServer::with_replay_guard`, `DpopReplayCache::with_guard`.
- **Strict TCT verification**: `TctVerifyContext::builder(..)` forces an
  explicit decision on revocation and the issuer-Manifest expiry cap
  (named `*_dangerous` waivers); `clock_skew_secs` knob.
- **Configurable facade transport**: `InitiatorConfig::new(..)` +
  `with_http_timeout` / `with_host_guard`.
- Five verify-path fuzz targets + a fuzz PR gate.
- **Operator docs & container**: `docs/deployment.md` (clustering + hardening
  checklist), `docs/key-management.md` (seed handling, KMS/HSM reality,
  rotation), and a reference `Dockerfile` + `docker-compose.yml` that run
  the two-agent demo (`docker run`). `agent-b` gained a `--host` flag.
- **Optional metrics** (`metrics` feature on `aitp-transport-http`):
  counters for replay rejections, handshake outcomes, session evictions,
  and revocation/JWKS cache effectiveness.

### Removed

- Dropped the unused `secrecy` workspace dependency (declared but never
  referenced).

### Changed — **BREAKING (Rust API)**

- `TctVerifyContext` and `InitiatorConfig` are now `#[non_exhaustive]`;
  construct via `TctVerifyContext::builder(..)`/`permissive_at(..)` and
  `InitiatorConfig::new(..)` respectively.
- `Aid::to_ed25519_bytes` / `to_p256_bytes` (panicking) **removed** — use
  the `try_*` variants.
- `DpopReplayCache` internals reworked to sit behind `ReplayGuard`
  (constructors `with_ttl` / `with_guard`).
- P-256 signatures are now emitted in canonical **low-S** form and the
  verifier rejects high-S (malleability fix); RSA keys below 2048 bits
  are rejected on the OIDC / DPoP paths.

## [SDK 0.4.0] — bindings (2026-06)

> Bindings-only release. The Rust crates (0.3.0, published) and the
> on-the-wire protocol (`aitp/0.2`) are unchanged; the language SDKs
> (`aitp-sdk` on PyPI, `@agentidentitytrustprotocol/aitp` on npm) bump
> 0.3.0 → 0.4.0.

### Changed — **BREAKING (bindings): all capabilities ship by default**

The Python and Node SDKs no longer hide post-v0.1 capabilities behind an
opt-in `experimental` build. **TCT renewal, session bundles, SPKI
pinning, and multi-hop delegation are now compiled into the default
wheel / `.node`**, so the published PyPI wheel and the default Docker
build expose the full surface with no special build step. Each capability
remains a named Cargo feature (`renewal`, `session-bundle`,
`spki-pinning`, `multihop-delegation`), all on by default; a minimal
artifact can opt out with `--no-default-features`.

- The `experimental` umbrella feature and the `experimental-*` feature
  names are removed (renamed to the plain capability names above).
- `verify_delegation_experimental_multihop` →
  `verify_delegation_multihop` (Python) and
  `verifyDelegationExperimentalMultihop` → `verifyDelegationMultihop`
  (Node). The strict single-hop `verify_delegation` is unchanged and
  remains the safe default.

Migration: depend on `aitp-sdk>=0.4.0`; replace any call to the old
multi-hop function name; drop any `--features experimental` build flags
(the default build now includes everything).

## [0.3.0] (AITP protocol `aitp/0.2`)

> Crate version 0.3.0. The Rust API has breaking changes (the
> compact-JWS migration below), so the crates bump their 0.x major
> from 0.2 to 0.3; the **protocol** version is `aitp/0.2`. The two
> version namespaces are independent.

Tracked in `plans/v0.2-roadmap.md`. Forward-looking work that did not
land in 0.1.0.

### Changed — **BREAKING: compact-JWS portable trust artifacts (`aitp/0.2`)**

The JWS/TCT migration (`plans/jws-tct-migration.md`; spec commit
`52582bb`). The portable trust artifacts — the **TCT**, the new **grant
voucher**, and the **delegation token** — are re-serialized as RFC 7515
compact JWS strings with explicit typing (`aitp-tct+jwt`,
`aitp-grant+jwt`, `aitp-delegation+jwt`). Signatures cover the exact
transmitted bytes: verifiers never re-serialize, re-canonicalize, or
reconstruct anything, and any off-the-shelf JOSE library verifies the
tokens given only the issuer public key (proven in CI by a
`jsonwebtoken` differential oracle and byte-for-byte reproduction of
the spec's signed-example KAT vectors). Protocol-internal artifacts
(envelopes, manifests, revocation snapshots) stay on the JCS
embedded-signature profile; the protocol version literal is `aitp/0.2`
everywhere. There is no wire migration path: v0.1 verifiers reject
v0.2 artifacts on the version gate; re-handshake.

Old → new claim mapping for TCTs: `version→ver`, `jti`, `issuer→iss`,
`subject→sub`, `audience→aud`, `issued_at→iat`, `expires_at→exp`,
`grants`, `binding.cnf` (raw key) → `cnf.jkt` (RFC 7638 thumbprint).

- **`aitp-crypto`**: new `jws` module — `sign_compact` /
  `verify_compact` with AID-derived algorithm pinning (`EdDSA`/`ES256`;
  `alg: none` and confusion headers rejected with the new
  `TOKEN_ALG_MISMATCH` code), RFC 8725 explicit-typing enforcement
  (`TOKEN_TYP_MISMATCH`), and strict three-segment parsing.
- **`aitp-tct`**: `Tct`/`TctEnvelope`/`TctBinding` replaced by
  `TctClaims` / `IssuedTct { token, claims, voucher }` /
  `VerifiedTct { token, claims }`. `TctBuilder::build()` also mints the
  companion **grant voucher** (RFC-AITP-0005 §8) unless
  `.without_voucher()`. `verify_tct` takes the compact string and the
  expected issuer **AID** (which pins key and algorithm). New
  `verify_voucher`. Renewal carries compact strings. The revocation
  snapshot stays JCS but signs the wrapped `{"revocation_list": …}`
  view per the v0.2 KAT.
- **`aitp-delegation`**: `grant_proof` and its source-TCT byte
  reconstruction (`verify_source_tct_projection`) are **gone** — a
  delegation embeds the issuer's grant voucher verbatim and the
  verifier checks its own past signature directly
  (`DELEGATION_INVALID_VOUCHER` replaces
  `DELEGATION_INVALID_GRANT_PROOF`). Multi-hop (RFC-AITP-0011) chains
  carry verbatim delegation JWS strings with per-hop `jti`, voucher on
  `chain[0]` only, and a digest-array `chain_hash`.
- **`aitp-handshake`**: commit payloads carry `tct` + optional
  `grant_voucher` as opaque strings; completions return
  `CompletedHandshake { tct: VerifiedTct, grant_voucher }`. The
  received voucher is verified to mirror its companion TCT.
- **`aitp-session-bundle`**: participants embed TCT compact strings
  verbatim; the bundle signs the wrapped `{"session_bundle": …}` view.
- **`aitp` facade**: `SessionContext` exposes `held_tct: VerifiedTct` +
  `grant_voucher`; `TctStore` stores token + claims + voucher;
  `renew_tct` returns `RenewedTct { tct, grant_voucher }`.
- **Conformance**: the runner materializes the spec's v0.2 placeholder
  families (compact-JWS tokens with claims-sibling minting, computed
  chain hashes, manifest PoP, P-256 envelope signatures, pinned
  reference clock); the adapter was reworked op-by-op. Full spec
  matrix: **46/46 core fixtures pass** (51/51 with the multihop +
  session-bundle opt-ins; the remaining 2 are the v0.1-frozen
  structural rejections, correctly skipped under opt-in).
- **Adapter fixes**: the handshake round-2 PoP is verified under the
  **sender** (TCT issuer) key per RFC-AITP-0004 §3, and HELLO-family
  envelope signatures are checked after the Manifest/identity
  bootstrap (RFC-AITP-0004 §5.1 step 6).
- **Bindings (`bindings/aitp-py`, `bindings/aitp-node`)**: migrated to
  the compact-JWS API — TCT/voucher/delegation cross the FFI boundary
  as opaque strings; handshake completions expose `tct` (token) +
  `claims` + optional `grant_voucher`; delegation issuance roots in the
  grant voucher. **F-1 closed**: both `verify_tct` entry points now take
  an optional set/array of revoked `jti` strings, wired into the
  verifier's revocation check (previously hard-coded to `None`, silently
  honoring revoked-but-unexpired TCTs).
- **Interop**: the cross-runtime Python↔Node handshake harness migrated
  to the JWS contract, plus a new **stock-JOSE acceptance check** — the
  spec's signed-example TCT / voucher / delegation tokens are verified
  by third-party `pyjwt` (Python) and `jose` (Node) given only the
  issuer public key, and both corroborate the `alg: none` rejection.
  This is the migration's headline property (off-the-shelf
  verifiability), proven against independent JOSE stacks and runnable
  without the native bindings.
- **Docs**: `docs/` refreshed for v0.2 — signing-profile boundary
  table, grant-voucher model, multi-hop rewrite, renewal/session-bundle
  shapes, conformance placeholder conventions, and a "debugging a TCT
  with jwt.io / jose / pyjwt" note.

Full migration verified: workspace tests + clippy clean, both bindings
`cargo check` clean, conformance **46/46 core (51/51 with opt-ins)**,
stock-`jose`/`pyjwt` acceptance green. Not executed here: the native
binding builds (maturin/napi absent) — their Rust compiles cleanly and
the Python/JS test + interop migrations are faithful to the contract,
to be confirmed in CI where the bindings build.

### Added — `aitp-envelope` crate

- **New crate `aitp-envelope`.** `sign_envelope`, `sign_envelope_with`,
  and `verify_envelope_signature` moved out of
  `aitp-transport-http::common` into a standalone crate depending only
  on `aitp-core` + `aitp-crypto` — no HTTP, no async, no I/O. This lets
  the language bindings (below) sign and verify envelopes without
  inheriting a transport stack. `aitp-transport-http::common` keeps thin
  wrappers over the three functions, so existing
  `aitp_transport_http::common::*` imports keep compiling unchanged.

### Added — language SDKs (`bindings/`)

- **`bindings/aitp-py`** — Python SDK built with PyO3 / maturin. An
  `AitpAgent` plus `InitiatorSession` / `ResponderSession` /
  `TctIdentity` classes; every method takes and returns JSON strings
  (HTTP request/response bodies), so agent code never handles a Rust
  type. In-process handshake tests under `bindings/aitp-py/tests/`.
- **`bindings/aitp-node`** — Node.js SDK built with NAPI-rs, the
  API-symmetric counterpart of `aitp-py` (`buildManifest` ↔
  `build_manifest`, etc.). In-process handshake tests under
  `bindings/aitp-node/tests/`.
- Both binding crates are **excluded from the Cargo workspace**: they
  are `cdylib`s built against an external Python / Node toolchain and
  must not be pulled into `cargo test --workspace`. Each carries its
  own `Cargo.lock`.

### Changed — language SDKs `0.1.0` → `0.2.0` (BREAKING)

- **Strict-by-default delegation.** `verify_delegation` /
  `verifyDelegation` now verify under strict AITP v0.1 single-hop and
  **reject** any token carrying a non-empty `chain`
  (`DELEGATION_MULTIHOP_NOT_SUPPORTED`), matching the Rust core default.
  Previously both SDKs silently defaulted to draft RFC-AITP-0011
  multi-hop (`max_hops = 3`). The `max_hops` parameter was removed from
  these functions. **Migration:** to accept multi-hop, build with the
  new `experimental-multihop-delegation` feature and call
  `verify_delegation_experimental_multihop` /
  `verifyDelegationExperimentalMultihop`.
- **OIDC mint-callback** presentation path (`IdentityMode::OidcWithMintCallback`
  in the facade; bindings already wrapped host callables as the minter).
- **`TctStore` / `verify_tct_cached`** — a hot-path cache that skips the
  signature check for a byte-identical, still-valid TCT (keyed by the
  SHA-256 of the envelope; tampered bytes miss and are fully verified).
- **Node binding now compiles with all features off** — the default
  v0.1-core-only build previously failed to compile.
- Published SDK versions bumped `0.1.0` → `0.2.0` to signal the breaking
  delegation change (pre-1.0 minor bump).

### Added — cross-language interop tests

- **`bindings/interop/`** — integration tests that drive a real
  four-message AITP handshake between the Python and Node SDKs in both
  directions, proving the two emit wire-compatible envelopes. The
  Python end runs in-process under `pytest`; the Node end runs as a
  line-delimited JSON-RPC subprocess worker (`node_worker.mjs`). Four
  tests cover both handshake directions plus cross-language TCT
  scope-rejection.
- **`make interop`** / **`scripts/interop.sh`** build both bindings
  (maturin + napi), then run the interop suite. Exits non-zero on any
  failure, so it can gate CI.

### Added — DPoP scaffolding (Phase 6, RFC 9449)

- **`aitp-transport-http::dpop`** module with `DpopProof`,
  `DpopHeader::parse`, and a `verify_dpop_proof` stub returning
  `DpopError::NotImplemented`. 4 unit tests cover header parsing.
- Full DPoP verification (signature, htm/htu/iat binding,
  replay-cache, `cnf.jkt` thumbprint check) is **deferred** — see
  `plans/v0.2-closeout.md` Phase 6.

### Added — CI hardening (Phase 8)

- New CI jobs: `semver` (cargo-semver-checks vs PR base ref),
  `msrv` (cargo-msrv verify), `coverage` (cargo-tarpaulin → Cobertura
  artifact).
- Fuzz scaffolding under `fuzz/` (excluded from the main workspace
  for cargo-fuzz's nightly profile): targets for envelope parsing,
  manifest parsing, delegation parsing. Run via
  `cd fuzz && cargo +nightly fuzz run <target>`.

### Documented — design / follow-ups

- `plans/v0.2-roadmap.md` — full 9-phase plan with dependencies.
- `plans/v0.2-closeout.md` — what landed, what's deferred, exact
  pickup order for the next session.
- `plans/v0.2-crypto-agility-design.md` — Phase 7 implementation
  sketch. Implementation blocked on spec-side algorithm identifier.
- (Spec repo) `plans/v0.2-conformance-followups.md` — concrete
  list of KATs and conformance fixtures still to mint.

### Fixed — documentation

- **Corrected the handshake signing-input recipes in
  `docs/handshake-transcripts.md`.** The page (written for
  cross-language implementers) documented the PoP/nonce preimage as the
  ASCII bytes of the base64url nonce string and the pinned-key proof as
  `message_id|timestamp` — both wrong. Per the code and
  RFC-AITP-0001 §5.4.2 / RFC-AITP-0002 §3.1, PoP inputs hash the
  **base64url-decoded** nonce bytes (hashing the string form is explicitly
  non-conformant), and the pinned-key proof is the 5-field domain-prefixed
  structure. The tables now defer to the normative RFC sections.
- **Fixed the TCT-renewal RFC reference** (`docs/tct-renewal.md`,
  `docs/sdk-node.md`, `docs/sdk-python.md`): renewal is RFC-AITP-0013
  (+ RFC-AITP-0004 §8.1, non-normative), not "RFC-AITP-0005 §10" (which is
  the Verification API).
- **Repaired dangling links to `docs/design/PENDING.md`** (a file that
  never existed) in `architecture.md`, `jcs.md`, `handshake-transcripts.md`,
  and a `state_machine.rs` comment — now pointing at
  `plans/defered/deferred.md`.
- **Refreshed stale design docs:** `conformance.md` ("13 fixtures"
  → 44; op vocabulary reconciled with `aitp-rs-adapter`); `jcs.md` (spec
  KAT hashes now exist and are CI-pinned, no longer a de-facto local value).

### Added — documentation

- **`docs/README.md`** — a documentation index establishing the
  "implementation docs here / normative protocol in the spec RFCs" boundary
  and linking the spec-side guides, so the implementation docs point rather
  than duplicate.

### Changed — documentation structure

- **Flattened `docs/design/` into `docs/`** and dropped the numeric
  filename prefixes — every page now lives directly under `docs/` with a
  descriptive name (`jcs.md`, `handshake-transcripts.md`,
  `session-bundle.md`, `multihop-delegation.md`, `tct-renewal.md`).
- **Merged the topology guide and the workspace rationale** into a single
  `docs/architecture.md` (former `docs/architecture.md` +
  `docs/design/00-architecture.md`), de-duplicating the crate map and
  bindings sections.
- **Merged the conformance matrix into the adapter-design doc** as
  `docs/conformance.md` (former `docs/design/02-conformance-adapter.md` +
  `docs/conformance-matrix.md`); `architecture.md`'s conformance section now
  points there instead of restating the op tables.
- Updated all inbound references (README, CONTRIBUTING,
  `adapters/README.md`, and the `//!` doc-comments in `aitp-core`,
  `aitp-conformance`, and `aitp-rs-adapter`).

### Deferred — production posture (to Phase 9)

These items were in the original Phase 2 scope but moved to Phase 9
polish since they are deployment-tunable rather than library-level
concerns:

- TLS root-CA override / certificate pinning (currently uses
  `reqwest`'s system roots).
- HTTP header-size cap and per-chunk slow-loris read timeout
  (axum/hyper provides `http1_max_buf_size`; deployment tunable).
- OIDC discovery cache + `iss` URL normalization (will land with
  Phase 6 OIDC DPoP work).

## [0.1.0] — 2026-05-19

First stable release. Tracks AITP specification v0.1.0-rc.1.
Closes the rc.1 → rc.2 hardening cycle: revocation ordering,
fail-mode strictness, server rate-limiting, facade response handling,
RFC-AITP-0007/0010 surface, multi-hop delegation under feature flag,
and the v0.1 conformance gate. 44/44 fixtures pass (37 `core` + 7
`draft` under their opt-in features).

### Security — rc.1 → rc.2 hardening

- **Revocation ordering (RFC-AITP-0008 §3.3).** `verify_received_tct`
  in the handshake state machine now verifies the TCT signature
  *before* consulting the revocation hook. `tct.issuer` / `tct.jti`
  are attacker-controlled bytes until the signature checks out; the
  prior order let an unsigned TCT steer revocation network I/O
  (amplification DoS, cache pollution, telemetry skew).
- **`SoftFail` key resolution fails closed through `resolve()`.** The
  plain `JwksResolver::resolve` path now returns the new
  `ResolveError::SoftFailRequiresOutcome` under
  `KeyResolutionFailMode::SoftFail` instead of an empty key set
  (which was wire-indistinguishable from `FailOpen`). The degraded
  outcome is reachable only via `KeyResolutionPolicy::resolve_outcome`.

### Added — server & facade hardening

- **Rate limiting wired into the handshake handlers** (RFC-AITP-0009
  §3.1): the normative `replay → rate-limit → timestamp` check order
  is enforced in `enforce_envelope_boundary_checks`; over-quota
  requests get HTTP 429 with no AITP error envelope.
- **Distinct TCT error codes** during the handshake — `TCT_REVOKED` /
  `TCT_EXPIRED` / `TCT_EXPIRES_AFTER_MANIFEST` instead of collapsing
  every `TctError` to `TCT_SIGNATURE_INVALID`.
- **`HandshakeServer::with_pinned_key_store`** wires a `PinnedKeyStore`
  into the responder handlers (RFC-AITP-0002 §3.2 step 1); an
  untrusted pinned-key initiator gets `IDENTITY_FAILED`.
- **Facade response handling**: `run_initiator_handshake` / `renew_tct`
  validate HTTP status, Content-Type and body size, and surface a
  peer's AITP error envelope as the new `FacadeError::Protocol`. The
  body is read under a hard cap — a `Content-Length` over the limit is
  rejected before any read, and the streaming read aborts the moment
  the running total exceeds it — so a malicious peer cannot exhaust
  initiator memory with an unbounded response.
- **`IdentityMode`** on `InitiatorConfig` — the facade presents the
  configured identity type (pinned-key or OIDC) and pre-checks it
  against the peer Manifest's `accepted_identity_types` before the
  handshake (previously always presented pinned-key).

### Added — RFC-AITP-0007 / 0010 surface

- `PresentedIdentity::oidc_checked` — construction-time validation
  that an OIDC JWT's `nonce` claim matches the handshake `pop_nonce`.
- `AsyncJwksResolver` trait + impl for `KeyResolutionPolicy`; the sync
  `resolve()` bridge detects a current-thread runtime and fails closed
  with a descriptive error instead of panicking in `block_in_place`.
- Session-bundle HTTP transport (RFC-AITP-0010 §4.3.1) behind the
  `experimental-session-bundle` feature: `SessionBundleServer` with
  `POST /aitp/session/bundle` + `GET /aitp/session/bundle/:session_id`,
  and the `aitp_session_bundle::RFC_AITP_0010_BUNDLE_URI` Manifest
  extension key.

### Added — conformance

- Adapter ops `authorize_capability_invocation`,
  `expect_pop_challenge_issued`, `withhold_pop_response` — the new
  `tct-007` PoP-enforcement fixture (RFC-AITP-0005 §6.2) now passes.
- `aitp-conformance run` enforces a **v0.1 conformance gate**: a
  `required_for_v0_1` fixture that fails or is SKIPped for an
  adapter-capability reason makes the run exit non-zero.
- The runner now honors fixture `side_effects` assertions — any side
  effect the adapter reports in its result is asserted against the
  fixture, and a reported mismatch fails the fixture.
- `docs/conformance-matrix.md` — per-fixture status (44 fixtures:
  37 `core` PASS, 7 `draft` PASS under their opt-in features).
- Runner placeholder resolver wires the spec's `__TAMPERED_SIG__` /
  `__TAMPERED_SIGNATURE__` recipe (PLACEHOLDERS.md §129–130 — sign
  properly, then flip the least-significant bit of the last raw
  signature byte) so `rev-004` exercises `Ed25519::verify_strict()`
  failure rather than a base64url decode error.
- Vendored spec schemas advanced to spec commit
  `4bb933a4ade85eb36b12b64cc66c11b636722c19` (RFC normative-hardening
  pass + `expected.side_effects` block in
  `aitp-conformance-fixture.schema.json`).

### Added — Session Trust Bundle (Phase 5, RFC-AITP-0010)

- **New crate `aitp-session-bundle`.** Coordinator-attested membership
  artifact for multi-agent sessions. Redistributes N bilateral
  coordinator↔participant Mutual Handshakes to all participants
  without requiring an O(N²) full mesh.
- Types: `SessionTrustBundle`, `ParticipantEntry`,
  `SessionBundleEnvelope`. Schema-conformant with the new
  `schemas/json/aitp-session-bundle.schema.json` shipped in the
  spec repo's Phase 3 PR.
- `SessionBundleBuilder` — coordinator-side: collects N participant
  TCTs, validates `issuer == coordinator` and `audience == aid`
  invariants, computes `expires_at = min(participant TCT expiries)`
  per RFC-AITP-0010 §6, JCS-canonicalizes and signs.
- `verify_session_bundle` — checks version, expiry, expiry-window
  invariant, member presence, outer signature, per-participant TCT
  validity. Per-pair revocation degradation: revoked participants
  are dropped from the active set rather than invalidating the
  whole bundle (`BundleOutcome::DegradedSubset`).
- 8 new integration tests in `crates/aitp-session-bundle/tests/round_trip.rs`
  — happy path with 3 participants, non-member, expired, tampered
  signature, revoked-participant degraded subset, empty
  participants, audience mismatch at build, schema rejection of
  unknown fields.
- Re-exported via `aitp::session_bundle` facade.

### Added — multi-hop delegation (Phase 4, RFC-AITP-0011)

- **`DelegationToken` carries optional `chain` and `chain_hash`** for
  delegation chains longer than one hop. Single-hop tokens are
  byte-identical to pre-rc.1 (both fields skip-if-none in JCS view).
- **`DelegationStep`** type alias for `GrantProof`. Each `chain[i]` is
  a step; the most-recent step lives in the top-level `grant_proof`.
- **`VerifyDelegationContext::max_hops`** caps total chain length
  (default 3 from RFC-AITP-0011 §2). Setting `0` reverts to strict
  v0.1 posture (rejects any chain with `MultihopNotSupported`).
- **Verifier per-hop checks** (RFC-AITP-0011 §3-§6): hop-0 source-TCT
  projection signature; hops i>0 step-body JCS signature; audience
  continuity through chain; `chain[0].issuer == delegator`; per-hop
  expiry monotonically non-increasing; transitive scope subsetting
  end-to-end; per-hop revocation lookup; JTI uniqueness within chain;
  `chain_hash` recompute and outer-signature-binding check.
- **New error variants**: `HopLimitExceeded`, `ChainHashMismatch`. The
  conformance adapter maps these to `DELEGATION_HOP_LIMIT_EXCEEDED`
  and `DELEGATION_CHAIN_HASH_MISMATCH` per the new RFC-AITP-0011
  registry. `MultihopNotSupported` is now mapped to the spec's
  `DELEGATION_MULTIHOP_NOT_SUPPORTED` (was `MULTIHOP_NOT_SUPPORTED`).
- **9 new integration tests** in `crates/aitp-delegation/tests/multihop.rs`
  — 3-hop happy path, hop-limit exceeded, max_hops=0 (strict v0.1),
  chain_hash tampered, chain truncation, scope inflation, revoked
  hop, duplicate JTI, single-hop unchanged.

### Added — production posture (Phase 2)

- **`tracing` instrumentation.** `aitp-transport-http` now emits structured
  `tracing` spans on `ManifestFetcher::fetch` and `JwksFetcher::resolve`,
  with span fields for the target origin/issuer. Library code is
  zero-cost when consumers don't install a subscriber. Add
  `tracing-subscriber = "0.3"` and call e.g.
  `tracing_subscriber::fmt::init()` in your binary to enable.
- **Retry policy for transient fetches.** `RetryPolicy` (in
  `aitp-transport-http::retry`) carries an exponential-backoff
  configuration: `none()`, `conservative()` (3 attempts / 100 ms
  base / 1 s cap), `aggressive()` (5 attempts / 200 ms / 5 s cap),
  or `custom(...)`. Wired into `ManifestFetcher::with_retry_policy`.
  Only transient errors (`Timeout`, `Network(_)`, 5xx upstream) are
  retried; verification, oversize, and content-type errors are not.
  Default is no retry (rc.1 behavior preserved).

### Fixed — production safety (Phase 1)

- **HTTP server mutex poisoning DoS** (post-rc.1 audit P0). `HandshakeState`
  used `std::sync::Mutex` for its session map and message-id deny list,
  with `.lock().unwrap()` at every call site
  (`crates/aitp-transport-http/src/server.rs:351,399,619`). A panic in
  any locked section would have poisoned the mutex; subsequent requests
  would have unwrapped on `PoisonError` and crashed the request handler
  permanently. The `JwksFetcher` cache (`client.rs:170,186,205`) had
  the same shape, as did the demo agent's session map
  (`examples/two-agents/src/bin/agent-b.rs:129,162`).
  Swapped to `parking_lot::Mutex` (no poison state, drop-in API)
  workspace-wide; all `.lock().unwrap()` call sites are gone. No
  observable behavior change in the happy path.

### Fixed — production hygiene

- Replaced five infallible `.unwrap()` calls in `crates/aitp/src/facade.rs`
  (`run_initiator_handshake` and `renew_tct` payload-serialization +
  URL-join sites) with `?`-propagated `FacadeError::Http` results so
  `cargo clippy -- -D clippy::unwrap_used` stays clean in production
  paths.

[0.1.0]: https://github.com/agentidentitytrustprotocol/aitp-rs/compare/v0.1.0-rc.1...v0.1.0

## [v0.1.0-rc.1]

Release-candidate gate over beta.1. Six P0/P1 bugs from the
post-beta.1 audit are fixed; the TCT verifier now caps `expires_at`
by the issuer Manifest's expiry; revocation is wired into the Mutual
Handshake; SoftFail enforces a real safe-grant subset; the Manifest
PoP signing input matches the spec's unified
`sha256(base64url_decode(x))` convention; and the responder's
grant_policy receives the verified peer identity instead of a
placeholder.

Breaking changes are confined to internal struct literals
(`PeerConfig`, `TctVerifyContext`, `RevocationFailMode::SoftFail`)
that any caller will have to update — the wire format is unchanged.

### Changed — breaking

- **`RevocationFailMode::SoftFail` now carries `safe_grants`** (BUG-4,
  P1 spec non-conformance). Pre-rc.1, `SoftFail` was identical in
  every observable way to `FailOpen` — both returned `Ok(false)` for
  `is_revoked` when the snapshot source failed, so a revoked TCT's
  issuer would still hand out the full grant set under degraded
  policy. RFC-AITP-0008 says SoftFail must reduce the grant set to a
  configured safe subset; SoftFail without a non-empty safe-grant
  list MUST behave as `FailClosed`.
  - `SoftFail` is now `SoftFail { safe_grants: Vec<String> }`. `Copy`
    is gone from `RevocationFailMode` and `RevocationPolicy`.
  - New `RevocationCache::check` returns `RevocationOutcome::{Clear,
    Revoked, SoftFailSafeSubset { safe_grants }}` so callers can
    branch on the degraded-policy result. Existing `is_revoked` is
    kept for handshake hooks that only need the bool.
  - New `apply_safe_subset(requested, safe_grants)` helper for the
    issuance site. Empty intersection is the caller's signal to
    surface `POLICY_VIOLATION`.

### Added — conformance

- **`aitp-rs-adapter` is now a library + binary**. The dispatch
  logic moved from `main.rs` into `lib.rs` so callers can drive the
  same dispatch in-process. The binary is a thin shell over
  `lib::handle`; behavior is unchanged.
- **In-process adapter at parity with the subprocess binary**.
  `aitp_conformance::adapter::in_process::InProcessRustAdapter` now
  delegates to `aitp_rs_adapter::handle`, so every Tier A/B/C/D op
  the subprocess supports is also reachable in-process. Pre-rc.1 the
  in-process adapter only spoke Tier A.
- **PoP challenge/response ops** (Phase 7, RFC-AITP-0005 §6).
  Adapter exposes `issue_pop_challenge`, `produce_pop_response`,
  `verify_pop_response`. State stashes pending challenges by JTI so
  multi-step fixtures (e.g. `tct-006`) can drive the full exchange
  without supplying a challenge to every step.
- **`verify_handshake_payload` adapter op**. Wires the op the spec's
  `id-*` and single-message `mh-*` fixtures dispatch to. Defaults to
  kat-keypair-001 when `self_aid` is omitted (the spec's mh-*
  convention).
- **OIDC mock-issuer demo**: `examples/two-agents/src/bin/oidc-demo.rs`
  drives a complete OIDC handshake against an in-process IdP that
  mints EdDSA-signed JWTs. Self-contained; no network required.
- **Sequence-fixture parsing** (runner). `FixtureInputVariant` now
  prefers `Sequence` over `Single` when both could match (untagged
  serde otherwise greedily picked Single, even for fixtures where
  `sequence` is the meaningful field). A new top-level
  `FixtureInput::operation` field captures fixtures like `env-004`
  that declare the op once at the parent level and rely on
  per-step inheritance.

### Added — security

- **`accepted_identity_types` pre-handshake screening** (BUG-6, P1
  spec compliance). RFC-AITP-0003 §3.2 / §5 step 5: a fetching peer
  MUST verify that its own identity type appears in the target
  Manifest's `accepted_identity_types` before initiating the
  handshake. Pre-rc.1 the check happened only inside the responder's
  HELLO handler, so a pinned-key initiator against an OIDC-only peer
  would round-trip several messages just to learn the peer rejects
  it. New `aitp_manifest::check_identity_type_compatibility` is wired
  into `aitp::facade::run_initiator_handshake` and surfaces as
  `ManifestError::IncompatibleIdentityType` →
  `INCOMPATIBLE_IDENTITY_TYPE`. New regression tests in
  `crates/aitp-manifest/tests/identity_type_compat.rs`.
- **TCT verifier enforces issuer-Manifest expiry bound** (BUG-5, P1
  spec gap). RFC-AITP-0004 §4.3 / RFC-AITP-0005 §9: a peer-issued TCT
  MUST NOT outlive its issuer's published Manifest, because the
  issuer's keys could legitimately rotate at that point. Issuance
  has always enforced this; pre-rc.1 the *verifier* couldn't because
  `TctVerifyContext` had no field for the bound. Added
  `TctVerifyContext::issuer_manifest_expires_at: Option<Timestamp>`
  and `TctError::ExpiresAfterManifest`. The handshake state machine
  captures the peer Manifest's `expires_at` from `MUTUAL_HELLO`
  (responder side) and `MUTUAL_HELLO_ACK` (initiator side) and feeds
  it through to `verify_received_tct`. Adapter maps the new error to
  the `TCT_EXPIRES_AFTER_MANIFEST` code. New regression tests in
  `crates/aitp-tct/tests/manifest_expiry_bound.rs`. Breaking:
  `TctVerifyContext` literal construction now requires the new
  field; callers without a known issuer Manifest pass `None`
  (RFC-AITP-0005 §9: MAY skip when unavailable).
- **Handshake-time revocation enforcement** (BUG-3, P0 security gap).
  `PeerConfig::revocation_check: Option<&RevocationCheckFn>` is a
  new optional hook called inside `verify_received_tct` for every
  peer-issued TCT (`MUTUAL_HELLO_ACK`'s and `MUTUAL_COMMIT_ACK`'s
  TCT). Pre-rc.1, the inner `verify_tct` was always passed
  `revocation_check: None`, so revoked TCTs slipped through the
  Mutual Handshake even when the caller had a fully wired
  `RevocationCache` available. The hook is called with
  `(issuer_aid, jti)` so per-issuer caches can route correctly; an
  `Err(HandshakeError)` from the hook propagates as-is to surface
  fail-closed policy when the revocation source is unreachable. New
  regression tests in `crates/aitp-handshake/tests/revocation_hook.rs`.

### Fixed — interoperability

- **Responder grant policy receives real peer identity** (BUG-2, P0
  policy bypass). `Responder::on_commit` previously synthesized a
  placeholder `IdentityDescriptor` (kind=PinnedKey, empty proof) when
  issuing the peer's TCT, so any policy that branched on `kind`,
  `issuer`, `subject`, or OIDC claims silently saw the wrong identity
  on the responder side. The verified `hello.identity` is now
  captured into `ResponderState::AwaitingCommit` and handed to
  `issue_tct_for_peer` — RFC-AITP-0004 §4.1 grant-policy symmetry is
  now correct on both peers. New regression test
  `responder_grant_policy_sees_real_pinned_key_identity` asserts the
  responder's policy sees the same descriptor the initiator
  presented.
- **Manifest PoP signing input** (BUG-1, P0 interop). Builder and
  verifier now use the unified RFC-AITP-0001 §5.4.2 signing-input
  convention `sha256(base64url_decode(challenge))`. Pre-fix, both
  sides hashed the ASCII bytes of the base64url-encoded challenge —
  internally consistent but rejected by any spec-conformant external
  verifier. New regression tests in
  `crates/aitp-manifest/tests/pop_kat.rs`: KAT-driven check against
  `kat-manifest-pop-001` from `jcs-sha256.json`, builder cross-path
  verification, and a legacy-form rejection guard. Pre-rc.1 minted
  Manifests will fail verification under rc.1 and must be re-minted
  with `cargo run -p mint-signed-examples`.
- **CI vendored-schemas drift job**. `actions/checkout@v4` defaulted
  to depth 1, so the pinned historical spec commit was unreachable
  and `git checkout <PIN>` failed with `unable to read tree`. Now
  reads `tests/schemas/SPEC_VERSION` first and passes it as `ref:`
  so checkout fetches the exact commit.
- **`docs` job rustdoc warning**. Removed broken intra-doc link
  `crate::client::RevocationFetcher` in `aitp-transport-http` (no
  such item; revocation fetching uses the `RevocationProvider`
  trait).
- **`demo_runs_end_to_end` and `full_pinned_key_handshake_over_http`
  TCT(Expired) flake**. Both call sites captured `cfg.now` at
  startup; on slow CI runners the peer-issued TCT's `issued_at`
  landed strictly after the stale `now` and the verifier rejected
  it as `Expired`. `PeerConfig` is now rebuilt with
  `Timestamp::now()` immediately before each `on_hello_ack` /
  `on_commit_ack`.

## [v0.1.0-beta.1]

Production-readiness release. Phases 10–16 of the unified hardening
plan: key-resolution policy, manifest-cache correctness, revocation
end-to-end, HTTP transport hardening, conformance-fixture expansion,
TCT renewal, and beta-gate validation. No breaking wire-format
changes vs alpha.5; the additions are layered on top.

### Added — production layer

- **Key resolution policy** (RFC-AITP-0007).
  `aitp_transport_http::KeyResolutionPolicy` composes a configurable
  `PinnedIssuerKeyStore` + `JwksFetcher` + in-memory cache into a
  single sync `JwksResolver`. Resolution order: cache → pinned
  issuer store → `/.well-known/aitp-keys` → OIDC JWKS. Three
  fail modes — `FailClosed` (default), `FailOpen`, `SoftFail`.
- **Manifest cache correctness**. `ManifestFetcher::cached`
  now returns `None` for expired entries (RFC-AITP-0003 §4.2);
  new `maybe_replace_inline` enforces newer-`published_at`-only
  replacement to defeat rollback attempts.
- **Revocation policy + HTTP endpoint** (RFC-AITP-0008 §1.5).
  `RevocationCache` + `RevocationPolicy { fail_mode,
  max_staleness_secs, cache_ttl_secs }`; `RevocationListProducer`
  trait wires `GET /.well-known/aitp-revocation-list` onto
  `HandshakeServer`. New `REVOCATION_LIST_URI_EXT` extension
  key for Manifest discovery.
- **HTTP transport hardening**. `ManifestFetcher` enforces
  Content-Type, oversize cap (`DEFAULT_MAX_MANIFEST_BYTES = 256 KB`),
  structured `UpstreamStatus`/`WrongContentType`/`OversizedResponse`
  errors. `HandshakeServer` now emits AITP error envelopes
  (`{"error": {"code": "...", "message": "..."}}`) keyed by
  `aitp_core::ErrorCode`. Boundary checks (Content-Type, body cap,
  timestamp tolerance, replay deny list) run before payload parsing.
- **TCT renewal** (RFC-AITP-0005 §10). New
  `aitp_tct::TctRenewalPayload` + `build_renewal_request` /
  `process_renewal_request`. `HandshakeServer` mounts
  `POST /aitp/handshake/renew`. Renewal flow: existing TCT +
  fresh PoP; issuer mints new JTI bounded by Manifest expiry.
- **High-level `aitp::facade`** (feature `http-client`). New
  `run_initiator_handshake(InitiatorConfig) -> SessionContext`
  drives the four-message handshake from a peer Manifest URL.
  `renew_tct(holder_key, current, endpoint) -> TctEnvelope`
  is the renewal one-liner.

### Added — conformance fixtures

Eight new negative-path fixtures pin the alpha.5 security work
across implementations:

- `id-005` — pinned-key legacy proof (pre-v0.1 two-field input)
- `id-006` — pinned-key proof bound to wrong `pop_nonce`
- `id-007` — pinned-key proof from key not in trust store
- `mh-009` — manifest type mismatch (`oidc` hint, `pinned_key` proof)
- `man-003` — expired Manifest must not be served from cache
- `tct-005` — TCT `expires_at` after issuer Manifest expiry
- `rev-001` — stale revocation snapshot, fail-closed
- `rev-002` — stale revocation snapshot, soft-fail
- `env-004` — replayed `message_id` rejected at envelope boundary

`tools/mint-conformance-fixtures` extended with mint logic for each.
Output is byte-stable across re-mints.

### Added — regression tests

`crates/aitp-handshake/tests/p1_p8_regressions.rs` pins six per-bug
regressions: P1 legacy proof, P1 wrong receiver, P1 wrong nonce,
P3 untrusted-key trust-store enforcement, P4 type mismatch,
P7 grant-policy plumbing.

### Test counts

214+ passing, 0 failed, 2 ignored (alpha.5 was 177; +37 from P10–P16
units + integrations + regressions). All gates clean: fmt, clippy
--all-features --all-targets -- -D warnings, build --release.

## [Released] — v0.1.0-alpha.5

Security + spec-compliance hardening release. Phases 1–9 of the
unified production-hardening plan: every P0 and P1 item is in. Two
breaking wire-format changes; six new spec-compliance enforcements;
one new transport-layer defense.

### ⚠️ Breaking wire-format changes vs alpha.4

- **Pinned-key identity proof format** (RFC-AITP-0002 §3.1).
  Previously signed `sha256("{message_id}|{timestamp}")` —
  vulnerable to cross-peer / cross-handshake replay. Now signs
  `sha256(b"aitp-pinned-key-v1\0" || sender_aid || \0 || receiver_aid
  || \0 || message_id || \0 || timestamp_be_8 || \0 ||
  base64url_decode(pop_nonce))`. Captured signatures are now bound to
  the full five-tuple. Any pinned-key proof minted by alpha.4 or
  earlier WILL fail to verify under alpha.5.
- **Handshake round-2 PoP signing input** (RFC-AITP-0004 §3).
  Previously `sha256(nonce.as_bytes())`. Now
  `sha256(base64url_decode(nonce))`, matching the TCT downstream PoP
  rule from spec rc.2. Aligns the handshake's two PoP paths with each
  other and the spec.

### Added — spec compliance + security

- **`PresentedIdentity` API refactor.** New
  `IdentityPresentationContext` carries the (sender, receiver,
  message_id, timestamp, pop_nonce) tuple to `build_descriptor`.
  `Initiator::start` now takes the peer's AID up-front (callers must
  fetch the peer's Manifest first).
- **`PinnedKeyStore` trust enforcement** (RFC-AITP-0002 §3.2 step 1).
  New trait + `StaticPinnedKeyStore`; `PeerConfig.pinned_key_store`
  is consulted before honoring any pinned-key identity. `None` keeps
  the legacy key-possession-only behavior for local dev.
- **Identity-type/hint match** (RFC-AITP-0004 §5.1). The verifier
  now rejects when `identity.kind ≠ manifest.identity_hint.kind`,
  closing a type-confusion bypass.
- **TCT expiry bounded by Manifest** (RFC-AITP-0004 §4.3).
  `issue_tct_for_peer` caps the issued TCT's `expires_at` at the
  issuing peer's Manifest expiry. Refuses to issue if the issuing
  Manifest is already expired.
- **Identity-aware grant policy** (RFC-AITP-0004 §4.1). New
  `PeerConfig.grant_policy: Option<&'a GrantPolicyFn>` lets
  deployments derive identity-based capability restrictions on top
  of the `peer_requested ∩ self.offered` intersection. Empty result
  → `PolicyViolation`.
- **Message-ID replay deny list on `HandshakeServer`**
  (RFC-AITP-0001 §5.5). Per-server `seen_message_ids` map with
  TTL-based eviction (default 5-minute window). Duplicate message_ids
  in the window are rejected with `REPLAY_DETECTED`.
  `with_session_ttl_and_replay_window` for tests.
- **JwksFetcher hardening** (RFC-AITP-0007 §2). HTTPS enforced for
  both discovery and the resolved `jwks_uri`. All redirects refused
  outright. Non-2xx responses surface as structured errors.
  Configurable timeout via `JwksFetcher::with_timeout`. On OIDC
  discovery failure, falls back to AITP-native
  `<issuer>/.well-known/aitp-keys`.

### Migration from alpha.4

Three things to re-do:

1. **Re-issue pinned-key identity proofs** — anything cached under
   alpha.4's two-field format will fail to verify
2. **Re-mint conformance fixtures** with the new pinned-key proof
   format: `cargo run -p mint-conformance-fixtures`
3. **Update `Initiator::start` callers** to pass the peer's AID
   (fetched from the peer's Manifest before the handshake begins)

`PinnedKeyStore` and `grant_policy` are both opt-in (`None` defaults
keep alpha.4 behavior). No action needed unless you want them.

### Test counts

177 passing, 0 failed, 2 ignored (alpha.4 was 171; +6 from the new
pinned-key proof regression tests). All gates clean: fmt, clippy
--all-features --all-targets -- -D warnings, doc --no-deps, build
--release, deny check.

### Still deferred (Phases 10-16 from the unified plan)

- **P10**: Key-resolution policy struct (RFC-AITP-0007 fail modes)
- **P11**: Manifest cache correctness (expiry-aware, inline-replace
  semantics)
- **P12**: Revocation policy + `/.well-known/aitp-revocation-list`
  HTTP endpoint
- **P13**: HTTP transport hardening (content-type, max body, error
  envelopes)
- **P14**: Conformance fixture expansion (negative-path fixtures
  for every bug fixed in P1-P8)
- **P15**: TCT renewal flow + high-level `aitp` facade driver
- **P16**: beta.1 release gates + per-bug regression tests

Carved out into a follow-up phase; this release cuts at the P0/P1
boundary.

## [Released] — v0.1.0-alpha.4

Spec rc.3 alignment + paired follow-up release. The spec rc.3 commit
landed `kat-keypair-003`, the `__VALID_SIG__` placeholder rename in
three fixtures, and the `aitp-revocation-list.schema.json` that was
missing despite RFC-AITP-0008 §1.5 already defining the wire shape.
This release implements the consumer side of all three.

### Added

- **`aitp-tct::revocation` module.** New types `RevocationList`,
  `RevocationListEnvelope`, `RevocationEntry`,
  `VerifyRevocationListContext`. New helpers
  `sign_revocation_list` and `verify_revocation_list`. Includes a
  KAT byte-match test that reproduces the spec rc.2
  `kat-revocation-001` canonical bytes byte-for-byte.
- **`verify_revocation_snapshot` op** wired in `aitp-rs-adapter`.
- **`tools/mint-signed-examples`.** New workspace member that mints
  cryptographically valid AITP example artifacts (Manifest, TCT,
  delegation token, signed revocation snapshot) from the spec's
  pinned KAT keypairs. Output goes to the spec repo's
  `signed-examples/` directory with `_kat_input` companions per the
  rc.2 README. Closes BLOCKED-SPEC-EXAMPLE
  (agentidentitytrustprotocol#5). Includes 4 cryptographic-verify
  tests over its own output.
- **KAT vector for `kat-keypair-003`.** Now exercised by the existing
  iteration-over-vectors structure in
  `crates/aitp-crypto/tests/kat.rs`.
- **`aitp-revocation-list.schema.json` schema test** in
  `crates/aitp-tct/tests/schema.rs` (2 cases: populated entries +
  empty entries snapshot).

### Changed

- **`tests/schemas/SPEC_VERSION`** advanced to spec commit
  `<rc.3 hash>`.
- **`unsupported_op_yields_skip` runner test** now uses
  `future_op_reserved_for_v0_2` as its canary (was
  `verify_revocation_snapshot`, which is now actually supported).

### Closed PENDING items

- `NOTE-VERIFY-REVOCATION-SNAPSHOT` — closed by the new
  `aitp-tct::revocation` module + adapter wiring.
- `BLOCKED-SPEC-EXAMPLE` (#5) — closed in spirit by
  `tools/mint-signed-examples`; spec PR populating the
  `signed-examples/` directory expected as the next paired action.

### Still deferred

- `PHASE-B-FIXTURE-PR` — migrating the 22 conformance fixtures from
  placeholders to fully-minted real values. Carved out as
  `plans/phase-11-fixture-migration.md`. Substantial focused work
  (4–8 hours) requiring per-placeholder substitution logic plus an
  OIDC mock issuer; deferred to keep alpha.4 scope coherent.

## [Released] — v0.1.0-alpha.3

RFC v0.1.0-rc.2 alignment release. Tracks spec commit
`c0e45653e8ac49e06747c8c289c28520a46b29e3`. Two breaking wire-format
changes; one new required field; first KAT-anchored interop validation.

### ⚠️ Breaking wire-format changes

- **TCT PoP signing input.** RFC-AITP-0005 §6.1+§6.2 (rc.2) pins the
  PoP signing input to `sha256(base64url_decode(nonce))` — the
  **decoded raw bytes** of the nonce, not its ASCII string form.
  alpha.1 and alpha.2 used the ASCII bytes. Any TCT PoP signature
  produced by an alpha.1 or alpha.2 holder will fail to verify under
  alpha.3, and vice versa. Affects `aitp-tct::sign_pop_response` and
  `aitp-tct::verify_pop_response`.
- **`grant_proof.issued_at` is now REQUIRED.** RFC-AITP-0006 §3.1
  (rc.2) added `issued_at` as a required wire field on `grant_proof`,
  copied verbatim from the source TCT. Verifiers use the carried
  value to reconstruct the source TCT signing input — the previous
  TTL-guessing reconstruction (`expires_at - DEFAULT_TCT_TTL_SECS`)
  is gone. Delegations issued by alpha.2 will fail to deserialize
  under alpha.3 (missing field) and vice versa. Affects
  `aitp-delegation::GrantProof`, `DelegationBuilder`,
  `verify_delegation`.

### Added

- **Spec KAT tests.** `crates/aitp-crypto/tests/kat.rs` validates
  Ed25519 seed→pubkey→AID derivation and JWK thumbprint computation
  against `tests/schemas/known-answer/{keypairs,jwk-thumbprints}.json`.
  `crates/aitp-core/tests/kat.rs` validates JCS canonicalization +
  SHA-256 against `tests/schemas/known-answer/jcs-sha256.json`. All
  pass byte-for-byte against the spec's pinned reference values.
- **`scripts/sync-schemas.sh`** now also vendors
  `schemas/conformance/known-answer/*.json` into
  `tests/schemas/known-answer/`.

### Changed

- **`tests/schemas/SPEC_VERSION`** advanced from spec commit
  `367567f…` to `c0e45653e8ac49e06747c8c289c28520a46b29e3`.

### Closed PENDING items

- `BLOCKED-SPEC-DELEGATION-ISSUEDAT` — closed by spec rc.2.
- `SPEC-POP-INPUT-AMBIGUITY` — closed by spec rc.2 (pinned to
  decoded bytes).
- `SPEC-005`, `SPEC-006`, `SPEC-007` — KAT vectors landed in spec rc.2;
  KAT tests in `aitp-rs` exercise them.

### Migration from alpha.2

Re-issue any persisted TCTs (PoP signatures are now bound to a
different hash input). Re-issue any persisted delegation tokens
(missing `grant_proof.issued_at`). Re-pull the vendored schemas
(`scripts/sync-schemas.sh`).

## [Released] — v0.1.0-alpha.2

Spec-alignment release. Tracks AITP spec v0.1.0-rc.1 with post-alpha.1
corrections.

### Added

- **Schema-validation drift firewall.** Vendored AITP JSON Schemas under
  `tests/schemas/` (pinned to spec commit via `tests/schemas/SPEC_VERSION`).
  Per-crate `tests/schema.rs` validates fully-populated wire types
  against the spec schemas: `aitp-manifest`, `aitp-tct`,
  `aitp-delegation`, and `aitp-handshake` (all four mutual-handshake
  payloads). New CI job `spec-schemas` fails if vendored schemas drift
  from the pinned spec commit.
- **Conformance Tier B/C/D** in `aitp-rs-adapter`. New supported ops:
  `verify_envelope`, `verify_delegation_token` (Tier A); `generate_keypair`,
  `issue_manifest`, `issue_tct`, `issue_delegation_token`, `sign_envelope`
  (Tier B); `start_handshake` (initiator role), `process_handshake_message`,
  `revoke_tct` (Tier C); `set_clock`, `inject_revocation`, `dump_session`
  (Tier D). Round-trip integration tests in
  `crates/aitp-conformance/tests/runner_integration.rs`.
- **Handshake session expiry.** `HandshakeServer` now takes a
  `session_ttl: Duration` (default 60s via `DEFAULT_SESSION_TTL`).
  Inline sweep on each request drops expired entries; expired sessions
  on commit return 400 `session expired`.
  `HandshakeServer::with_session_ttl(...)` for tests.

### Changed

- **`serde_jcs` 0.1 → 0.2.** Upstream fixed RFC 8785 §3.2.3 UTF-16
  code-unit ordering for object keys; the previously-ignored
  `jcs_surrogate_pair_ordering` test now passes.

### Removed

- **`Manifest.description`** field. Was carried in the Rust types
  (and the builder, signing view, verifier) but was never in
  RFC-AITP-0003 §3.1/§3.2 or `aitp-manifest.schema.json` (which sets
  `additionalProperties: false`). Setting it would have produced wire
  bytes that fail spec validation. Breaking change for any caller that
  set it; none expected in alpha.1. The new
  `rejects_legacy_description_field` round-trip test guards against it
  reappearing.

### Known limitations carried from alpha.1

- Multi-hop delegation (RFC-AITP-0011 reserved for v0.2)
- Session Trust Bundle (RFC-AITP-0010 reserved)
- OIDC `cnf.jkt` requires DPoP-aware identity provider; no token-exchange
  proxy ships with this release
- Conformance fixtures at `agentidentitytrustprotocol/schemas/conformance/`
  still use the legacy placeholder shape; spec-side migration PR pending
- Responder-side handshake conformance ops deferred to alpha.3
  (initiator-side covers the most useful test scenarios)
- `verify_revocation_snapshot` is intentionally not in the adapter's
  supported_ops; v0.1 has no spec-defined revocation snapshot type

## [Released] — v0.1.0-alpha.1

First implementation milestone for the AITP Rust reference implementation.
Tracks AITP spec v0.1.0-rc.1.

### Added — protocol crates

- **`aitp-core`** — `Aid`, `AitpEnvelope`, `Sender`, `MessageType`,
  `Timestamp`, `ExtensionsMap`, `AitpError`, `ErrorCode` (32 pinned wire
  strings), strict unpadded `base64url` codec, JCS canonicalization wrapper
  (24 standard vectors + 3 property tests), and the RFC-AITP-0001 §5.4
  envelope signing-input helper.
- **`aitp-crypto`** — `AitpSigningKey` (generate/from_seed/sign),
  `AitpVerifyingKey` (from_aid/from_bytes/`verify_strict`), `Signature::parse`
  with strict 86-char + base64url-charset + no-padding gates, JWK thumbprint
  per RFC-AITP-0002 §2.2.1.
- **`aitp-manifest`** — `ManifestBuilder` with required-field +
  identity-hint validation; `verify_manifest` running the five steps from
  RFC-AITP-0003 §5; `ManifestEnvelope` HTTP wrapper.
- **`aitp-tct`** — `TctBuilder` with `audience == subject` and non-empty
  grants enforced at issuance and verification; `verify_tct` covering the
  RFC-AITP-0005 §9 order; `PopChallenge` / `PopResponse` plus
  `sign_pop_response` / `verify_pop_response` for downstream PoP.
- **`aitp-delegation`** — `DelegationBuilder` reusing A's source-TCT
  signature verbatim; `verify_delegation` running the 11 RFC-AITP-0006 §4
  checks. Single-hop only; multi-hop reserved for v0.2.
- **`aitp-handshake`** — `Initiator` and `Responder` state machines;
  `bootstrap_verify_peer` running RFC-AITP-0004 §5.1 steps 3–6;
  `verify_oidc` with pluggable `JwksResolver` trait; `verify_pinned_key`
  per RFC-AITP-0002 §3.1; `INSUFFICIENT_GRANTS` enforcement against
  `required_peer_capabilities`. Full pinned-key handshake test where both
  peers end up holding each other's TCT.
- **`aitp-transport-http`** — `ManifestFetcher` with HTTPS-on-the-wire
  (HTTP allowed for `localhost`/`127.0.0.1` only), `JwksFetcher` doing
  OIDC discovery → JWKS resolution, `ManifestServer` and `HandshakeServer`
  axum routers with `X-Aitp-Session-Id` correlation.
- **`aitp` (facade)** — re-exports + a working `cargo test --doc` example.

### Added — tooling

- `examples/two-agents` — end-to-end demo on `localhost`. `make demo` runs
  the four-message handshake and exercises a `demo.echo` capability over
  HTTP.
- `aitp-conformance` — subprocess-based runner with a 30s per-request
  timeout, `--filter`/`--tag`/`--output {text|json|tap}` CLI surface,
  and integration tests against the real `aitp-rs-adapter` binary.
- `aitp-rs-adapter` — Tier-A op dispatcher: `init`, `shutdown`,
  `verify_jcs`, `compute_jwk_thumbprint`, `verify_manifest`, `verify_tct`.
- Workspace standards: `rust-toolchain.toml`, `rustfmt.toml`,
  `clippy.toml`, `.editorconfig`, `.gitignore`, GitHub Actions CI
  (fmt + clippy + matrix test + doc + cargo-deny + cargo-audit),
  Dependabot, PR/issue templates, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `Makefile`.

### Changed

- Bumped MSRV from 1.75 → 1.88. Transitive deps (`time`, `time-macros`,
  `icu_*`, `idna_adapter`, `clap_lex`) now require edition2024.
- Dropped `secrecy::Secret<DalekSigningKey>` wrapper. `ed25519_dalek::SigningKey`
  already implements `ZeroizeOnDrop`; the wrapper required a bound
  (`DefaultIsZeroes`) the type doesn't satisfy. Net effect: same
  zeroization behaviour, fewer dependencies.
- `AitpEnvelope.extensions` removed (envelope schema is
  `additionalProperties: false`).
- `Tct.evidence_ref`, `Tct.extensions`, `DelegationToken.extensions`,
  `MutualHello*Payload.extensions` all removed (schemas forbid them).
- `TctBinding.cnf` documentation corrected: it is the subject's raw
  32-byte Ed25519 pubkey in 43-char base64url, not the JWK thumbprint
  (RFC-AITP-0005 §1 schema, §6.2 step 4).
- `IdentityProof` tagged-enum scaffold replaced with the schema's
  flat `IdentityDescriptor` struct.
- Mutual-handshake commit/commit-ack payloads use the
  `tct_for_peer: { tct: { ... } }` wrapper per the schema.

### Known limitations

- **`BLOCKED-JCS-SURROGATE`** — `serde_jcs` 0.1 sorts object keys by
  UTF-8 byte order rather than UTF-16 code-unit order (RFC 8785 §3.2.3).
  One vector is `#[ignore]`'d. Affects only objects that mix astral and
  BMP characters with the specific code-unit-vs-byte ordering inversion.
- **`BLOCKED-SPEC-DELEGATION-ISSUEDAT`** — `grant_proof` doesn't carry
  the source TCT's `issued_at`, but A's `grant_proof.signature` covers
  it. The verifier reconstructs as `expires_at - 3600` (default TTL).
  Tokens minted with non-default TTLs would fail cross-impl until the
  spec adds the field or pins a recipe.
- **`BLOCKED-CONF-TIERBCD`** — Conformance Tier B (issuance), Tier C
  (stateful flows), Tier D (test-only) ops are not yet wired into
  `aitp-rs-adapter`. Deferred to v0.1.0-alpha.2.
- **`BLOCKED-SPEC-FIXTURE-MIGRATION`** — The spec's
  `schemas/conformance/*.json` fixtures predate the runner's
  `input.operation` shape; they all `FAIL` with `input.operation
  missing` until migrated.
- **Multi-hop delegation** — RFC-AITP-0011 reserved.
- **Session Trust Bundle** — RFC-AITP-0010 reserved.

## [0.1.0-alpha.0] — initial scaffold

Architectural skeleton; no runnable functionality.
