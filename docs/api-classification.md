# API classification

Every public struct and enum in the stable `aitp` surface (the types in
[`crates/aitp/public-api.stable.txt`](../crates/aitp/public-api.stable.txt))
is in one of three classes. The class says what a later release may add
to the type without a breaking change ([`STABILITY.md`](../STABILITY.md)).

| Class | What it means |
|---|---|
| `non_exhaustive` | `#[non_exhaustive]`. A release may add a field or a variant. Outside `aitp`, a `match` needs a wildcard arm and a struct is built with its constructor, not a literal; its public fields can still be read and set. |
| `private fields` | A struct with at least one private field. Callers build it with its constructor or builder, so a release may add a field. |
| `exhaustive` | Callers may match every variant or build the struct with a literal, so any new field or variant is a breaking change. Each one has a reason below. |

A type is exhaustive only for a reason that outweighs that cost: a
newtype whose one field is its value, a unit value, or a security
decision whose callers must handle each outcome deliberately rather than
through a wildcard arm.

[`scripts/api-classification.py`](../scripts/api-classification.py)
reads each type's class from the rustdoc JSON of `aitp` built with the
stable features. Each type is listed at its shortest public path. CI runs
`make api-classification-check`, which fails on a stable type missing
from the table, a type listed under the wrong class, or an exhaustive
type without a reason. After a type is added, removed or reclassified,
regenerate the table under [Types](#types) with `make api-classification`;
reasons already in the table are kept.

## Types

| Type | Kind | Class | Why exhaustive |
|---|---|---|---|
| `aitp::core::Aid` | struct | private fields |  |
| `aitp::core::AidAlgorithm` | enum | non_exhaustive |  |
| `aitp::core::AidParseError` | enum | non_exhaustive |  |
| `aitp::core::AitpEnvelope` | struct | non_exhaustive |  |
| `aitp::core::CheckedJson` | struct | private fields |  |
| `aitp::core::CheckedJsonError` | struct | private fields |  |
| `aitp::core::EnvelopeParseError` | enum | non_exhaustive |  |
| `aitp::core::EnvelopeStructureError` | enum | non_exhaustive |  |
| `aitp::core::ErrorCode` | enum | non_exhaustive |  |
| `aitp::core::ExtensionsMap` | struct | private fields |  |
| `aitp::core::InMemoryNonceStore` | struct | private fields |  |
| `aitp::core::MessageType` | enum | non_exhaustive |  |
| `aitp::core::RawUrl` | struct | private fields |  |
| `aitp::core::Sender` | struct | non_exhaustive |  |
| `aitp::core::Timestamp` | struct | exhaustive | A newtype over Unix seconds: its one field is the value. |
| `aitp::core::UnknownErrorCode` | struct | private fields |  |
| `aitp::core::base64url::Base64UrlError` | enum | non_exhaustive |  |
| `aitp::core::ids::InvalidTag` | struct | non_exhaustive |  |
| `aitp::core::ids::V4Error` | enum | non_exhaustive |  |
| `aitp::core::jcs::JcsError` | enum | non_exhaustive |  |
| `aitp::core::nonce_store::ConsumeOutcome` | enum | non_exhaustive |  |
| `aitp::core::nonce_store::IssuedNonce` | struct | non_exhaustive |  |
| `aitp::core::nonce_store::NonceStoreError` | enum | non_exhaustive |  |
| `aitp::crypto::AitpSigningKey` | struct | private fields |  |
| `aitp::crypto::AitpVerifyingKey` | struct | private fields |  |
| `aitp::crypto::BackendSignature` | enum | non_exhaustive |  |
| `aitp::crypto::BlockingSigner` | struct | exhaustive | A newtype adapter: its one field is the wrapped signer. |
| `aitp::crypto::CryptoError` | enum | non_exhaustive |  |
| `aitp::crypto::Digest32` | struct | private fields |  |
| `aitp::crypto::SignRequest` | enum | non_exhaustive |  |
| `aitp::crypto::Signature` | struct | private fields |  |
| `aitp::crypto::SignatureAlgorithm` | enum | non_exhaustive |  |
| `aitp::crypto::SignerError` | enum | non_exhaustive |  |
| `aitp::delegation::DelegationBuilder` | struct | private fields |  |
| `aitp::delegation::DelegationClaims` | struct | non_exhaustive |  |
| `aitp::delegation::DelegationError` | enum | non_exhaustive |  |
| `aitp::delegation::VerifiedDelegation` | struct | private fields |  |
| `aitp::delegation::VerifiedDelegationParts` | struct | non_exhaustive |  |
| `aitp::delegation::VerifyDelegationContext` | struct | non_exhaustive |  |
| `aitp::envelope::EnvelopeError` | enum | non_exhaustive |  |
| `aitp::facade::FacadeError` | enum | non_exhaustive |  |
| `aitp::facade::IdentityMode` | enum | non_exhaustive |  |
| `aitp::facade::InitiatorConfig` | struct | non_exhaustive |  |
| `aitp::facade::SessionContext` | struct | private fields |  |
| `aitp::facade::SessionContextParts` | struct | non_exhaustive |  |
| `aitp::facade::TctStore` | struct | private fields |  |
| `aitp::facade::TrustMode` | enum | non_exhaustive |  |
| `aitp::handshake::CompletedHandshake` | struct | private fields |  |
| `aitp::handshake::CompletedHandshakeParts` | struct | non_exhaustive |  |
| `aitp::handshake::GrantPolicyContext` | struct | non_exhaustive |  |
| `aitp::handshake::GrantPolicyError` | struct | private fields |  |
| `aitp::handshake::HandshakeError` | enum | non_exhaustive |  |
| `aitp::handshake::IdentityDescriptor` | struct | non_exhaustive |  |
| `aitp::handshake::IdentityKind` | enum | non_exhaustive |  |
| `aitp::handshake::IdentityVerifyContext` | struct | non_exhaustive |  |
| `aitp::handshake::IdentityVerifyError` | enum | non_exhaustive |  |
| `aitp::handshake::Initiator` | struct | private fields |  |
| `aitp::handshake::JwkKeyMaterial` | enum | non_exhaustive |  |
| `aitp::handshake::JwkParseError` | enum | non_exhaustive |  |
| `aitp::handshake::JwkPublicKey` | struct | non_exhaustive |  |
| `aitp::handshake::JwsAlgorithm` | enum | non_exhaustive |  |
| `aitp::handshake::JwsVerifyError` | enum | non_exhaustive |  |
| `aitp::handshake::MutualCommitAckPayload` | struct | non_exhaustive |  |
| `aitp::handshake::MutualCommitPayload` | struct | non_exhaustive |  |
| `aitp::handshake::MutualHelloAckPayload` | struct | non_exhaustive |  |
| `aitp::handshake::MutualHelloPayload` | struct | non_exhaustive |  |
| `aitp::handshake::NoPinnedKeys` | struct | exhaustive | A unit value callers write as `NoPinnedKeys`. |
| `aitp::handshake::OidcMintError` | struct | private fields |  |
| `aitp::handshake::OidcVerifyContext` | struct | non_exhaustive |  |
| `aitp::handshake::PeerConfig` | struct | non_exhaustive |  |
| `aitp::handshake::PinnedKeyEntry` | struct | non_exhaustive |  |
| `aitp::handshake::PinnedKeyEntryError` | enum | non_exhaustive |  |
| `aitp::handshake::PinnedKeyVerifyContext` | struct | non_exhaustive |  |
| `aitp::handshake::PresentedIdentity` | enum | non_exhaustive |  |
| `aitp::handshake::ResolveError` | enum | non_exhaustive |  |
| `aitp::handshake::Responder` | struct | private fields |  |
| `aitp::handshake::StaticPinnedKeyStore` | struct | private fields |  |
| `aitp::handshake::SubjectBinding` | enum | non_exhaustive |  |
| `aitp::handshake::VerifiedIdentity` | struct | private fields |  |
| `aitp::handshake::VerifiedPinnedKey` | struct | private fields |  |
| `aitp::handshake::VerifiedPinnedKeyParts` | struct | non_exhaustive |  |
| `aitp::handshake::admission::AdmissionChallenge` | struct | non_exhaustive |  |
| `aitp::handshake::admission::AdmissionError` | enum | non_exhaustive |  |
| `aitp::handshake::admission::Admitted` | struct | private fields |  |
| `aitp::handshake::admission::AdmittedParts` | struct | non_exhaustive |  |
| `aitp::handshake::admission::ChallengeSource` | struct | private fields |  |
| `aitp::handshake::admission::DenyListError` | enum | non_exhaustive |  |
| `aitp::handshake::admission::IdentityPresentationPayload` | struct | non_exhaustive |  |
| `aitp::handshake::admission::InMemoryMessageIdDenyList` | struct | private fields |  |
| `aitp::handshake::admission::PinnedAdmission` | struct | private fields |  |
| `aitp::handshake::admission::PinnedAdmissionBuilder` | struct | private fields |  |
| `aitp::handshake::admission::RecommendedLimiter` | struct | private fields |  |
| `aitp::handshake::admission::RefusalCause` | enum | non_exhaustive |  |
| `aitp::handshake::admission::TokenBucketLimiter` | struct | private fields |  |
| `aitp::handshake::admission::TransportId` | enum | non_exhaustive |  |
| `aitp::manifest::IdentityHint` | struct | non_exhaustive |  |
| `aitp::manifest::IdentityHintKind` | enum | non_exhaustive |  |
| `aitp::manifest::Manifest` | struct | non_exhaustive |  |
| `aitp::manifest::ManifestBuilder` | struct | private fields |  |
| `aitp::manifest::ManifestEnvelope` | struct | non_exhaustive |  |
| `aitp::manifest::ManifestError` | enum | non_exhaustive |  |
| `aitp::manifest::ManifestPop` | struct | non_exhaustive |  |
| `aitp::manifest::VerifiedManifest` | struct | private fields |  |
| `aitp::manifest::VerifyManifestContext` | struct | non_exhaustive |  |
| `aitp::tct::AttestationVerifyContext` | struct | non_exhaustive |  |
| `aitp::tct::AttestationVerifyContextBuilder` | struct | private fields |  |
| `aitp::tct::Cnf` | struct | non_exhaustive |  |
| `aitp::tct::GrantVoucherClaims` | struct | non_exhaustive |  |
| `aitp::tct::IssuedTct` | struct | non_exhaustive |  |
| `aitp::tct::PopChallenge` | struct | non_exhaustive |  |
| `aitp::tct::PopResponse` | struct | non_exhaustive |  |
| `aitp::tct::RevocationEntry` | struct | non_exhaustive |  |
| `aitp::tct::RevocationList` | struct | non_exhaustive |  |
| `aitp::tct::RevocationListEnvelope` | struct | non_exhaustive |  |
| `aitp::tct::RevocationQuery` | struct | non_exhaustive |  |
| `aitp::tct::RevocationSource` | enum | non_exhaustive |  |
| `aitp::tct::RevocationStatus` | enum | exhaustive | A security decision: a new outcome must break callers' matches, so none is handled by a wildcard arm. |
| `aitp::tct::RevocationUnavailable` | struct | private fields |  |
| `aitp::tct::TctBuilder` | struct | private fields |  |
| `aitp::tct::TctClaims` | struct | non_exhaustive |  |
| `aitp::tct::TctError` | enum | non_exhaustive |  |
| `aitp::tct::TctVerifyContext` | struct | non_exhaustive |  |
| `aitp::tct::TctVerifyContextBuilder` | struct | private fields |  |
| `aitp::tct::TctVerifyContextError` | enum | non_exhaustive |  |
| `aitp::tct::VerifiedAttestation` | struct | private fields |  |
| `aitp::tct::VerifiedAttestationParts` | struct | non_exhaustive |  |
| `aitp::tct::VerifiedTct` | struct | private fields |  |
| `aitp::tct::VerifiedTctParts` | struct | non_exhaustive |  |
| `aitp::tct::VerifyRevocationListContext` | struct | non_exhaustive |  |
| `aitp::transport::ClientConfig` | struct | private fields |  |
| `aitp::transport::FetchError` | enum | non_exhaustive |  |
| `aitp::transport::GuardMode` | enum | non_exhaustive |  |
| `aitp::transport::HandshakeServer` | struct | private fields |  |
| `aitp::transport::HostGuard` | struct | private fields |  |
| `aitp::transport::HostGuardError` | enum | non_exhaustive |  |
| `aitp::transport::InMemoryReplayGuard` | struct | private fields |  |
| `aitp::transport::JwksFetcher` | struct | private fields |  |
| `aitp::transport::JwksFetcherError` | enum | non_exhaustive |  |
| `aitp::transport::KeyResolutionFailMode` | enum | non_exhaustive |  |
| `aitp::transport::KeyResolutionOutcome` | enum | exhaustive | A security decision: a new outcome must break callers' matches, so none is handled by a wildcard arm. |
| `aitp::transport::KeyResolutionPolicy` | struct | private fields |  |
| `aitp::transport::KeyResolutionPolicyBuilder` | struct | private fields |  |
| `aitp::transport::ManifestFetcher` | struct | private fields |  |
| `aitp::transport::ManifestServer` | struct | private fields |  |
| `aitp::transport::PreparedRevocation` | struct | private fields |  |
| `aitp::transport::RateLimitConfig` | struct | non_exhaustive |  |
| `aitp::transport::RetryPolicy` | struct | private fields |  |
| `aitp::transport::RevocationError` | enum | non_exhaustive |  |
| `aitp::transport::RevocationFailMode` | enum | non_exhaustive |  |
| `aitp::transport::RevocationFetcher` | struct | private fields |  |
| `aitp::transport::RevocationPolicy` | struct | non_exhaustive |  |
| `aitp::transport::ServeConfig` | struct | non_exhaustive |  |
| `aitp::transport::StaticPinnedIssuerKeyStore` | struct | private fields |  |
| `aitp::transport::TrustedProxy` | struct | private fields |  |
| `aitp::transport::TrustedProxyParseError` | struct | private fields |  |
| `aitp::transport::revocation::EmptyRevocationProvider` | struct | private fields |  |
