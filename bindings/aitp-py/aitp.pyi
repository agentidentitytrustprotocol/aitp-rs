# Type stubs for the `aitp` Python SDK (`bindings/aitp-py`).
#
# Hand-maintained because the underlying extension is built by PyO3 / maturin
# and does not auto-generate stubs. Edit when the binding's public surface
# changes; the symmetry oracle is the auto-generated `bindings/aitp-node/
# index.d.ts` — every type here SHOULD have a camelCase counterpart there
# (and vice versa), per CLAUDE.md's binding-symmetry rule.

from typing import Callable, Literal, Optional, Sequence, Union

from typing_extensions import deprecated

# Revoked-`jti` deny lists. The binding extracts these into a Rust
# `HashSet<str>`, which accepts only a `set` or `frozenset` — not an
# arbitrary `AbstractSet` (e.g. `dict.keys()`) and not a `list`.
# Entries are lookup keys and are normalized: any RFC 9562 text form
# (uppercase, braced, `urn:uuid:`, unhyphenated) matches the canonical
# `jti`. An entry that is not a UUID raises `ValueError` (#272).
RevokedJtis = Union[set[str], frozenset[str]]
# Revocation policy (RFC-AITP-0008 §3.1). `None` means "fail_closed": with no
# `revoked_jtis` every check fails with `.code` TCT_REVOKED (or
# DELEGATION_SOURCE_TCT_REVOKED). "fail_open" skips revocation entirely.
Revocation = Literal["fail_closed", "fail_open"]
# `(challenge_json, response_json)`: a downstream PoP exchange
# (RFC-AITP-0005 §6) for `AitpAgent.verify_tct(..., pop=...)`.
PopExchange = tuple[str, str]

REVOCATION_LIST_PATH: str
"""Conventional path of an agent's `ListRevoked` endpoint
(`/.well-known/aitp-revocation-list`). The Manifest still carries an
explicit absolute URL: `build_manifest(revocation_list_uri=...)`."""

# ── Core handshake surface ──────────────────────────────────────────────


class TctIdentity:
    """Verified peer identity carried by a TCT."""

    peer_aid: str
    grants: list[str]
    expires_at: int  # unix seconds
    jti: str  # UUID string

class TctStore:
    """Bounded in-memory cache of successful TCT verifications, keyed by the
    SHA-256 of the exact TCT compact-JWS bytes. Lets a high-throughput verifier
    skip the signature check when it re-sees a byte-identical, still-valid TCT.
    Cheap policy checks (expiry, audience, grant, revocation) still run on
    every hit."""

    def __init__(self, max_entries: int) -> None: ...
    def len(self) -> int: ...
    def clear(self) -> None: ...

class DelegationVerified:
    """Verified delegation token (RFC-AITP-0006)."""

    delegator: str
    delegatee: str
    issued_by: str
    grants: list[str]
    expires_at: int
    cnf_jkt: str  # RFC 7638 JWK thumbprint (cnf.jkt) of the delegatee's key
    @property
    @deprecated("DelegationVerified.cnf is deprecated; use cnf_jkt")
    def cnf(self) -> str:
        """Deprecated alias for `cnf_jkt`. Reading it emits a
        `DeprecationWarning`."""

class InitiatorSession:
    """Outbound handshake session. Construct via `AitpAgent.new_session`."""

    def build_hello(
        self,
        peer_manifest_json: str,
        requested_grants: list[str],
        oidc_mint_jwt: Optional[Callable[[str], str]] = ...,
    ) -> str: ...
    def process_hello_ack(self, hello_ack_json: str, session_id: str) -> str: ...
    def complete(
        self,
        commit_ack_json: str,
        revoked_jtis: Optional[RevokedJtis] = ...,
        revocation: Optional[Revocation] = ...,
    ) -> str:
        """Returns a JSON object string
        `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`:
        the TCT the peer issued to us plus the companion grant voucher.

        The peer's TCT is checked against `revoked_jtis` (the peer's deny
        list). Revocation is fail_closed: with no list the handshake fails
        with `.code == "TCT_REVOKED"`. Pass an empty set when nothing is
        revoked, or `revocation="fail_open"` to skip the check."""
        ...

class ResponderSession:
    """Inbound handshake session. Construct via `AitpAgent.new_responder`."""

    def process_hello(
        self,
        hello_json: str,
        oidc_mint_jwt: Optional[Callable[[str], str]] = ...,
    ) -> tuple[str, str]: ...
    def process_commit(
        self,
        commit_json: str,
        revoked_jtis: Optional[RevokedJtis] = ...,
        revocation: Optional[Revocation] = ...,
    ) -> tuple[str, str]:
        """Returns `(commit_ack_json, completed_json)` where `completed_json`
        is `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`
        — the TCT the initiator issued to us (the responder) plus its
        companion grant voucher. The TCT we issued to the initiator travels
        inside `commit_ack_json`. `revoked_jtis` and `revocation` are as in
        `InitiatorSession.complete` (fail_closed)."""
        ...

# ── OIDC identity (RFC-AITP-0002) ───────────────────────────────────────

class JwksProvider:
    """In-memory issuer URL → list of JWK dicts. The SDK does no HTTP;
    callers fetch the JWKS themselves and hand the parsed dicts in."""

    def __init__(self, keys: Optional[dict[str, list[dict]]] = ...) -> None: ...
    def upsert(self, issuer: str, keys: list[dict]) -> None: ...
    def remove(self, issuer: str) -> None: ...
    def issuers(self) -> list[str]: ...

# ── Agent ───────────────────────────────────────────────────────────────

class AitpAgent:
    """An AITP agent: a signing key + (once built) its published Manifest."""

    @property
    def aid(self) -> str: ...
    @staticmethod
    def generate(suite: Literal["ed25519", "p256"] = "ed25519") -> "AitpAgent": ...
    @staticmethod
    def from_seed(
        seed: bytes, suite: Literal["ed25519", "p256"] = "ed25519"
    ) -> "AitpAgent": ...
    def build_manifest(
        self,
        display_name: str,
        handshake_endpoint: str,
        offered_caps: list[str],
        required_caps: Optional[list[str]] = ...,
        ttl_secs: Optional[int] = ...,
        identity_type: Literal["pinned_key", "oidc"] = "pinned_key",
        oidc_issuer: Optional[str] = ...,
        oidc_subject: Optional[str] = ...,
        accepted_trust_anchors: Optional[list[str]] = ...,
        revocation_list_uri: Optional[str] = None,
        accepted_identity_types: Optional[list[str]] = None,
    ) -> str:
        """Build and sign this agent's Manifest; returns the envelope JSON.

        `accepted_identity_types` lists the peer identity types this agent
        accepts (RFC-AITP-0004 §5.1 step 8): a peer presenting any other
        type fails with `INCOMPATIBLE_IDENTITY_TYPE`. It defaults to
        `[identity_type]`, so a pinned-key agent talking to an OIDC peer
        must pass `["pinned_key", "oidc"]`. `[]` accepts nothing.

        `revocation_list_uri` advertises this agent's `ListRevoked` URL as
        `rfc-aitp-0008.revocation_list_uri` in the signed Manifest. Every
        agent that issues TCTs MUST set it (RFC-AITP-0005 §11,
        RFC-AITP-0008 §1.4): without it a `fail_closed` verifier that
        discovers lists through the Manifest rejects this agent's TCTs as
        `TCT_REVOKED`. Pass an absolute HTTPS URL, conventionally the
        agent's origin plus `REVOCATION_LIST_PATH`."""
        ...
    def new_session(
        self,
        jwks: Optional[JwksProvider] = ...,
        trust_anchors: Optional[list[str]] = ...,
        pinned_keys: Optional[list[str]] = None,
    ) -> InitiatorSession:
        """Create an outbound handshake session.

        `pinned_keys` is the local pinned-key trust store (RFC-AITP-0002
        §3.2): peer AID strings (Ed25519 or P-256). A peer presenting a
        `pinned_key` identity is accepted only if its AID is listed; the
        check runs before the proof. `None` or `[]` trusts no pinned key,
        so EVERY `pinned_key` peer is rejected (fail closed). An invalid
        AID entry raises `ValueError`. Since 0.14 there is no
        possession-only mode: pass the peer's AID (e.g. `[peer.aid]`)."""
        ...
    def new_responder(
        self,
        jwks: Optional[JwksProvider] = ...,
        trust_anchors: Optional[list[str]] = ...,
        pinned_keys: Optional[list[str]] = None,
    ) -> ResponderSession:
        """Create an inbound handshake session. `pinned_keys` as in
        `new_session`: `None` ⇒ every `pinned_key` initiator is rejected."""
        ...
    def verify_tct(
        self,
        tct_token: str,
        required_grant: str,
        expected_audience: Optional[str] = ...,
        revoked_jtis: Optional[RevokedJtis] = ...,
        revocation: Optional[Revocation] = ...,
        pop: Optional[PopExchange] = ...,
    ) -> TctIdentity:
        """Verify a TCT compact-JWS string. `expected_audience` defaults to
        this agent's AID (holder-receipt model).

        A resource server verifying a presented TCT passes
        `pop=(challenge_json, response_json)`: the challenge from
        `new_pop_challenge` and the holder's `sign_pop_response` reply. The
        TCT and every RFC-AITP-0005 §6.2 step are verified together, and the
        audience is pinned to the proven holder AID (`sub`). A PoP failure
        raises `RuntimeError` with `.code` `POP_CHALLENGE_INVALID` or
        `POP_RESPONSE_INVALID`. `pop` excludes `expected_audience`. Without
        `pop`, a presented TCT's `expected_audience` MUST come from an
        authenticated source (a verified PoP response or an equivalent channel
        binding), never from the token's own `aud`.

        `revoked_jtis` is the issuer's
        deny list of revoked TCT `jti` strings (RFC-AITP-0008): a TCT whose
        jti is in it is rejected after its signature checks pass. Revocation
        is fail_closed: without `revoked_jtis` every TCT is rejected. Both
        failures raise `RuntimeError` with `.code == "TCT_REVOKED"`. Pass an
        empty set when nothing is revoked, or `revocation="fail_open"` to
        skip the check. Entries are normalized (any RFC 9562 text form
        matches); one that is not a UUID raises `ValueError`."""
        ...
    def verify_tct_cached(
        self,
        tct_token: str,
        required_grant: str,
        store: TctStore,
        expected_audience: Optional[str] = ...,
        revoked_jtis: Optional[RevokedJtis] = ...,
        revocation: Optional[Revocation] = ...,
        pop: Optional[PopExchange] = ...,
    ) -> TctIdentity:
        """Like `verify_tct` but consults `store` first. Revocation
        (`revoked_jtis`, fail_closed) and `pop` are re-checked on every call,
        cache hits included."""
        ...
    def new_pop_challenge(self, tct_token: str, ttl_secs: int = 60) -> str:
        """Consumer side of downstream PoP (RFC-AITP-0005 §6.1): a
        `pop_challenge` payload JSON (`tct_jti`, `nonce`, `expires_at`) for a
        presented TCT. The nonce is 128 CSPRNG bits. Keep the challenge to
        verify the response, and accept each challenge's response at most
        once (RFC-AITP-0001 §5.5): the SDK keeps no nonce cache."""
        ...
    def sign_pop_response(self, challenge_json: str) -> str:
        """Holder side of downstream PoP (RFC-AITP-0005 §6.1): sign a
        received challenge over sha256 of the *decoded* nonce bytes. Returns
        the `pop_response` payload JSON. A malformed or expired challenge
        raises with `.code == "POP_CHALLENGE_INVALID"`."""
        ...
    def build_delegation(
        self,
        voucher_token: str,
        delegatee_aid: str,
        scope: list[str],
        ttl_secs: Optional[int] = ...,
    ) -> str:
        """Build a single-hop delegation token (compact JWS) from a held grant
        voucher. `voucher_token` is the `grant_voucher` from a `complete()` /
        `process_commit()` result; its `sub` MUST equal this agent's AID. The
        delegatee's key binding is derived from its AID."""
        ...
    def issue_tct_for_delegatee(
        self,
        verified: DelegationVerified,
        ttl_secs: Optional[int] = ...,
    ) -> str:
        """Mint a fresh TCT for a verified delegatee. Returns a JSON object
        string `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" |
        null}`."""
        ...
    def sign_envelope(
        self,
        message_type: str,
        payload_json: str,
        extensions_json: Optional[str] = ...,
        message_id: Optional[str] = ...,
        timestamp: Optional[int] = ...,
    ) -> str:
        """Sign an `AitpEnvelope` from this agent (RFC-AITP-0001 §5.4,
        `aitp/0.3` signing input v2) and return its JSON.

        `message_type` is the wire string (e.g. `"mutual_hello"`),
        `payload_json` a JSON object, `extensions_json` an optional JSON
        object for the `extensions` member (signed like every other member).
        `message_id` defaults to a fresh UUID v4; a supplied one must be the
        lowercase hyphenated v4 wire form (uppercase, braced, `urn:uuid:`,
        unhyphenated and non-v4 forms raise `ValueError`, not normalized).
        `timestamp` (unix seconds) defaults to now. Raises `ValueError` on
        bad input. The counterpart
        of `verify_envelope`."""
        ...
    def sign_revocation_list(
        self,
        entries: list[dict],
        expires_in_secs: Optional[int] = ...,
    ) -> str: ...

# ── Free functions ──────────────────────────────────────────────────────

def verify_delegation(
    delegation_token: str,
    verifier_aid: str,
    issuer_manifests: Sequence[str],
    revoked_jtis: Optional[RevokedJtis] = None,
    revocation: Optional[Revocation] = None,
) -> DelegationVerified:
    """Verify a delegation token (compact-JWS string) under strict AITP v0.3
    (RFC-AITP-0006 single-hop). A token carrying a non-empty `chain`
    (RFC-AITP-0011 multi-hop) is rejected with
    `DELEGATION_MULTIHOP_NOT_SUPPORTED`.

    `issuer_manifests` holds the delegator's Manifest, each entry a
    `{"manifest": {...}}` envelope JSON string. The token is verified under
    the key resolved from its issuer's verified Manifest (RFC-AITP-0006 §4
    step 1); an issuer with no valid Manifest in the list fails with
    `KEY_RESOLUTION_FAILED`. Malformed JSON raises `ValueError`.

    `revoked_jtis` is the verifier's own deny list. A token whose
    `voucher.src_jti` is in the set is rejected after every signature check
    passes (RFC-AITP-0006 §4 step 7, ordered per RFC-AITP-0008 §3.3).
    Revocation is fail_closed: **without `revoked_jtis` every token is
    rejected**. Both failures raise `RuntimeError` with
    `.code == "DELEGATION_SOURCE_TCT_REVOKED"`. Pass an empty set when
    nothing is revoked, or `revocation="fail_open"` to skip the check.
    Entries are normalized (any RFC 9562 text form matches); one that is not
    a UUID raises `ValueError`."""
    ...

class ManifestVerificationError(RuntimeError):
    """A manifest envelope failed verification.

    `code` is the stable, machine-readable cause — one of
    `signature_invalid`, `pop_failed`, `aid_mismatch`, `expired`,
    `version_unknown`, `identity_hint_malformed`,
    `incompatible_identity_type`, `unknown_field`, `malformed`. **Branch on
    `code`, never on the message text.**

    Inherits `RuntimeError`, which is what this function raised before it was
    typed — adding a machine-readable cause does not break a caller that was
    already handling the failure."""

    code: str

def verify_manifest_json(
    manifest_envelope_json: str,
    now_unix_secs: Optional[int] = ...,
) -> None:
    """Verify a `ManifestEnvelope` JSON. Raises on failure.

    Raises `ManifestVerificationError` (with `.code`) when the envelope does
    not verify, and `ValueError` when it is not parseable as a manifest at
    all — that second one is the caller handing us the wrong bytes, not a
    peer failing verification. A duplicate JSON key anywhere
    (RFC-AITP-0001 §5.4.5) raises `ValueError`; a member outside the schema
    (RFC-AITP-0001 §7) raises `ManifestVerificationError` with
    `code == "unknown_field"`.

    `now_unix_secs` overrides the verification clock — omit it to use the
    system clock, or pass a pinned value in tests. Matches
    `verify_revocation_list`'s `now_unix_secs` parameter."""
    ...

class RevocationVerificationError(RuntimeError):
    """A revocation snapshot failed verification.

    `code` is the stable, machine-readable cause — one of
    `signature_invalid`, `issuer_mismatch`, `version_unknown`, `expired`,
    `unknown_field`, `malformed`. A duplicate JSON key (RFC-AITP-0001 §5.4.5)
    is `malformed`; a member outside the schema (RFC-AITP-0001 §7) is
    `unknown_field`. **Branch on `code`, never on the message text**: matching an
    exception message pins program output as an expected value, which is the
    bug class the 0.5.0 signing-input change exposed. Before 0.6.0 there was
    no typed error here at all, so message-matching was the only option."""

    code: str

def verify_revocation_list(
    envelope_json: str,
    expected_issuer_aid: str,
    now_unix_secs: Optional[int] = ...,
) -> None:
    """Verify a `RevocationListEnvelope` against a pinned issuer.

    Returns `None` on success; raises `RevocationVerificationError` (with
    `.code`) otherwise. Raises `ValueError` if `expected_issuer_aid` is not a
    valid AID — that is the caller's mistake, not the snapshot's.

    Establishes **authenticity and non-expiry only**: the snapshot was signed
    by the holder of `expected_issuer_aid`, and its `expires_at` has not
    passed. It deliberately does NOT check `published_at` staleness —
    RFC-AITP-0008 §3 puts freshness policy at the consuming peer, and
    collapsing authenticity and freshness into one switch is how a `soft_fail`
    mode ends up reporting a *forged* snapshot as not-revoked. The staleness
    budget is yours; `published_at` is on the body for that purpose.

    Verification without a pinned expected issuer would be near-worthless —
    any key can sign a list — which is why the AID is required, not optional."""
    ...

class EnvelopeVerificationError(RuntimeError):
    """An AITP envelope failed verification.

    `code` is the registered RFC-AITP-0001 §5.7 error code of the first
    failing step of the §5.4 check order — one of `UNKNOWN_VERSION`,
    `UNKNOWN_FIELD`, `INVALID_ENVELOPE`, `INVALID_SIGNATURE`. **Branch on
    `code`, never on the message text.**"""

    code: str

def verify_envelope(envelope_json: str, expected_sender_aid: str) -> None:
    """Verify an `AitpEnvelope` JSON string sent by `expected_sender_aid`.

    Returns `None` on success; raises `EnvelopeVerificationError` with the
    code of the first failing RFC-AITP-0001 §5.4 step: `version` absent or
    not `aitp/0.3` → `UNKNOWN_VERSION`; a member outside the schema and
    outside `extensions` → `UNKNOWN_FIELD`; any other structural defect
    (duplicate key, missing member, unregistered `message_type`, non-v4
    `message_id`, non-object `payload`, negative `timestamp`, `signature`
    outside the schema pattern) → `INVALID_ENVELOPE`; a signature that does
    not verify over signing input v2 under the expected sender's key, or a
    `sender.agent_id` other than `expected_sender_aid` → `INVALID_SIGNATURE`.
    Raises
    `ValueError` if `expected_sender_aid` is not a valid AID.

    The key comes from `expected_sender_aid` (an AID encodes its public key).
    Establishes **authenticity and structure only**: replay and freshness
    (RFC-AITP-0001 §5.5 — timestamp window, `message_id` deduplication) are
    the receiving endpoint's job in the RFC-AITP-0009 §3.1 order and are not
    checked here."""
    ...

def revocation_signing_bytes(envelope_json: str) -> bytes:
    """The exact bytes a revocation snapshot's signature is computed over:
    `JCS(revocation_list)` — the **inner** body, not the `{"revocation_list":
    ...}` transport wrapper.

    Exposed so a caller needing the signed bytes (an independent verifier, an
    HSM signing path, a debugging tool) obtains them instead of reconstructing
    the shape at the call site. Reconstructing it is exactly how signer,
    verifier and conformance fixture drifted apart before 0.5.0."""
    ...

def verify_pop_response(challenge_json: str, response_json: str, tct_token: str) -> str:
    """Verify a downstream PoP response (RFC-AITP-0005 §6.2) and return the
    proven holder AID (the TCT's `sub`). Checks the jti, the nonce echo, the
    challenge expiry, the signature under the key `sub` encodes, and
    `cnf.jkt`. A malformed or stale challenge raises `RuntimeError` with
    `.code == "POP_CHALLENGE_INVALID"`; any other failure,
    `.code == "POP_RESPONSE_INVALID"`. It does not verify the TCT itself:
    use `AitpAgent.verify_tct(..., pop=...)` for that."""
    ...

def compute_aid_jkt(aid: str) -> str:
    """RFC 7638 JWK thumbprint of the pubkey embedded in an AID — the
    value to place in an OIDC JWT's `cnf.jkt` claim (RFC-AITP-0002
    §2.2.1). Supports both Ed25519 and P-256 AIDs."""
    ...

# ── spki-pinning (Cargo feature) ────────────────────────────────

def compute_spki_hash(cert_der: bytes) -> bytes:
    """SHA-256 over the leaf cert's SubjectPublicKeyInfo. Returns 32 bytes.
    Behind the `spki-pinning` feature (on by default)."""
    ...

class SpkiPinVerifier:
    """Holds a list of 32-byte SPKI pins. Behind the `spki-pinning` feature (on by default)."""

    def __init__(self, pins: list[bytes]) -> None: ...
    def is_pinned(self, cert_der: bytes) -> bool: ...
    @property
    def len(self) -> int: ...
