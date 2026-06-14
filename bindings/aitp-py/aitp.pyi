# Type stubs for the `aitp` Python SDK (`bindings/aitp-py`).
#
# Hand-maintained because the underlying extension is built by PyO3 / maturin
# and does not auto-generate stubs. Edit when the binding's public surface
# changes; the symmetry oracle is the auto-generated `bindings/aitp-node/
# index.d.ts` — every type here SHOULD have a camelCase counterpart there
# (and vice versa), per CLAUDE.md's binding-symmetry rule.

from typing import AbstractSet, Callable, Literal, Optional

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
    cnf: str  # RFC 7638 JWK thumbprint (cnf.jkt) of the delegatee's key

class InitiatorSession:
    """Outbound handshake session. Construct via `AitpAgent.new_session`."""

    def build_hello(
        self,
        peer_manifest_json: str,
        requested_grants: list[str],
        oidc_mint_jwt: Optional[Callable[[str], str]] = ...,
    ) -> str: ...
    def process_hello_ack(self, hello_ack_json: str, session_id: str) -> str: ...
    def complete(self, commit_ack_json: str) -> str:
        """Returns a JSON object string
        `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`:
        the TCT the peer issued to us plus the companion grant voucher."""
        ...

class ResponderSession:
    """Inbound handshake session. Construct via `AitpAgent.new_responder`."""

    def process_hello(
        self,
        hello_json: str,
        oidc_mint_jwt: Optional[Callable[[str], str]] = ...,
    ) -> tuple[str, str]: ...
    def process_commit(self, commit_json: str) -> tuple[str, str]:
        """Returns `(commit_ack_json, completed_json)` where `completed_json`
        is `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`
        — the TCT we issued to the peer plus its companion grant voucher."""
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
    ) -> str: ...
    def new_session(
        self,
        jwks: Optional[JwksProvider] = ...,
        trust_anchors: Optional[list[str]] = ...,
    ) -> InitiatorSession: ...
    def new_responder(
        self,
        jwks: Optional[JwksProvider] = ...,
        trust_anchors: Optional[list[str]] = ...,
    ) -> ResponderSession: ...
    def verify_tct(
        self,
        tct_token: str,
        required_grant: str,
        expected_audience: Optional[str] = ...,
        revoked_jtis: Optional[AbstractSet[str]] = ...,
    ) -> TctIdentity:
        """Verify a TCT compact-JWS string. `revoked_jtis` is an OPTIONAL set
        of revoked TCT `jti` strings (RFC-AITP-0008); when supplied, a TCT
        whose jti is in the set is rejected after its signature checks pass.
        Verifiers SHOULD supply it — omitting it silently honors a
        revoked-but-unexpired TCT (F-1)."""
        ...
    def verify_tct_cached(
        self,
        tct_token: str,
        required_grant: str,
        store: TctStore,
        expected_audience: Optional[str] = ...,
        revoked_jtis: Optional[AbstractSet[str]] = ...,
    ) -> TctIdentity:
        """Like `verify_tct` but consults `store` first. `revoked_jtis` (F-1)
        is re-checked on every call, cache hits included."""
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
    def sign_revocation_list(
        self,
        entries: list[dict],
        expires_in_secs: Optional[int] = ...,
    ) -> str: ...
    # ── renewal (Cargo feature) ────────────────────────────
    def build_renewal_request(self, current_tct_token: str) -> str:
        """Holder side. `current_tct_token` is the held TCT compact JWS.
        Behind the `renewal` Cargo feature (on by default; absent only in a
        `--no-default-features` wheel)."""
        ...
    def process_renewal_request(
        self,
        request_payload_json: str,
        manifest_exp_unix_secs: int,
        new_ttl_secs: int,
    ) -> str:
        """Issuer side. Returns a JSON object string
        `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`.
        Behind the `renewal` feature (on by default)."""
        ...

# ── Free functions ──────────────────────────────────────────────────────

def verify_delegation(
    delegation_token: str, verifier_aid: str
) -> DelegationVerified:
    """Verify a delegation token (compact-JWS string) under strict AITP v0.2
    (RFC-AITP-0006 single-hop). A token carrying a non-empty `chain`
    (RFC-AITP-0011 multi-hop) is rejected with
    `DELEGATION_MULTIHOP_NOT_SUPPORTED`. To allow multi-hop chains, use
    `verify_delegation_multihop` instead."""
    ...

def verify_delegation_multihop(
    delegation_token: str, verifier_aid: str, max_hops: int = 3
) -> DelegationVerified:
    """Verify a delegation token (compact-JWS string) allowing RFC-AITP-0011
    multi-hop chains up to `max_hops` total hops. Present by default (the
    `multihop-delegation` Cargo feature); absent only in a
    `--no-default-features` wheel. `max_hops=0` reverts to strict
    single-hop."""
    ...
def verify_manifest_json(manifest_envelope_json: str) -> None:
    """Verify a `ManifestEnvelope` JSON. Raises on failure."""
    ...

def compute_aid_jkt(aid: str) -> str:
    """RFC 7638 JWK thumbprint of the pubkey embedded in an AID — the
    value to place in an OIDC JWT's `cnf.jkt` claim (RFC-AITP-0002
    §2.2.1). Supports both Ed25519 and P-256 AIDs."""
    ...

# ── session-bundle (Cargo feature) ─────────────────────────────────

class SessionBundleBuilder:
    """RFC-AITP-0010 Session Trust Bundle builder. Behind the
    `session-bundle` Cargo feature (on by default)."""

    def __init__(self, coordinator: AitpAgent) -> None: ...
    def session_id(self, uuid_str: str) -> "SessionBundleBuilder": ...
    def issued_at(self, unix_secs: int) -> "SessionBundleBuilder": ...
    def participant(
        self, aid: str, tct_token: str
    ) -> "SessionBundleBuilder":
        """`tct_token` is the participant's TCT as a compact-JWS string."""
        ...
    def build(self) -> str: ...

def verify_session_bundle(
    bundle_envelope_json: str,
    verifier_aid: str,
    now_unix_secs: Optional[int] = ...,
    revocation_check: Optional[Callable[[str], bool]] = ...,
) -> dict:
    """Returns `{"kind": "clear"|"degraded", "active_aids": [...],
    "dropped_aids": [...]}`. Behind the `session-bundle` feature (on by default)."""
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
