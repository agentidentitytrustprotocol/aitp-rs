# Type stubs for the experimental `aitp` build (`--features experimental`).
#
# Reference only: not shipped in the wheel. The published `aitp` package has
# none of these. `tests/test_stub_signatures.py` checks them against a build
# that has the features.

from typing import Any, Callable, Dict, Optional, Sequence

from aitp import AitpAgent as _AitpAgent
from aitp import DelegationVerified, Revocation, RevokedJtis

class AitpAgent(_AitpAgent):
    # ── experimental-renewal ───────────────────────────────────
    def build_renewal_request(self, current_tct_token: str) -> str:
        """Holder side. `current_tct_token` is the held TCT compact JWS.
        Feature `experimental-renewal`."""
        ...
    def process_renewal_request(
        self,
        request_payload_json: str,
        manifest_exp_unix_secs: int,
        new_ttl_secs: int,
        revoked_jtis: Optional[RevokedJtis] = None,
    ) -> str:
        """Issuer side. Returns a JSON object string
        `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`.
        Requires `build_manifest()` first: grants the Manifest no longer
        offers are dropped (none left raises). A TCT whose `jti` is in
        `revoked_jtis`, or a replayed request, raises RuntimeError.
        `revoked_jtis` entries are normalized (any RFC 9562 text form
        matches); one that is not a UUID raises `ValueError`.
        Feature `experimental-renewal`."""
        ...

# ── experimental-a2a-agent-card ────────────────────────────────

def a2a_card_manifest_url(card_json: str) -> Dict[str, str]:
    """RFC-AITP-0014 §4.2 step 2. Returns `{"aid", "manifest_url"}`, both
    unverified. Raises `RuntimeError` with `.code == "IDENTITY_FAILED"`.
    Feature `experimental-a2a-agent-card`."""
    ...

def verify_a2a_agent_card_binding(
    card_json: str,
    selected_interface_url: str,
    manifest_json: Optional[str] = None,
    now_unix_secs: Optional[int] = None,
) -> Dict[str, Any]:
    """RFC-AITP-0014 §4.2 steps 2 to 5. `manifest_json` is the fetched body;
    `None` means the fetch failed. Returns the §4.3 effective values:
    `{"aid", "accepted_identity_types", "accepted_trust_anchors",
    "offered_capabilities", "handshake_endpoint", "interface_url"}`. Raises
    `RuntimeError` with the registered code on `.code`. Feature
    `experimental-a2a-agent-card`."""
    ...

# ── experimental-multihop-delegation ───────────────────────────

def verify_delegation_multihop(
    delegation_token: str,
    verifier_aid: str,
    issuer_manifests: Sequence[str],
    max_delegation_hops: int = 3,
    revoked_jtis: Optional[RevokedJtis] = None,
    revocation: Optional[Revocation] = None,
    *,
    insecure_localhost_dangerous: bool = False,
) -> DelegationVerified:
    """Verify a delegation token (compact-JWS string) allowing RFC-AITP-0011
    multi-hop chains up to `max_delegation_hops` total hops. Feature
    `experimental-multihop-delegation`. `max_delegation_hops=0` reverts to
    strict single-hop.

    `issuer_manifests` holds the hop issuers' Manifests, each a
    `{"manifest": {...}}` envelope JSON string. Every hop is verified under
    the key resolved from its issuer's verified Manifest (RFC-AITP-0011 §3
    step 1); a hop whose issuer has no valid Manifest in the list fails
    with `KEY_RESOLUTION_FAILED`. Malformed JSON raises `ValueError`.

    `revoked_jtis` and `revocation` are as in `verify_delegation`
    (fail_closed). The list is consulted twice — both only after every
    signature check: once for the root `voucher.src_jti` (RFC-AITP-0006 §4
    step 7), and once for every hop's `jti`, meaning each chain entry and the
    outer token (RFC-AITP-0011 §6). Both are MUST-rejects. A revoked hop
    invalidates every hop downstream of it; there is no partial-validity
    model.

    Note that §6 specifies each hop `jti` be checked against the deny list of
    *that hop's issuer*, which one flat set cannot express — so the set is
    applied to every hop regardless of issuer. That can only reject more,
    never accept a revoked hop, but it does mean a set aggregated from
    several issuers lets any contributor revoke any hop.

    Entries are normalized as in `verify_delegation`."""
    ...

# ── experimental-session-bundle ────────────────────────────────

class SessionBundleBuilder:
    """RFC-AITP-0010 Session Trust Bundle builder. Feature
    `experimental-session-bundle`."""

    def __init__(self, coordinator: AitpAgent) -> None: ...
    def session_id(self, uuid_str: str) -> "SessionBundleBuilder":
        """Set the session ID. It is signed into the bundle, so it must be
        the lowercase hyphenated UUID v4 wire form; uppercase, braced,
        `urn:uuid:`, unhyphenated and non-v4 forms raise `ValueError`
        rather than being normalized. Defaults to a fresh one."""
        ...
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
    coordinator_manifest_json: str,
    now_unix_secs: Optional[int] = ...,
    revocation_check: Optional[Callable[[str], bool]] = ...,
) -> dict:
    """Returns `{"kind": "clear"|"degraded", "active_aids": [...],
    "dropped_aids": [...]}`. Feature `experimental-session-bundle`.

    `coordinator_manifest_json` (required; the coordinator's
    `ManifestEnvelope` JSON) is verified, must designate the bundle's
    `coordinator`, and supplies the coordinator key (RFC-AITP-0010 §5
    step 5). There is no AID-only fallback. Raises `RuntimeError` when
    it names another AID, `ValueError` when it is malformed."""
    ...
