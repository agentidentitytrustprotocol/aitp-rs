//! Operation name constants — the wire vocabulary of the conformance protocol.
//!
//! See `docs/conformance.md` for the full operation table.

// ── Tier A: pure verification ───────────────────────────────────────────
/// Verify an envelope's signature and structure.
pub const OP_VERIFY_ENVELOPE: &str = "verify_envelope";
/// Verify a Manifest.
pub const OP_VERIFY_MANIFEST: &str = "verify_manifest";
/// Verify a TCT.
pub const OP_VERIFY_TCT: &str = "verify_tct";
/// Verify a delegation token.
pub const OP_VERIFY_DELEGATION_TOKEN: &str = "verify_delegation_token";
/// Compute JCS canonical form (returns hex bytes).
pub const OP_VERIFY_JCS: &str = "verify_jcs";
/// Compute a JWK thumbprint from a 32-byte pubkey.
pub const OP_COMPUTE_JWK_THUMBPRINT: &str = "compute_jwk_thumbprint";

// ── Tier B: issuance ────────────────────────────────────────────────────
/// Generate a fresh keypair (or load from seed) and return a handle.
pub const OP_GENERATE_KEYPAIR: &str = "generate_keypair";
/// Issue a Manifest from a keypair handle.
pub const OP_ISSUE_MANIFEST: &str = "issue_manifest";
/// Issue a TCT from a keypair handle.
pub const OP_ISSUE_TCT: &str = "issue_tct";
/// Issue a delegation token.
pub const OP_ISSUE_DELEGATION_TOKEN: &str = "issue_delegation_token";
/// Sign an envelope.
pub const OP_SIGN_ENVELOPE: &str = "sign_envelope";

// ── Tier C: stateful flows ──────────────────────────────────────────────
/// Begin a handshake; returns a session_id and the first envelope to send.
pub const OP_START_HANDSHAKE: &str = "start_handshake";
/// Feed an incoming envelope into an in-progress handshake.
pub const OP_PROCESS_HANDSHAKE_MESSAGE: &str = "process_handshake_message";
/// Revoke a TCT by JTI.
pub const OP_REVOKE_TCT: &str = "revoke_tct";
/// Verify a signed revocation snapshot.
pub const OP_VERIFY_REVOCATION_SNAPSHOT: &str = "verify_revocation_snapshot";

// ── Tier D: test-only ───────────────────────────────────────────────────
/// Override the adapter's idea of "now" for time-dependent tests.
pub const OP_SET_CLOCK: &str = "set_clock";
/// Force a JTI into the adapter's deny list.
pub const OP_INJECT_REVOCATION: &str = "inject_revocation";
/// Dump session state for debugging.
pub const OP_DUMP_SESSION: &str = "dump_session";
