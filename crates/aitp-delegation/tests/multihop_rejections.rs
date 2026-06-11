//! Adversarial multi-hop verifier tests (RFC-AITP-0011 §3-§5).
//!
//! `multihop.rs` proves the happy path and a few rejections, but several
//! verifier guards are reachable only by an attacker and were previously
//! unproven. Each test here mints an otherwise-valid 3-hop token and
//! breaks exactly ONE invariant, **re-signing every layer that the
//! mutation touches** so the verifier reaches the intended guard rather
//! than tripping an incidental earlier check.
//!
//! Topology (same as `multihop.rs`): A → B → C → D, verifier = A.
//!   chain[0] = A→B (TCT projection)   chain[1] = B→C (signed step)
//!   grant_proof = C→D (signed step)   issued_by = C, delegatee = D

use aitp_core::{base64url, jcs, Aid, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_delegation::{
    compute_chain_hash, verify_delegation, DelegationError, DelegationStep, DelegationToken,
    GrantProof, VerifyDelegationContext, DEFAULT_MAX_HOPS,
};
use aitp_tct::{Tct, TctBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn key(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_seed(&[seed; 32])
}

#[derive(Serialize)]
struct StepSigningView<'a> {
    issuer: &'a Aid,
    subject: &'a Aid,
    capabilities: &'a [String],
    issued_at: &'a Timestamp,
    expires_at: &'a Timestamp,
    source_tct_jti: &'a Uuid,
}

fn mint_step(
    issuer_key: &AitpSigningKey,
    subject: Aid,
    capabilities: Vec<String>,
    expires_at: Timestamp,
) -> DelegationStep {
    let issued_at = NOW;
    let source_tct_jti = Uuid::new_v4();
    let view = StepSigningView {
        issuer: issuer_key.aid(),
        subject: &subject,
        capabilities: &capabilities,
        issued_at: &issued_at,
        expires_at: &expires_at,
        source_tct_jti: &source_tct_jti,
    };
    let digest = Sha256::digest(jcs::canonicalize_serializable(&view).unwrap());
    GrantProof {
        issuer: issuer_key.aid().clone(),
        subject,
        capabilities,
        issued_at,
        expires_at,
        source_tct_jti,
        signature: issuer_key.sign(&digest).into_string(),
    }
}

#[derive(Serialize)]
struct OuterSigningView<'a> {
    delegator: &'a Aid,
    delegatee: &'a Aid,
    issued_by: &'a Aid,
    audience: &'a Aid,
    scope: &'a [String],
    expires_at: &'a Timestamp,
    cnf: &'a str,
    grant_proof: &'a GrantProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain: Option<&'a [DelegationStep]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_hash: Option<&'a str>,
}

/// Knobs for breaking exactly one invariant. `Default` yields a valid
/// 3-hop token that verifies.
struct Opts {
    /// Who mints chain[0] (the A→B TCT). Default A; set to a rogue key to
    /// break the "chain rooted at the delegator" invariant.
    chain0_issuer_seed: u8,
    /// chain[1] (B→C) capabilities. Default a subset of chain[0]'s.
    bc_caps: Vec<&'static str>,
    /// chain[1] (B→C) expiry. Default below chain[0]'s.
    bc_expires: Timestamp,
    /// Flip a byte in chain[1]'s signature *before* the outer signature
    /// is computed (so only the per-hop step-signature check fails).
    tamper_bc_sig: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            chain0_issuer_seed: 0xA0,
            bc_caps: vec!["read", "write"],
            bc_expires: Timestamp(NOW.0 + 3600 - 60),
            tamper_bc_sig: false,
        }
    }
}

/// Mint a 3-hop token. The verifier is always A (seed 0xA0). Everything
/// is internally consistent (and re-signed) except whatever `opts` breaks.
fn mint(opts: Opts) -> DelegationToken {
    let alice = key(0xA0); // delegator A (always the verifier)
    let chain0_issuer = key(opts.chain0_issuer_seed);
    let bob = key(0xB0);
    let carol = key(0xC0);
    let dave = key(0xD0);

    // chain[0]: A→B, a real peer-issued TCT (signature reused verbatim).
    let tct_b: Tct = TctBuilder::new(&chain0_issuer)
        .subject(bob.aid().clone())
        .audience(bob.aid().clone())
        .grants(["read", "write", "admin"])
        .ttl_secs(3600)
        .subject_pubkey(bob.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap();
    let step_ab = GrantProof {
        issuer: chain0_issuer.aid().clone(),
        subject: bob.aid().clone(),
        capabilities: tct_b.grants.clone(),
        issued_at: tct_b.issued_at,
        expires_at: tct_b.expires_at,
        source_tct_jti: tct_b.jti,
        signature: tct_b.signature.clone(),
    };

    // chain[1]: B→C.
    let bc_caps: Vec<String> = opts.bc_caps.iter().map(|s| s.to_string()).collect();
    let mut step_bc = mint_step(&bob, carol.aid().clone(), bc_caps, opts.bc_expires);
    if opts.tamper_bc_sig {
        let mut raw = step_bc.signature.into_bytes();
        raw[0] ^= 0x01;
        // Keep it parseable base64url so we reach the verify (not parse) error.
        step_bc.signature = String::from_utf8(raw)
            .ok()
            .filter(|s| {
                s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            })
            .unwrap_or_else(|| "A".repeat(86));
    }

    // grant_proof: C→D, narrowest scope, expiry below chain[1].
    let cd_expires = Timestamp(opts.bc_expires.0.min(NOW.0 + 3600) - 60);
    let step_cd = mint_step(&carol, dave.aid().clone(), vec!["read".into()], cd_expires);

    let chain = vec![step_ab, step_bc];
    let chain_hash = compute_chain_hash(&chain).unwrap();

    let delegator = alice.aid().clone();
    let audience = delegator.clone();
    let scope = vec!["read".to_string()];
    let expires_at = Timestamp(cd_expires.0 - 60);
    let cnf = base64url::encode(&dave.verifying_key().to_bytes());

    let outer = OuterSigningView {
        delegator: &delegator,
        delegatee: dave.aid(),
        issued_by: carol.aid(),
        audience: &audience,
        scope: &scope,
        expires_at: &expires_at,
        cnf: &cnf,
        grant_proof: &step_cd,
        chain: Some(&chain),
        chain_hash: Some(&chain_hash),
    };
    let digest = Sha256::digest(jcs::canonicalize_serializable(&outer).unwrap());
    let signature = carol.sign(&digest).into_string();

    DelegationToken {
        delegator,
        delegatee: dave.aid().clone(),
        issued_by: carol.aid().clone(),
        audience,
        scope,
        expires_at,
        cnf,
        grant_proof: step_cd,
        chain: Some(chain),
        chain_hash: Some(chain_hash),
        signature,
    }
}

fn ctx<'a>(verifier: &'a Aid) -> VerifyDelegationContext<'a> {
    VerifyDelegationContext {
        verifier_aid: verifier,
        now: NOW,
        revocation_check: None,
        max_hops: DEFAULT_MAX_HOPS,
    }
}

#[test]
fn baseline_opts_verify() {
    // Sanity: the default knobs really do produce a valid token, so a
    // rejection in another test is attributable to its single mutation.
    let alice = key(0xA0);
    let token = mint(Opts::default());
    verify_delegation(&token, &ctx(alice.aid())).expect("default 3-hop verifies");
}

#[test]
fn first_hop_not_rooted_at_delegator_rejected() {
    // chain[0] minted by a rogue key R ≠ A, while delegator stays A.
    // RFC-AITP-0011 §3 step 3: chain[0].issuer MUST equal the delegator.
    let alice = key(0xA0);
    let token = mint(Opts {
        chain0_issuer_seed: 0xEE, // rogue
        ..Opts::default()
    });
    let err = verify_delegation(&token, &ctx(alice.aid())).unwrap_err();
    assert!(
        matches!(err, DelegationError::InvalidGrantProof),
        "expected InvalidGrantProof, got {err:?}"
    );
}

#[test]
fn interior_hop_expiry_not_monotonic_rejected() {
    // chain[1].expires_at > chain[0].expires_at. RFC-AITP-0011 §3 step 4:
    // per-hop expiry must be non-increasing along the chain.
    let alice = key(0xA0);
    let token = mint(Opts {
        bc_expires: Timestamp(NOW.0 + 7200), // > chain[0] (NOW+3600)
        ..Opts::default()
    });
    let err = verify_delegation(&token, &ctx(alice.aid())).unwrap_err();
    assert!(
        matches!(err, DelegationError::Expired),
        "expected Expired (monotonicity), got {err:?}"
    );
}

#[test]
fn interior_hop_signature_tamper_rejected() {
    // chain[1]'s step signature is forged but the outer signature is
    // re-computed over the forged chain, so the per-hop step-signature
    // check (not the outer signature) is what must reject.
    let alice = key(0xA0);
    let token = mint(Opts {
        tamper_bc_sig: true,
        ..Opts::default()
    });
    let err = verify_delegation(&token, &ctx(alice.aid())).unwrap_err();
    assert!(
        matches!(err, DelegationError::InvalidGrantProof),
        "expected InvalidGrantProof (interior step sig), got {err:?}"
    );
}

#[test]
fn interior_hop_scope_inflation_rejected() {
    // chain[1] grants a capability ("superadmin") that chain[0] never
    // had. RFC-AITP-0011 §4: capabilities must subset transitively.
    let alice = key(0xA0);
    let token = mint(Opts {
        bc_caps: vec!["read", "superadmin"], // superadmin ∉ chain[0]
        ..Opts::default()
    });
    let err = verify_delegation(&token, &ctx(alice.aid())).unwrap_err();
    assert!(
        matches!(err, DelegationError::ScopeExceeded),
        "expected ScopeExceeded (mid-chain inflation), got {err:?}"
    );
}
