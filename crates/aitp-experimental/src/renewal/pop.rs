//! The renewal proof-of-possession input (RFC-AITP-0013 §3.1).

/// The domain tag that starts the renewal PoP input (RFC-AITP-0013
/// §3.1): the 19 ASCII bytes `aitp-renewal-pop-v1` and one `0x00` byte.
pub const RENEWAL_POP_DOMAIN_TAG: &[u8; 20] = b"aitp-renewal-pop-v1\0";

/// The renewal PoP input of RFC-AITP-0013 §3.1:
/// `"aitp-renewal-pop-v1\0" || iss || "\0" || jti || "\0" || nonce`.
///
/// `iss` and `jti` are the current TCT's claims exactly as written in
/// the token; `pop_nonce` is the decoded nonce, not its base64url form.
/// The signature covers `sha256` of this input, hashed once.
pub fn renewal_pop_input(iss: &str, jti: &str, pop_nonce: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        RENEWAL_POP_DOMAIN_TAG.len() + iss.len() + 1 + jti.len() + 1 + pop_nonce.len(),
    );
    input.extend_from_slice(RENEWAL_POP_DOMAIN_TAG);
    input.extend_from_slice(iss.as_bytes());
    input.push(0);
    input.extend_from_slice(jti.as_bytes());
    input.push(0);
    input.extend_from_slice(pop_nonce);
    input
}
