//! TCT renewal (RFC-AITP-0013, Draft). **No stability promise.**
//!
//! A holder asks the issuer for a new TCT in place of the one it holds.
//! Renewal does not replay the Mutual Handshake: it carries forward the
//! identity binding in the current TCT's `sub` and `cnf`, and the holder
//! proves possession of the subject key over the renewal PoP input
//! ([`renewal_pop_input`], §3.1).
//!
//! The request (§3) is the unenveloped JSON body of a `POST` to the
//! issuer's `renew_uri` ([`RENEW_URI_EXT`]):
//!
//! ```json
//! {
//!   "current_tct":   "<compact JWS, typ aitp-tct+jwt>",
//!   "pop_nonce":     "<22-char base64url, fresh>",
//!   "pop_signature": "<sign(holder_key, sha256(renewal_pop_input))>"
//! }
//! ```
//!
//! The issuer runs [`parse_renewal_request`] and
//! [`process_renewal_request`] (§4) and answers with a signed `tct`
//! envelope built by [`renewal_response_envelope`] (§6), or an `error`
//! envelope built by [`renewal_error_envelope`] carrying
//! [`RenewalError::error_code`]. The holder checks the answer with
//! [`verify_renewal_response`] (§6.1) before it uses the renewed TCT.
//!
//! - `RenewalServer`, the issuer's HTTP endpoint, needs feature
//!   `http-server`.
//! - `renew_tct`, the holder's HTTP client, needs feature `http-client`.

mod error;
mod holder;
mod issuer;
mod peek;
mod pop;
mod wire;

#[cfg(feature = "http-client")]
mod client;
#[cfg(feature = "http-server")]
mod server;

pub use error::{RenewalError, RenewalResponseError};
pub use holder::{
    build_renewal_request, verify_renewal_response, RenewalResponseContext, RenewedTct,
};
pub use issuer::{
    parse_renewal_request, process_renewal_request, renewal_error_envelope,
    renewal_response_envelope, RenewalContext, RenewalGrantPolicyFn,
};
pub use pop::{renewal_pop_input, RENEWAL_POP_DOMAIN_TAG};
pub use wire::{
    renew_uri_from_manifest, RenewalErrorPayload, RenewalResponsePayload, TctRenewalPayload,
    RENEWAL_RESPONSE_PAYLOAD_MEMBERS, RENEW_URI_EXT,
};

#[cfg(feature = "http-client")]
pub use client::{renew_tct, renew_tct_with_insecure_localhost, RenewClientError};
#[cfg(feature = "http-server")]
pub use server::{RenewalServer, RenewalServerError};
