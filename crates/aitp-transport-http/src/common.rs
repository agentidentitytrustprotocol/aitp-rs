//! Shared client/server helpers.
//!
//! Envelope signing/verification lives in the `aitp-envelope` crate
//! (no HTTP, no async) so language bindings and other sync consumers
//! can reuse it without a transport stack. It is re-exported here so
//! existing `aitp_transport_http::common::*` imports keep working.

pub use aitp_envelope::{sign_envelope, sign_envelope_with, verify_envelope_signature};
