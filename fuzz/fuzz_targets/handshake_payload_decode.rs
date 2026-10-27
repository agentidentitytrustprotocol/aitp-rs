#![no_main]

//! Fuzz target: Mutual Handshake payload decoding (RFC-AITP-0004).
//!
//! The input goes through the path `aitp::transport`'s handshake
//! routes take for a received payload: duplicate-key rejection
//! (`CheckedJson`), the unknown-member check, then typed
//! deserialization, for each of the four messages. Every step must
//! return, never panic.

use aitp::core::{check_members, from_serde_error, CheckedJson};
use aitp::handshake::{
    MutualCommitAckPayload, MutualCommitPayload, MutualHelloAckPayload, MutualHelloPayload,
    MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS, MUTUAL_COMMIT_PAYLOAD_MEMBERS,
    MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS, MUTUAL_HELLO_PAYLOAD_MEMBERS,
};
use libfuzzer_sys::fuzz_target;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn decode<T: DeserializeOwned>(name: &'static str, members: &[&str], value: &Value) {
    if check_members(name, value, members).is_err() {
        return;
    }
    if let Err(e) = serde_json::from_value::<T>(value.clone()) {
        let _ = from_serde_error(&e);
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(checked) = CheckedJson::from_slice(data) else {
        return;
    };
    let v = checked.as_value();
    decode::<MutualHelloPayload>("MutualHelloPayload", MUTUAL_HELLO_PAYLOAD_MEMBERS, v);
    decode::<MutualHelloAckPayload>("MutualHelloAckPayload", MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS, v);
    decode::<MutualCommitPayload>("MutualCommitPayload", MUTUAL_COMMIT_PAYLOAD_MEMBERS, v);
    decode::<MutualCommitAckPayload>(
        "MutualCommitAckPayload",
        MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS,
        v,
    );
});
