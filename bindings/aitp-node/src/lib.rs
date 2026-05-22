//! AITP Node.js SDK — Agent Identity & Trust Protocol.
//!
//! Thin NAPI-rs binding over the pure-Rust AITP protocol crates. Every
//! method consumes and produces JSON strings that are HTTP request /
//! response bodies, so agent code never sees a Rust type across the
//! boundary.
//!
//! `#![forbid(unsafe_code)]` is intentionally omitted: the NAPI-rs
//! export macros expand to `unsafe` glue. The underlying protocol
//! crates keep the forbid attribute.

mod agent;
mod helpers;
mod session;
mod tct;
