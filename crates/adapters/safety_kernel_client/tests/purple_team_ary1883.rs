//! Cargo integration-test entry point for the  /purple-team
//! adversarial campaign suite (session ary1883-pt-5d8d4b5c).
//!
//! The actual campaigns live in `tests/purple/adversarial_campaigns.rs`
//! (namespaced under `tests/purple/` per the /test–/purple-team
//! coordination contract — concurrent /test campaigns may write under
//! the rest of `tests/`).

#[path = "purple/adversarial_campaigns.rs"]
mod adversarial_campaigns;

#[path = "purple/cert_pinning_bypass.rs"]
mod cert_pinning_bypass;
