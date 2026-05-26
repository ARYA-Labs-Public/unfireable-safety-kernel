//! Transparency-log domain types (, ).
//!
//! Pure types only — no I/O, no clock, no RNG, no logging. RFC-6962
//! compatible Merkle semantics. Verification logic and proof
//! construction land in Step 4; this module is the type-only scaffold.
//!
//! Boundary contract per `agent/boundaries.toml`:
//!   FORBIDDEN imports:
//!     `std::fs`, `std::env`, `std::net`, `std::time::SystemTime`,
//!     `rand::`, `sqlx::`, `diesel::`, `reqwest::`, `rdkafka::`,
//!     `tracing::`, `log::`
//!
//! Implementations of Merkle append, inclusion-proof, consistency-proof
//! and Ed25519 signed-tree-head minting live in the storage adapter
//! (`crates/adapters/transparency_store/`, ) and the
//! transparency-log service (`crates/services/transparency-log/`,
//! ). The types themselves stay here so the kernel,
//! reconciler, and any external auditor share a single contract.

pub mod merkle;
pub mod sth;

pub use merkle::{
    build_consistency_proof, build_inclusion_proof, compute_root, leaf_hash,
    node_hash, verify_consistency_proof, verify_inclusion_proof,
    ConsistencyProof, InclusionProof, MerkleLeaf, MerkleNode, SignedTreeHead,
    VerificationError,
};
pub use sth::{mint_sth, verify_sth};
