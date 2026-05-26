//! Route handler modules — one file per `OpenAPI` tag.
//!
//! Routes are wired in `main.rs::build_router`. Per 
//! §6.1, the Rust crate matches the Python module split (`meta`,
//! `authorize`, `approvals`).

pub mod approvals;
pub mod authorize;
pub mod meta;
pub mod policy;
