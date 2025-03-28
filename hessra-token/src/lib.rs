//! # Hessra Token
//!
//! Core verification library for Hessra authentication tokens.
//!
//! This crate provides functionality for verifying and attenuating biscuit tokens
//! used in the Hessra authentication system. It is designed to be WASM-compatible
//! and has no networking dependencies.
//!
//! ## Features
//!
//! - Token verification: Verify tokens without contacting the authorization server
//! - Token attestation: Add service node attestations to tokens
//! - WASM compatibility: Can be compiled to WebAssembly for use in browsers

mod attenuate;
mod verify;

pub use attenuate::add_service_node_attenuation;
pub use verify::{verify_biscuit_local, verify_service_chain_biscuit_local, ServiceNode};

// Re-export biscuit types that are needed for public API
pub use biscuit_auth::{Biscuit, KeyPair, PublicKey};
