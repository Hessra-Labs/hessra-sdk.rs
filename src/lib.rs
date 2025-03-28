//! # Hessra SDK
//!
//! This crate has been refactored into modular components. Please use the `hessra-sdk` crate directly.
//!
//! The SDK is now split into:
//! - `hessra-token`: Token verification and attestation
//! - `hessra-config`: Configuration management
//! - `hessra-api`: HTTP client for the Hessra service
//! - `hessra-sdk`: Unified SDK that combines all components
//!
//! For documentation and usage examples, please see the `hessra-sdk` crate.

pub use hessra_sdk::*;

#[deprecated(
    since = "0.4.1",
    note = "This crate has been refactored into modular components. Please use the `hessra-sdk` crate directly."
)]
pub struct HessraSDK;
