//! Revocation utilities for identity tokens
//!
//! This module provides functionality for extracting revocation identifiers
//! from identity tokens and correlating them with their associated identities.

use crate::inspect::inspect_identity_token;
use hessra_token_core::{get_revocation_ids, Biscuit, PublicKey, RevocationId, TokenError};
use std::fmt;

/// Represents an identity and its associated revocation ID
#[derive(Debug, Clone)]
pub struct IdentityRevocation {
    /// The identity (subject or delegated actor)
    pub identity: String,
    /// The revocation ID for this identity's block
    pub revocation_id: RevocationId,
    /// Whether this is a delegated identity (false for the base identity)
    pub is_delegated: bool,
    /// The block index (0 for authority block, 1+ for delegation blocks)
    pub block_index: usize,
}

impl fmt::Display for IdentityRevocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "identity: {}, revocation_id: {}, delegated: {}, block: {}",
            self.identity,
            self.revocation_id.to_hex(),
            self.is_delegated,
            self.block_index
        )
    }
}

/// Get all identity revocations from an identity token
///
/// This function returns a list of identities and their revocation IDs.
/// For a base identity token, this will return one entry.
/// For a delegated token, this will return entries for the base identity
/// and each delegation level.
///
/// # Arguments
/// * `token` - Base64-encoded Biscuit token
/// * `public_key` - Public key to parse the token
///
/// # Returns
/// * `Ok(Vec<IdentityRevocation>)` - List of identities with their revocation IDs
/// * `Err(TokenError)` - If the token cannot be parsed
pub fn get_identity_revocations(
    token: String,
    public_key: PublicKey,
) -> Result<Vec<IdentityRevocation>, TokenError> {
    // Parse the token
    let biscuit = Biscuit::from_base64(&token, public_key)?;

    // Get all revocation IDs
    let rev_ids = get_revocation_ids(&biscuit);

    // Inspect the token to get identity information
    let inspect_result = inspect_identity_token(token.clone(), public_key)?;

    let mut revocations = Vec::new();

    // First, add the base identity (authority block)
    // We need to extract the base subject from the token
    let base_identity = extract_base_identity(&biscuit)?;

    if let Some(base_rev_id) = rev_ids.first() {
        revocations.push(IdentityRevocation {
            identity: base_identity.clone(),
            revocation_id: base_rev_id.clone(),
            is_delegated: false,
            block_index: 0,
        });
    }

    // If the token is delegated, extract identities for each delegation block
    if inspect_result.is_delegated {
        // Parse delegated identities from the token blocks
        let delegated_identities = extract_all_delegated_identities(&biscuit);

        // Add each delegated identity with its corresponding revocation ID
        for (idx, delegated_identity) in delegated_identities.iter().enumerate() {
            let block_index = idx + 1; // +1 because block 0 is the authority block
            if let Some(rev_id) = rev_ids.get(block_index) {
                revocations.push(IdentityRevocation {
                    identity: delegated_identity.clone(),
                    revocation_id: rev_id.clone(),
                    is_delegated: true,
                    block_index,
                });
            }
        }
    }

    Ok(revocations)
}

/// Get the revocation ID for the current active identity in a token
///
/// For a base token, returns the authority block's revocation ID.
/// For a delegated token, returns the last delegation's revocation ID.
///
/// # Arguments
/// * `token` - Base64-encoded Biscuit token
/// * `public_key` - Public key to parse the token
///
/// # Returns
/// * `Ok(IdentityRevocation)` - The active identity and its revocation ID
/// * `Err(TokenError)` - If the token cannot be parsed
pub fn get_active_identity_revocation(
    token: String,
    public_key: PublicKey,
) -> Result<IdentityRevocation, TokenError> {
    let revocations = get_identity_revocations(token, public_key)?;

    // Return the last entry (most specific identity)
    revocations
        .into_iter()
        .last()
        .ok_or_else(|| TokenError::internal("No identities found in token".to_string()))
}

/// Extract the base identity (subject) from the authority block
fn extract_base_identity(biscuit: &Biscuit) -> Result<String, TokenError> {
    // Parse the token content to find the subject fact
    let content = biscuit.print();

    for line in content.lines() {
        if line.trim().starts_with("subject(") {
            // Extract the subject value between parentheses
            if let Some(start) = line.find('"') {
                if let Some(end) = line[start + 1..].find('"') {
                    return Ok(line[start + 1..start + 1 + end].to_string());
                }
            }
        }
    }

    Err(TokenError::internal(
        "No subject found in authority block".to_string(),
    ))
}

/// Extract all delegated identities from the token's attestation blocks
fn extract_all_delegated_identities(biscuit: &Biscuit) -> Vec<String> {
    let mut identities = Vec::new();
    let content = biscuit.print();

    if let Some(blocks_start) = content.find("blocks: [") {
        let blocks_section = &content[blocks_start..];

        if let Some(blocks_end) = blocks_section.find("\n}") {
            let blocks_content = &blocks_section[..blocks_end];

            let blocks: Vec<&str> = blocks_content
                .split("Block {")
                .skip(1) // Skip the part before first block
                .collect();

            // Process each block to find delegated identities
            for block in blocks.iter() {
                if let Some(symbols_line_start) = block.find("symbols: [") {
                    let after_symbols = &block[symbols_line_start + 10..]; // Skip "symbols: ["
                    if let Some(symbols_end) = after_symbols.find(']') {
                        let symbols_str = &after_symbols[..symbols_end];

                        // Parse symbols and look for identity patterns
                        for symbol in symbols_str.split(',') {
                            let symbol = symbol.trim().trim_matches('"');
                            // Check if this looks like an identity
                            if symbol.contains(':')
                                && (symbol.starts_with("urn:")
                                    || symbol.starts_with("https:")
                                    || symbol.starts_with("mailto:")
                                    || symbol.contains("hessra"))
                            {
                                identities.push(symbol.to_string());
                                break; // Found the identity for this block
                            }
                        }
                    }
                }
            }
        }
    }

    identities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{add_identity_attenuation_to_token, create_identity_token, HessraIdentity};
    use hessra_token_core::{KeyPair, TokenTimeConfig};

    #[test]
    fn test_get_identity_revocations_base_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let subject = "urn:hessra:alice".to_string();

        let token = create_identity_token(subject.clone(), keypair, TokenTimeConfig::default())
            .expect("Failed to create token");

        let revocations =
            get_identity_revocations(token, public_key).expect("Failed to get revocations");

        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].identity, subject);
        assert!(!revocations[0].is_delegated);
        assert_eq!(revocations[0].block_index, 0);
        assert!(!revocations[0].revocation_id.to_hex().is_empty());
    }

    #[test]
    fn test_get_identity_revocations_delegated_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let base_identity = "urn:hessra:alice".to_string();
        let delegated_identity = "urn:hessra:alice:laptop".to_string();

        let token = HessraIdentity::new(base_identity.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create token");

        let delegated_token = add_identity_attenuation_to_token(
            token,
            delegated_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to delegate token");

        let revocations = get_identity_revocations(delegated_token, public_key)
            .expect("Failed to get revocations");

        assert_eq!(revocations.len(), 2);

        // Check base identity
        assert_eq!(revocations[0].identity, base_identity);
        assert!(!revocations[0].is_delegated);
        assert_eq!(revocations[0].block_index, 0);

        // Check delegated identity
        assert_eq!(revocations[1].identity, delegated_identity);
        assert!(revocations[1].is_delegated);
        assert_eq!(revocations[1].block_index, 1);

        // Revocation IDs should be different
        assert_ne!(
            revocations[0].revocation_id.to_hex(),
            revocations[1].revocation_id.to_hex()
        );
    }

    #[test]
    fn test_get_active_identity_revocation() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let base_identity = "urn:hessra:alice".to_string();
        let delegated_identity = "urn:hessra:alice:laptop".to_string();

        // Test with base, delegatable token
        let token = HessraIdentity::new(base_identity.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create token");

        let active_rev = get_active_identity_revocation(token.clone(), public_key)
            .expect("Failed to get active revocation");
        assert_eq!(active_rev.identity, base_identity);
        assert!(!active_rev.is_delegated);

        // Test with delegated token
        let delegated_token = add_identity_attenuation_to_token(
            token,
            delegated_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to delegate token");

        let active_rev = get_active_identity_revocation(delegated_token, public_key)
            .expect("Failed to get active revocation");
        assert_eq!(active_rev.identity, delegated_identity);
        assert!(active_rev.is_delegated);
    }

    #[test]
    fn test_multi_level_delegation_revocations() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let org_identity = "urn:hessra:company".to_string();
        let dept_identity = "urn:hessra:company:dept_eng".to_string();
        let user_identity = "urn:hessra:company:dept_eng:alice".to_string();

        // Create and delegate token through multiple levels
        let token = HessraIdentity::new(org_identity.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create org token");

        let token = add_identity_attenuation_to_token(
            token,
            dept_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate to department");

        let token = add_identity_attenuation_to_token(
            token,
            user_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate to user");

        let revocations =
            get_identity_revocations(token, public_key).expect("Failed to get revocations");

        assert_eq!(revocations.len(), 3);

        // Check all three levels
        assert_eq!(revocations[0].identity, org_identity);
        assert_eq!(revocations[0].block_index, 0);
        assert!(!revocations[0].is_delegated);

        assert_eq!(revocations[1].identity, dept_identity);
        assert_eq!(revocations[1].block_index, 1);
        assert!(revocations[1].is_delegated);

        assert_eq!(revocations[2].identity, user_identity);
        assert_eq!(revocations[2].block_index, 2);
        assert!(revocations[2].is_delegated);

        // All revocation IDs should be unique
        let rev_ids: Vec<String> = revocations
            .iter()
            .map(|r| r.revocation_id.to_hex())
            .collect();
        assert_eq!(rev_ids.len(), 3);
        assert_ne!(rev_ids[0], rev_ids[1]);
        assert_ne!(rev_ids[1], rev_ids[2]);
        assert_ne!(rev_ids[0], rev_ids[2]);
    }
}
