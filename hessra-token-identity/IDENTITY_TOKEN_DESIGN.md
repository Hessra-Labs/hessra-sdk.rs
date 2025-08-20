# Hessra Identity Token Design Document

## Overview

Identity tokens in the Hessra system provide a hierarchical, delegatable identity mechanism using Biscuit tokens. These tokens serve as the identity layer in the authorization system, similar to OAuth2 refresh tokens, and are exchanged for authorization tokens based on policy.

## Core Concepts

### Hierarchical URI-Based Identities

Identity tokens use URI-based identifiers that support hierarchical delegation. The hierarchy is defined using colon (`:`) as the delimiter:

- Base identity: `urn:hessra:alice`
- Delegated to device: `urn:hessra:alice:laptop`
- Further delegated: `urn:hessra:alice:laptop:chrome`

This hierarchy enables secure delegation where each level can create more specific sub-identities.

### Token Structure

Each identity token consists of:

1. **Base Block**: Contains the root identity and validation checks

   - `subject(identity)` - The identity this token represents
   - `check if actor($a), $a == {subject} || $a.starts_with({subject} + ":")` - Validates the actor
   - `check if time($time), $time < {expiration}` - Time-based expiration

2. **Attenuation Blocks** (optional): Added through delegation
   - `check if actor($a), $a == {identity} || $a.starts_with({identity} + ":")` - Restricts to delegated identity
   - `check if time($time), $time < {expiration}` - Additional time constraints

## Security Model

### Prefix Attack Prevention

The system prevents prefix attacks through strict boundary checking. The check `$a == {identity} || $a.starts_with({identity} + ":")` ensures:

- ✅ `urn:hessra:alice` matches `urn:hessra:alice` (exact match)
- ✅ `urn:hessra:alice:laptop` matches pattern for `urn:hessra:alice` token
- ❌ `urn:hessra:alice2` does NOT match (prevented by colon boundary)

### Delegation Restricts Usage

When a token is attenuated (delegated), it becomes MORE restrictive, not less:

1. Alice creates base token for `urn:hessra:alice`
2. Alice attenuates it to `urn:hessra:alice:laptop`
3. The attenuated token now works ONLY for `urn:hessra:alice:laptop` (and its sub-hierarchies)
4. Alice herself cannot use the attenuated token - she should use her original token

This follows the principle of least privilege - delegation narrows permissions.

### All Checks Must Pass

Biscuit enforces that ALL checks in ALL blocks must pass. This creates an intersection of permissions:

- Base block: allows `alice` and `alice:*`
- Attenuation block: allows `alice:laptop` and `alice:laptop:*`
- Result: only `alice:laptop` and `alice:laptop:*` are authorized

## Design Decisions

### Why Colon as Delimiter?

The colon (`:`) delimiter was chosen for:

- URN compatibility (`urn:hessra:user:device`)
- Clear hierarchy separation
- Avoiding conflicts with URL paths (which use `/`)
- Consistent with existing URI schemes

### Base Token Permissiveness

The base token allows all sub-hierarchies (`$a.starts_with({subject} + ":")`) by design. While this means `alice:laptop` could technically use Alice's base token, this is acceptable because:

1. Identity tokens should never be shared - they're exchanged with trusted services only
2. The permissiveness enables flexible delegation patterns

### Attenuation via Third-Party Blocks

Delegations use Biscuit's third-party blocks, which:

- Require the token holder's public key for verification
- Cannot be forged without the private key
- Create a cryptographic chain of trust
- Support offline verification

## Usage Patterns

### Basic Identity Token

```
Token for: urn:hessra:alice
Can be used by: urn:hessra:alice (and technically alice:* but shouldn't be shared)
```

### Single Delegation

```
Token for: urn:hessra:alice
Attenuated to: urn:hessra:alice:laptop
Can be used by: ONLY urn:hessra:alice:laptop (and laptop:*)
```

### Multi-Level Delegation Chain

```
Token for: urn:hessra:company
Attenuated to: urn:hessra:company:dept_eng
Attenuated to: urn:hessra:company:dept_eng:alice
Attenuated to: urn:hessra:company:dept_eng:alice:laptop
Can be used by: ONLY urn:hessra:company:dept_eng:alice:laptop (and its sub-hierarchies)
```

## Time-Based Expiration

Each token and attenuation can have independent expiration times:

- Base tokens typically have longer validity periods
- Attenuations can add shorter expiration times
- All time checks must pass for authorization to succeed

## Verification Process

During verification, the authorizer:

1. Adds the current time as a fact: `time(now)`
2. Adds the requesting actor as a fact: `actor(identity)`
3. Evaluates all checks in all blocks
4. Allows access with: `allow if true`
5. Authorization succeeds only if ALL checks pass

## Constraints and Limitations

1. **Delimiter-Dependent**: The system assumes `:` as the hierarchy delimiter
2. **No Revocation**: Once attenuated, tokens cannot be revoked (only expire)
3. **No Lateral Delegation**: Cannot delegate to siblings (alice:laptop cannot create tokens for alice:phone)
4. **URN-Optimized**: While other URI schemes work, the system is optimized for URN-style identifiers

## Security Considerations

1. **Never Share Base Tokens**: Identity tokens should only be exchanged with trusted authorization services
2. **Use Short Expiration**: Especially for attenuated tokens
3. **Combine with Authentication**: Delegated identities should authenticate separately (e.g., mTLS certificates)
4. **Audit Delegation Chains**: Monitor and limit delegation depth in production

## Future Enhancements

Potential improvements to consider:

- attenuating to a shorter-lived time and sealing the token for use by the actor
- Support for different delimiters per URI scheme
- Revocation mechanisms
- Maximum delegation depth limits
- Lateral delegation with explicit permissions
- Audit trail in token blocks
