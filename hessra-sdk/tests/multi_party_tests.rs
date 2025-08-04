#[cfg(test)]
mod multi_party_tests {
    use hessra_sdk::{SignTokenRequest, SignTokenResponse, SignoffInfo, TokenResponse};
    use serde_json;

    #[test]
    fn test_signoff_info_serialization() {
        let signoff_info = SignoffInfo {
            component: "approval_service".to_string(),
            authorization_service: "https://approval.example.com".to_string(),
            public_key: "ed25519/abcdef1234567890".to_string(),
        };

        // Test serialization
        let json = serde_json::to_string(&signoff_info).unwrap();
        assert!(json.contains("approval_service"));
        assert!(json.contains("https://approval.example.com"));
        assert!(json.contains("ed25519/abcdef1234567890"));

        // Test deserialization
        let deserialized: SignoffInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.component, "approval_service");
        assert_eq!(
            deserialized.authorization_service,
            "https://approval.example.com"
        );
        assert_eq!(deserialized.public_key, "ed25519/abcdef1234567890");
    }

    #[test]
    fn test_sign_token_request_serialization() {
        let request = SignTokenRequest {
            token: "test_token_123".to_string(),
            resource: "sensitive_resource".to_string(),
            operation: "admin".to_string(),
        };

        // Test serialization
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test_token_123"));
        assert!(json.contains("sensitive_resource"));
        assert!(json.contains("admin"));

        // Test deserialization
        let deserialized: SignTokenRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.token, "test_token_123");
        assert_eq!(deserialized.resource, "sensitive_resource");
        assert_eq!(deserialized.operation, "admin");
    }

    #[test]
    fn test_sign_token_response_serialization() {
        let response = SignTokenResponse {
            response_msg: "Token signed successfully".to_string(),
            signed_token: Some("signed_token_456".to_string()),
        };

        // Test serialization
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Token signed successfully"));
        assert!(json.contains("signed_token_456"));

        // Test deserialization
        let deserialized: SignTokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.response_msg, "Token signed successfully");
        assert_eq!(
            deserialized.signed_token,
            Some("signed_token_456".to_string())
        );
    }

    #[test]
    fn test_token_response_with_pending_signoffs() {
        let signoff_info = SignoffInfo {
            component: "legal_dept".to_string(),
            authorization_service: "https://legal.example.com".to_string(),
            public_key: "ed25519/legal123456".to_string(),
        };

        let response = TokenResponse {
            response_msg: "Token issued with pending signoffs".to_string(),
            token: Some("initial_token_789".to_string()),
            pending_signoffs: Some(vec![signoff_info]),
        };

        // Test serialization
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Token issued with pending signoffs"));
        assert!(json.contains("initial_token_789"));
        assert!(json.contains("legal_dept"));
        assert!(json.contains("https://legal.example.com"));

        // Test deserialization
        let deserialized: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.response_msg,
            "Token issued with pending signoffs"
        );
        assert_eq!(deserialized.token, Some("initial_token_789".to_string()));
        assert!(deserialized.pending_signoffs.is_some());
        let pending = deserialized.pending_signoffs.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].component, "legal_dept");
    }

    #[test]
    fn test_token_response_without_pending_signoffs() {
        let response = TokenResponse {
            response_msg: "Token issued successfully".to_string(),
            token: Some("complete_token_999".to_string()),
            pending_signoffs: None,
        };

        // Test serialization - pending_signoffs should be omitted
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Token issued successfully"));
        assert!(json.contains("complete_token_999"));
        assert!(!json.contains("pending_signoffs")); // Should be omitted due to serde skip

        // Test deserialization
        let deserialized: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.response_msg, "Token issued successfully");
        assert_eq!(deserialized.token, Some("complete_token_999".to_string()));
        assert!(deserialized.pending_signoffs.is_none());
    }

    #[test]
    fn test_token_response_backward_compatibility() {
        // Test that the old TokenResponse format still works (without pending_signoffs field)
        let old_format_json = r#"{
            "response_msg": "Token issued",
            "token": "legacy_token_123"
        }"#;

        let deserialized: TokenResponse = serde_json::from_str(old_format_json).unwrap();
        assert_eq!(deserialized.response_msg, "Token issued");
        assert_eq!(deserialized.token, Some("legacy_token_123".to_string()));
        assert!(deserialized.pending_signoffs.is_none());
    }

    #[test]
    fn test_multi_party_token_flow_structure() {
        // Test the complete multi-party token flow data structures
        let signoff_info1 = SignoffInfo {
            component: "approval_service".to_string(),
            authorization_service: "https://approval.example.com".to_string(),
            public_key: "ed25519/approval123".to_string(),
        };

        let signoff_info2 = SignoffInfo {
            component: "security_team".to_string(),
            authorization_service: "https://security.example.com".to_string(),
            public_key: "ed25519/security456".to_string(),
        };

        // Step 1: Initial token response with pending signoffs
        let initial_response = TokenResponse {
            response_msg: "Multi-party token issued".to_string(),
            token: Some("initial_mp_token".to_string()),
            pending_signoffs: Some(vec![signoff_info1.clone(), signoff_info2.clone()]),
        };

        assert!(initial_response.pending_signoffs.is_some());
        assert_eq!(initial_response.pending_signoffs.as_ref().unwrap().len(), 2);

        // Step 2: First signoff request
        let _first_sign_request = SignTokenRequest {
            token: "initial_mp_token".to_string(),
            resource: "sensitive_data".to_string(),
            operation: "read".to_string(),
        };

        let first_sign_response = SignTokenResponse {
            response_msg: "Approved by approval service".to_string(),
            signed_token: Some("partially_signed_token".to_string()),
        };

        assert!(first_sign_response.signed_token.is_some());

        // Step 3: Second signoff request
        let _second_sign_request = SignTokenRequest {
            token: "partially_signed_token".to_string(),
            resource: "sensitive_data".to_string(),
            operation: "read".to_string(),
        };

        let second_sign_response = SignTokenResponse {
            response_msg: "Approved by security team".to_string(),
            signed_token: Some("fully_signed_token".to_string()),
        };

        assert!(second_sign_response.signed_token.is_some());

        // Verify the flow makes sense
        assert_ne!(
            initial_response.token.unwrap(),
            first_sign_response.signed_token.clone().unwrap()
        );
        assert_ne!(
            first_sign_response.signed_token.unwrap(),
            second_sign_response.signed_token.unwrap()
        );
    }
}
