//! Comprehensive unit tests for mimicry, fingerprint consistency, and snapshot fidelity.

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{json, Value};

    use crate::mimic::body::{transform_request_body, transform_ws_frame};
    use crate::mimic::headers::{sanitize_and_inject_headers, sanitize_and_inject_headers_for_request};
    use crate::mimic::identity::{
        derive_converged_thread_id, derive_converged_uuid_v4, extract_client_version_from_headers,
        extract_window_number, sanitize_workspace_path,
    };
    use crate::mimic::metadata::sanitize_client_metadata;
    use crate::mimic::types::{
        ConvergedIdentity, MimicError, UnknownFieldPolicy, ALLOWED_ACCOUNT_X_HEADERS,
        ALLOWED_FLAT_CLIENT_METADATA_KEYS, ALLOWED_RESPONSES_X_HEADERS,
        EXPLICITLY_STRIPPED_ATTESTATION_NAMES, EXPLICITLY_STRIPPED_TRACE_AND_TRACKING_NAMES,
        SUB2API_EXTENDED_ACCOUNT_X_HEADERS, SUB2API_EXTENDED_FLAT_CLIENT_METADATA_KEYS,
        SUB2API_EXTENDED_RESPONSES_X_HEADERS, UPSTREAM_ALLOWED_ACCOUNT_X_HEADERS,
        UPSTREAM_ALLOWED_FLAT_CLIENT_METADATA_KEYS, UPSTREAM_ALLOWED_RESPONSES_X_HEADERS,
        UPSTREAM_EXPLICITLY_STRIPPED_ACCOUNT_X_HEADERS,
        UPSTREAM_EXPLICITLY_STRIPPED_FLAT_CLIENT_METADATA_KEYS,
        UPSTREAM_EXPLICITLY_STRIPPED_RESPONSES_X_HEADERS,
    };

    #[test]
    fn deterministic_uuid_convergence_with_salt() {
        let salt1 = "deploy_salt_prod";
        let salt2 = "deploy_salt_staging";

        let id1 = derive_converged_uuid_v4("group_123", "codex-install-id", salt1);
        let id2 = derive_converged_uuid_v4("group_123", "codex-install-id", salt1);
        assert_eq!(id1, id2, "same seed & salt must produce identical installation_id");
        assert_eq!(id1.chars().nth(14), Some('4'), "must be UUIDv4");

        // Cloned DB with different deployment salt produces independent UUIDs
        let id_cloned = derive_converged_uuid_v4("group_123", "codex-install-id", salt2);
        assert_ne!(id1, id_cloned, "different salt must isolate cloned DBs");

        let th1 = derive_converged_thread_id("group_123", "client_sess_1", salt1);
        let th2 = derive_converged_thread_id("group_123", "client_sess_1", salt1);
        assert_eq!(th1, th2, "same client session must produce identical thread_id");
    }

    #[test]
    fn window_number_preserves_protocol_fidelity_across_compaction() {
        let identity_init = ConvergedIdentity::new("seed_compaction", Some("sess"), None, "salt", None, 0);
        assert_eq!(identity_init.window_number, 0);
        assert!(identity_init.window_id.ends_with(":0"));

        // After compaction advances to window 2
        let identity_compacted = ConvergedIdentity::new("seed_compaction", Some("sess"), None, "salt", None, 2);
        assert_eq!(identity_compacted.window_number, 2);
        assert!(identity_compacted.window_id.ends_with(":2"));
        assert_eq!(identity_compacted.thread_id, identity_init.thread_id, "thread_id remains stable across compaction");
    }

    #[test]
    fn extract_window_number_from_headers_and_metadata() {
        assert_eq!(extract_window_number(Some("019abc-def:3"), None), 3);
        assert_eq!(extract_window_number(Some("019abc-def:0"), None), 0);
        assert_eq!(extract_window_number(Some("5"), None), 5);

        let meta = json!({
            "window_number": 4,
            "window_id": "thread:4"
        });
        assert_eq!(extract_window_number(None, Some(&meta)), 4);
    }

    #[test]
    fn groups_have_distinct_organic_environments() {
        let env_a = ConvergedIdentity::new("group_team_alpha", None, None, "salt", Some("0.1.144"), 0);
        let env_b = ConvergedIdentity::new("group_finance_infra", None, None, "salt", Some("0.1.144"), 0);

        // Both are valid, realistic environments
        assert!(env_a.cwd.starts_with("/Users/") || env_a.cwd.starts_with("/home/"));
        assert!(env_b.cwd.starts_with("/Users/") || env_b.cwd.starts_with("/home/"));

        // Different groups have distinct paths and identities
        assert_ne!(env_a.installation_id, env_b.installation_id);
        assert_ne!(env_a.cwd, env_b.cwd);
        assert_eq!(env_a.client_version, "0.1.144");
        assert_eq!(env_b.client_version, "0.1.144");
    }

    #[test]
    fn exact_agent_header_version_extraction() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::USER_AGENT,
            HeaderValue::from_static("codex_cli_rs/0.144.1"),
        );
        let ver = extract_client_version_from_headers(&headers);
        assert_eq!(ver, Some("0.144.1".to_string()));

        let mut headers_oai = HeaderMap::new();
        headers_oai.insert(
            axum::http::header::USER_AGENT,
            HeaderValue::from_static("OpenAI/Codex/0.1.183 (Darwin arm64)"),
        );
        let ver_oai = extract_client_version_from_headers(&headers_oai);
        assert_eq!(ver_oai, Some("0.1.183".to_string()));
    }

    #[test]
    fn custom_device_id_is_pseudonymized() {
        let identity = ConvergedIdentity::new("seed", None, Some("raw_hardware_id_abc"), "salt", None, 0);
        assert_ne!(identity.installation_id, "raw_hardware_id_abc");
        assert_eq!(identity.installation_id.chars().nth(14), Some('4'));
    }

    #[test]
    fn fail_closed_metadata_sanitization_and_mimic() {
        let identity = ConvergedIdentity::new("test_seed", Some("client_sess"), None, "salt", Some("0.1.183"), 1);
        let mut meta = json!({
            "ws_request_header_traceparent": "00-trace-01",
            "ws_request_header_tracestate": "state-01",
            "window_number": 1,
            "session_id": "client_original_session",
            "thread_id": "client_original_thread",
        });

        // Explicitly stripped keys are stripped normally with Ok(())
        assert!(sanitize_client_metadata(&mut meta, &identity, UnknownFieldPolicy::Forbidden).is_ok());
        assert!(meta.get("ws_request_header_traceparent").is_none());
        assert!(meta.get("ws_request_header_tracestate").is_none());
        assert_eq!(meta.get("session_id").unwrap(), "client_original_session");
        assert_eq!(meta.get("thread_id").unwrap(), "client_original_thread");
        assert_eq!(meta.get("window_number").unwrap(), 1);

        // Unknown extra field in flat client_metadata -> Err(ForbiddenMetadataKey) (HTTP 403) under Forbidden policy
        let mut invalid_meta = json!({
            "unknown_extra_telemetry": "bad_field",
            "session_id": "sess_123"
        });
        let res = sanitize_client_metadata(&mut invalid_meta, &identity, UnknownFieldPolicy::Forbidden);
        assert_eq!(
            res,
            Err(MimicError::ForbiddenMetadataKey("unknown_extra_telemetry".to_string()))
        );

        // Unknown extra field in flat client_metadata under Strip policy -> Ok(()) and stripped!
        let mut strip_meta = json!({
            "unknown_extra_telemetry": "bad_field",
            "session_id": "sess_123"
        });
        let res_strip = sanitize_client_metadata(&mut strip_meta, &identity, UnknownFieldPolicy::Strip);
        assert!(res_strip.is_ok());
        assert!(strip_meta.get("unknown_extra_telemetry").is_none());
        assert_eq!(strip_meta.get("session_id").unwrap(), "sess_123");
    }

    #[test]
    fn fingerprint_double_check_and_window_consistency() {
        let identity = ConvergedIdentity::new("test_group_seed", Some("raw_client_session"), None, "salt_1", Some("0.1.183"), 2);
        assert_eq!(identity.window_number, 2);

        // 1. Consistent flat metadata and nested turn metadata passes with Ok(())
        let mut consistent_meta = json!({
            "session_id": "sess_123",
            "thread_id": "thread_abc",
            "window_id": "thread_abc:2",
            "window_number": 2,
            "previous_window_id": "thread_abc:1",
            "x-codex-turn-metadata": json!({
                "session_id": "sess_123",
                "thread_id": "thread_abc",
                "window_id": "thread_abc:2",
                "window_number": 2,
                "previous_window_id": "thread_abc:1",
                "workspaces": {
                    "/develop/sub2api": {
                        "associated_remote_urls": ["https://github.com/leaked/secret.git"]
                    }
                }
            }).to_string()
        });

        assert!(sanitize_client_metadata(&mut consistent_meta, &identity, UnknownFieldPolicy::Forbidden).is_ok());
        let tm_str = consistent_meta.get("x-codex-turn-metadata").unwrap().as_str().unwrap();
        assert!(!tm_str.contains("secret.git"));

        // 2. Diverging thread_id vs window_id prefix -> Err(ForbiddenDivergingFingerprint) (HTTP 403)
        let mut diverging_thread_meta = json!({
            "thread_id": "thread_diverged",
            "window_id": "thread_abc:2",
            "window_number": 2,
        });
        let err_th = sanitize_client_metadata(&mut diverging_thread_meta, &identity, UnknownFieldPolicy::Forbidden);
        assert!(matches!(err_th, Err(MimicError::ForbiddenDivergingFingerprint(_))));

        // 3. Diverging window_number vs window_id suffix -> Err(ForbiddenDivergingFingerprint) (HTTP 403)
        let mut diverging_win_meta = json!({
            "thread_id": "thread_abc",
            "window_id": "thread_abc:2",
            "window_number": 3,
        });
        let err_win = sanitize_client_metadata(&mut diverging_win_meta, &identity, UnknownFieldPolicy::Forbidden);
        assert!(matches!(err_win, Err(MimicError::ForbiddenDivergingFingerprint(_))));

        // 4. Diverging previous_window_id -> Err(ForbiddenDivergingFingerprint) (HTTP 403)
        let mut diverging_prev_meta = json!({
            "thread_id": "thread_abc",
            "window_id": "thread_abc:2",
            "window_number": 2,
            "previous_window_id": "thread_abc:0", // should be thread_abc:1
        });
        let err_prev = sanitize_client_metadata(&mut diverging_prev_meta, &identity, UnknownFieldPolicy::Forbidden);
        assert!(matches!(err_prev, Err(MimicError::ForbiddenDivergingFingerprint(_))));

        // 5. Diverging nested turn metadata -> Err(ForbiddenDivergingFingerprint) (HTTP 403)
        let mut diverging_nested_meta = json!({
            "session_id": "sess_123",
            "thread_id": "thread_abc",
            "window_id": "thread_abc:2",
            "window_number": 2,
            "x-codex-turn-metadata": json!({
                "session_id": "sess_DIFFERENT",
                "thread_id": "thread_abc",
            }).to_string()
        });
        let err_nested = sanitize_client_metadata(&mut diverging_nested_meta, &identity, UnknownFieldPolicy::Forbidden);
        assert!(matches!(err_nested, Err(MimicError::ForbiddenDivergingFingerprint(_))));

        // 6. Headers: missing required session-id or x-codex-window-id -> Err(ForbiddenMissingFingerprint) (HTTP 403)
        let mut missing_headers = HeaderMap::new();
        let err_missing = sanitize_and_inject_headers(&mut missing_headers, "test_group_seed", Some("sess"), None, "salt_1", Some("0.1.183"), 2, true, UnknownFieldPolicy::Forbidden);
        assert!(matches!(err_missing, Err(MimicError::ForbiddenMissingFingerprint(_))));

        // 7. Headers: diverging thread-id vs x-codex-window-id prefix -> Err(ForbiddenDivergingFingerprint) (HTTP 403)
        let mut div_headers = HeaderMap::new();
        div_headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_123"));
        div_headers.insert(HeaderName::from_static("thread-id"), HeaderValue::from_static("wrong_thread"));
        div_headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("actual_thread:2"));
        let err_hdr_div = sanitize_and_inject_headers(&mut div_headers, "test_group_seed", Some("sess_123"), None, "salt_1", Some("0.1.183"), 2, true, UnknownFieldPolicy::Forbidden);
        assert!(matches!(err_hdr_div, Err(MimicError::ForbiddenDivergingFingerprint(_))));

        // 8. Headers: consistent headers pass
        let mut valid_headers = HeaderMap::new();
        valid_headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_123"));
        valid_headers.insert(HeaderName::from_static("thread-id"), HeaderValue::from_static("actual_thread"));
        valid_headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("actual_thread:2"));
        assert!(sanitize_and_inject_headers(&mut valid_headers, "test_group_seed", Some("sess_123"), None, "salt_1", Some("0.1.183"), 2, true, UnknownFieldPolicy::Forbidden).is_ok());
        assert_eq!(valid_headers.get("originator").unwrap().to_str().unwrap(), "codex_cli_rs");
        assert_eq!(valid_headers.get("version").unwrap().to_str().unwrap(), "0.1.183");
    }

    #[test]
    fn window_id_bug_fix_and_compaction_lifecycle() {
        let identity_w0 = ConvergedIdentity::new("group_seed", Some("sess_1"), None, "salt", Some("0.1.183"), 0);
        let identity_w1 = ConvergedIdentity::new("group_seed", Some("sess_1"), None, "salt", Some("0.1.183"), 1);
        let identity_w2 = ConvergedIdentity::new("group_seed", Some("sess_1"), None, "salt", Some("0.1.183"), 2);
        let identity_w3 = ConvergedIdentity::new("group_seed", Some("sess_1"), None, "salt", Some("0.1.183"), 3);

        // 1. Initial Window 0: previous_window_id MUST NOT exist
        let mut valid_w0 = json!({
            "session_id": "sess_1",
            "thread_id": "th_abc",
            "window_id": "th_abc:0",
            "window_number": 0,
            "x-codex-turn-metadata": json!({
                "session_id": "sess_1",
                "thread_id": "th_abc",
                "window_id": "th_abc:0",
                "window_number": 0
            }).to_string()
        });
        assert!(sanitize_client_metadata(&mut valid_w0, &identity_w0, UnknownFieldPolicy::Forbidden).is_ok());

        // Window 0 with illegal previous_window_id in flat metadata -> 403 Forbidden
        let mut bug_w0_flat = json!({
            "session_id": "sess_1",
            "thread_id": "th_abc",
            "window_id": "th_abc:0",
            "window_number": 0,
            "previous_window_id": "th_abc:0", // Invalid! Window 0 cannot have previous window
        });
        let err_w0_flat = sanitize_client_metadata(&mut bug_w0_flat, &identity_w0, UnknownFieldPolicy::Forbidden);
        assert!(matches!(err_w0_flat, Err(MimicError::ForbiddenDivergingFingerprint(_))));

        // Window 0 with illegal previous_window_id in turn_metadata -> 403 Forbidden
        let mut bug_w0_nested = json!({
            "session_id": "sess_1",
            "thread_id": "th_abc",
            "window_id": "th_abc:0",
            "window_number": 0,
            "x-codex-turn-metadata": json!({
                "session_id": "sess_1",
                "thread_id": "th_abc",
                "window_id": "th_abc:0",
                "window_number": 0,
                "previous_window_id": "th_abc:0" // Invalid on Window 0!
            }).to_string()
        });
        let err_w0_nested = sanitize_client_metadata(&mut bug_w0_nested, &identity_w0, UnknownFieldPolicy::Forbidden);
        assert!(matches!(err_w0_nested, Err(MimicError::ForbiddenDivergingFingerprint(_))));

        // 2. Compaction Progression (Window 1 -> 2 -> 3)
        // Window 1: previous is th_abc:0
        let mut valid_w1 = json!({
            "session_id": "sess_1",
            "thread_id": "th_abc",
            "window_id": "th_abc:1",
            "window_number": 1,
            "previous_window_id": "th_abc:0",
            "x-codex-turn-metadata": json!({
                "session_id": "sess_1",
                "thread_id": "th_abc",
                "window_id": "th_abc:1",
                "window_number": 1,
                "previous_window_id": "th_abc:0"
            }).to_string()
        });
        assert!(sanitize_client_metadata(&mut valid_w1, &identity_w1, UnknownFieldPolicy::Forbidden).is_ok());

        // Window 2: previous is th_abc:1
        let mut valid_w2 = json!({
            "session_id": "sess_1",
            "thread_id": "th_abc",
            "window_id": "th_abc:2",
            "window_number": 2,
            "previous_window_id": "th_abc:1",
            "x-codex-turn-metadata": json!({
                "session_id": "sess_1",
                "thread_id": "th_abc",
                "window_id": "th_abc:2",
                "window_number": 2,
                "previous_window_id": "th_abc:1"
            }).to_string()
        });
        assert!(sanitize_client_metadata(&mut valid_w2, &identity_w2, UnknownFieldPolicy::Forbidden).is_ok());

        // Window 3: previous is th_abc:2
        let mut valid_w3 = json!({
            "session_id": "sess_1",
            "thread_id": "th_abc",
            "window_id": "th_abc:3",
            "window_number": 3,
            "previous_window_id": "th_abc:2",
            "x-codex-turn-metadata": json!({
                "session_id": "sess_1",
                "thread_id": "th_abc",
                "window_id": "th_abc:3",
                "window_number": 3,
                "previous_window_id": "th_abc:2"
            }).to_string()
        });
        assert!(sanitize_client_metadata(&mut valid_w3, &identity_w3, UnknownFieldPolicy::Forbidden).is_ok());

        // 3. Mismatched / Diverging Previous Window Detection (403 Forbidden)
        // Window 2 with wrong previous window number (th_abc:0 instead of th_abc:1)
        let mut bad_prev_num = json!({
            "session_id": "sess_1",
            "thread_id": "th_abc",
            "window_id": "th_abc:2",
            "window_number": 2,
            "previous_window_id": "th_abc:0" // Should be th_abc:1
        });
        assert!(matches!(
            sanitize_client_metadata(&mut bad_prev_num, &identity_w2, UnknownFieldPolicy::Forbidden),
            Err(MimicError::ForbiddenDivergingFingerprint(_))
        ));

        // Window 2 with wrong previous window thread (th_other:1 instead of th_abc:1)
        let mut bad_prev_thread = json!({
            "session_id": "sess_1",
            "thread_id": "th_abc",
            "window_id": "th_abc:2",
            "window_number": 2,
            "previous_window_id": "th_other:1"
        });
        assert!(matches!(
            sanitize_client_metadata(&mut bad_prev_thread, &identity_w2, UnknownFieldPolicy::Forbidden),
            Err(MimicError::ForbiddenDivergingFingerprint(_))
        ));

        // 4. Header Validation for Window Progression & Bug Fixes
        // Window 0 headers: valid
        let mut hdr_w0 = HeaderMap::new();
        hdr_w0.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_1"));
        hdr_w0.insert(HeaderName::from_static("thread-id"), HeaderValue::from_static("th_abc"));
        hdr_w0.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("th_abc:0"));
        assert!(sanitize_and_inject_headers(&mut hdr_w0, "group_seed", Some("sess_1"), None, "salt", Some("0.1.183"), 0, true, UnknownFieldPolicy::Forbidden).is_ok());

        // Window 0 headers with illegal previous_window_id in turn_metadata header -> 403 Forbidden
        let mut hdr_w0_bad = HeaderMap::new();
        hdr_w0_bad.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_1"));
        hdr_w0_bad.insert(HeaderName::from_static("thread-id"), HeaderValue::from_static("th_abc"));
        hdr_w0_bad.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("th_abc:0"));
        hdr_w0_bad.insert(
            HeaderName::from_static("x-codex-turn-metadata"),
            HeaderValue::from_static("{\"session_id\":\"sess_1\",\"thread_id\":\"th_abc\",\"window_id\":\"th_abc:0\",\"window_number\":0,\"previous_window_id\":\"th_abc:0\"}"),
        );
        let err_hdr_w0 = sanitize_and_inject_headers(&mut hdr_w0_bad, "group_seed", Some("sess_1"), None, "salt", Some("0.1.183"), 0, true, UnknownFieldPolicy::Forbidden);
        assert!(matches!(err_hdr_w0, Err(MimicError::ForbiddenDivergingFingerprint(_))));

        // Window 2 headers with matching previous_window_id in turn_metadata header -> Ok(())
        let mut hdr_w2 = HeaderMap::new();
        hdr_w2.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_1"));
        hdr_w2.insert(HeaderName::from_static("thread-id"), HeaderValue::from_static("th_abc"));
        hdr_w2.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("th_abc:2"));
        hdr_w2.insert(
            HeaderName::from_static("x-codex-turn-metadata"),
            HeaderValue::from_static("{\"session_id\":\"sess_1\",\"thread_id\":\"th_abc\",\"window_id\":\"th_abc:2\",\"window_number\":2,\"previous_window_id\":\"th_abc:1\"}"),
        );
        assert!(sanitize_and_inject_headers(&mut hdr_w2, "group_seed", Some("sess_1"), None, "salt", Some("0.1.183"), 2, true, UnknownFieldPolicy::Forbidden).is_ok());
    }

    #[test]
    fn subagent_and_parent_thread_consistency() {
        let identity = ConvergedIdentity::new("group_seed", Some("sess_1"), None, "salt", Some("0.1.183"), 0);

        // 1. Consistent parent_thread_id and subagent_header in metadata -> Ok(())
        let mut valid_meta = json!({
            "session_id": "sess_1",
            "thread_id": "th_child",
            "window_id": "th_child:0",
            "x-codex-parent-thread-id": "018f3a7e-4b21-7000-8000-112233445566",
            "x-openai-subagent": "collab_spawn",
            "x-codex-turn-metadata": json!({
                "session_id": "sess_1",
                "thread_id": "th_child",
                "window_id": "th_child:0",
                "parent_thread_id": "018f3a7e-4b21-7000-8000-112233445566",
                "subagent_header": "collab_spawn",
            }).to_string()
        });
        assert!(sanitize_client_metadata(&mut valid_meta, &identity, UnknownFieldPolicy::Forbidden).is_ok());

        // 2. Invalid parent_thread_id UUID -> 403 Forbidden
        let mut bad_uuid_meta = json!({
            "session_id": "sess_1",
            "thread_id": "th_child",
            "window_id": "th_child:0",
            "x-codex-parent-thread-id": "not-a-valid-uuid",
        });
        assert!(matches!(
            sanitize_client_metadata(&mut bad_uuid_meta, &identity, UnknownFieldPolicy::Forbidden),
            Err(MimicError::ForbiddenDivergingFingerprint(_))
        ));

        // 3. Diverging parent_thread_id between flat and nested -> 403 Forbidden
        let mut diverging_parent_meta = json!({
            "session_id": "sess_1",
            "thread_id": "th_child",
            "window_id": "th_child:0",
            "x-codex-parent-thread-id": "018f3a7e-4b21-7000-8000-112233445566",
            "x-codex-turn-metadata": json!({
                "session_id": "sess_1",
                "thread_id": "th_child",
                "window_id": "th_child:0",
                "parent_thread_id": "018f3a7e-4b21-7000-8000-999999999999", // Diverged!
            }).to_string()
        });
        assert!(matches!(
            sanitize_client_metadata(&mut diverging_parent_meta, &identity, UnknownFieldPolicy::Forbidden),
            Err(MimicError::ForbiddenDivergingFingerprint(_))
        ));

        // 4. Headers: consistent parent thread and subagent headers -> Ok(())
        let mut valid_sub_headers = HeaderMap::new();
        valid_sub_headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_1"));
        valid_sub_headers.insert(HeaderName::from_static("thread-id"), HeaderValue::from_static("th_child"));
        valid_sub_headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("th_child:0"));
        valid_sub_headers.insert(HeaderName::from_static("x-codex-parent-thread-id"), HeaderValue::from_static("018f3a7e-4b21-7000-8000-112233445566"));
        valid_sub_headers.insert(HeaderName::from_static("x-openai-subagent"), HeaderValue::from_static("collab_spawn"));
        assert!(sanitize_and_inject_headers(&mut valid_sub_headers, "group_seed", Some("sess_1"), None, "salt", Some("0.1.183"), 0, true, UnknownFieldPolicy::Forbidden).is_ok());

        // 5. Headers: invalid parent thread UUID -> 403 Forbidden
        let mut bad_uuid_headers = HeaderMap::new();
        bad_uuid_headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_1"));
        bad_uuid_headers.insert(HeaderName::from_static("thread-id"), HeaderValue::from_static("th_child"));
        bad_uuid_headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("th_child:0"));
        bad_uuid_headers.insert(HeaderName::from_static("x-codex-parent-thread-id"), HeaderValue::from_static("bad-uuid"));
        assert!(matches!(
            sanitize_and_inject_headers(&mut bad_uuid_headers, "group_seed", Some("sess_1"), None, "salt", Some("0.1.183"), 0, true, UnknownFieldPolicy::Forbidden),
            Err(MimicError::ForbiddenDivergingFingerprint(_))
        ));
    }

    #[test]
    fn headers_sanitization_preserves_turn_state_and_strips_tracking() {
        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_123"));
        headers.insert(HeaderName::from_static("traceparent"), HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"));
        headers.insert(HeaderName::from_static("cookie"), HeaderValue::from_static("oai_session=leaked_cookie"));
        headers.insert(HeaderName::from_static("x-oai-attestation"), HeaderValue::from_static("attest_token"));
        headers.insert(HeaderName::from_static("x-codex-turn-state"), HeaderValue::from_static("server_turn_state_token_123"));
        headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("client_th:2"));
        headers.insert(axum::http::header::USER_AGENT, HeaderValue::from_static("OpenAI/Codex/0.1.183 (Unknown 1.0)"));

        assert!(sanitize_and_inject_headers(&mut headers, "seed", Some("sess_123"), None, "salt", Some("0.1.183"), 2, true, UnknownFieldPolicy::Forbidden).is_ok());

        assert!(headers.get("traceparent").is_none());
        assert!(headers.get("cookie").is_none());
        assert!(headers.get("x-oai-attestation").is_none());
        // x-codex-turn-state MUST be preserved for server routing!
        assert_eq!(headers.get("x-codex-turn-state").unwrap().to_str().unwrap(), "server_turn_state_token_123");
        assert_eq!(headers.get("session-id").unwrap().to_str().unwrap(), "sess_123");
        assert!(headers.get("x-codex-window-id").unwrap().to_str().unwrap().ends_with(":2"));

        // User-Agent normalized to reflect simulated OS and arch
        let ua = headers.get(axum::http::header::USER_AGENT).unwrap().to_str().unwrap();
        assert!(ua.contains("Darwin") || ua.contains("Linux"));
    }

    #[test]
    fn transform_request_body_roundtrip() {
        let input = json!({
            "model": "gpt-4o",
            "session_id": "client_session_abc",
            "prompt_cache_key": "client_session_abc",
            "client_metadata": {
                "session_id": "client_session_abc",
                "ws_request_header_traceparent": "00-trace-01",
                "window_number": 2,
            }
        });
        let raw = serde_json::to_vec(&input).unwrap();
        let transformed = transform_request_body(&raw, "seed_42", None, "salt_1", Some("0.1.183"), None, UnknownFieldPolicy::Forbidden).unwrap().unwrap();
        let parsed: Value = serde_json::from_slice(&transformed).unwrap();

        assert_eq!(parsed.get("model").unwrap(), "gpt-4o");
        let meta = parsed.get("client_metadata").unwrap();

        // Explicitly stripped tracking keys stripped
        assert!(meta.get("ws_request_header_traceparent").is_none());

        // Allowed fields kept without mutation
        assert_eq!(meta.get("session_id").unwrap(), "client_session_abc");
        assert_eq!(meta.get("window_number").unwrap(), 2);
        assert_eq!(parsed.get("prompt_cache_key").unwrap(), "client_session_abc");

        // Unknown extra field returns Forbidden error under Forbidden policy
        let bad_input = json!({
            "client_metadata": {
                "unauthorized_field": "123"
            }
        });
        let bad_raw = serde_json::to_vec(&bad_input).unwrap();
        let res = transform_request_body(&bad_raw, "seed_42", None, "salt_1", Some("0.1.183"), None, UnknownFieldPolicy::Forbidden);
        assert_eq!(res, Err(MimicError::ForbiddenMetadataKey("unauthorized_field".to_string())));

        // Unknown extra field stripped under Strip policy
        let res_strip = transform_request_body(&bad_raw, "seed_42", None, "salt_1", Some("0.1.183"), None, UnknownFieldPolicy::Strip).unwrap().unwrap();
        let parsed_strip: Value = serde_json::from_slice(&res_strip).unwrap();
        assert!(parsed_strip.pointer("/client_metadata/unauthorized_field").is_none());
    }

    #[test]
    fn transform_ws_frame_roundtrip() {
        let input = json!({
            "type": "response.create",
            "client_metadata": {
                "ws_request_header_tracestate": "state-01",
                "session_id": "ws_client_sess",
                "window_number": 1,
            }
        });
        let raw_str = serde_json::to_string(&input).unwrap();
        let transformed = transform_ws_frame(&raw_str, "seed_ws", None, "salt_ws", Some("0.1.183"), None, UnknownFieldPolicy::Forbidden).unwrap().unwrap();
        let parsed: Value = serde_json::from_str(&transformed).unwrap();

        let meta = parsed.get("client_metadata").unwrap();
        assert!(meta.get("ws_request_header_tracestate").is_none());
        assert_eq!(meta.get("session_id").unwrap(), "ws_client_sess");
        assert_eq!(meta.get("window_number").unwrap(), 1);

        // Unknown extra field returns Forbidden error under Forbidden policy
        let bad_input = json!({
            "client_metadata": {
                "bad_telemetry": "leak"
            }
        });
        let bad_str = serde_json::to_string(&bad_input).unwrap();
        let res = transform_ws_frame(&bad_str, "seed_ws", None, "salt_ws", Some("0.1.183"), None, UnknownFieldPolicy::Forbidden);
        assert_eq!(res, Err(MimicError::ForbiddenMetadataKey("bad_telemetry".to_string())));

        // Unknown extra field stripped under Strip policy
        let res_strip = transform_ws_frame(&bad_str, "seed_ws", None, "salt_ws", Some("0.1.183"), None, UnknownFieldPolicy::Strip).unwrap().unwrap();
        let parsed_strip: Value = serde_json::from_str(&res_strip).unwrap();
        assert!(parsed_strip.pointer("/client_metadata/bad_telemetry").is_none());
    }

    #[test]
    fn workspaces_strip_remote_url_and_preserve_sandbox() {
        let identity = ConvergedIdentity::new("test_seed", Some("client_sess"), None, "salt", Some("0.1.183"), 1);
        let turn_meta_raw = json!({
            "installation_id": "inst_123",
            "session_id": "sess_123",
            "sandbox": "seatbelt",
            "sandbox_mode": "danger-full-access",
            "workspaces": {
                "/Users/alice/proprietary/project": {
                    "associated_remote_urls": {
                        "origin": "https://token:secret@github.com/secret-org/proprietary-repo.git"
                    },
                    "latest_git_commit_hash": "a1b2c3d4e5f67890",
                    "has_changes": false
                }
            }
        });

        let mut meta = json!({
            "session_id": "sess_123",
            "x-codex-turn-metadata": serde_json::to_string(&turn_meta_raw).unwrap(),
        });

        assert!(sanitize_client_metadata(&mut meta, &identity, UnknownFieldPolicy::Forbidden).is_ok());

        let sanitized_tm_str = meta.get("x-codex-turn-metadata").unwrap().as_str().unwrap();
        let sanitized_tm: Value = serde_json::from_str(sanitized_tm_str).unwrap();

        // sandbox & sandbox_mode are preserved!
        assert_eq!(sanitized_tm.get("sandbox").unwrap(), "seatbelt");
        assert_eq!(sanitized_tm.get("sandbox_mode").unwrap(), "danger-full-access");

        // workspaces associated_remote_urls is stripped, while commit hash & has_changes are kept, and path is sanitized
        let workspaces = sanitized_tm.get("workspaces").unwrap().as_object().unwrap();
        let (ws_path, ws_info) = workspaces.iter().next().unwrap();
        assert!(ws_path.ends_with("/project"));
        assert!(ws_info.get("associated_remote_urls").is_none());
        assert_eq!(ws_info.get("latest_git_commit_hash").unwrap(), "a1b2c3d4e5f67890");
        assert_eq!(ws_info.get("has_changes").unwrap(), false);
    }

    #[test]
    fn git_branch_uses_normal_names() {
        for seed_idx in 0..20 {
            let identity = ConvergedIdentity::new(&format!("seed_{seed_idx}"), None, None, "salt", None, 0);
            assert!(
                matches!(identity.git_branch.as_str(), "main" | "master" | "develop" | "testing"),
                "git_branch '{}' must be one of standard normal branches",
                identity.git_branch
            );
        }
    }

    #[test]
    fn user_agent_and_workspace_path_are_mutually_consistent() {
        for seed_idx in 0..10 {
            let seed = format!("seed_consistency_{seed_idx}");
            let identity = ConvergedIdentity::new(&seed, None, None, "salt", Some("0.1.183"), 0);

            // Workspace path
            let ws_path = sanitize_workspace_path("/Users/raw_user/private_dir/my_tool", &identity);
            if identity.os == "darwin" {
                assert!(ws_path.starts_with("/Users/"), "Darwin must produce /Users/ path: {}", ws_path);
            } else {
                assert!(ws_path.starts_with("/home/"), "Linux must produce /home/ path: {}", ws_path);
            }

            // User-Agent
            let mut headers = HeaderMap::new();
            headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_1"));
            headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("th_1:0"));
            headers.insert(axum::http::header::USER_AGENT, HeaderValue::from_static("OpenAI/Codex/0.1.183 (Unknown)"));
            assert!(sanitize_and_inject_headers(&mut headers, &seed, None, None, "salt", Some("0.1.183"), 0, true, UnknownFieldPolicy::Forbidden).is_ok());

            let ua = headers.get(axum::http::header::USER_AGENT).unwrap().to_str().unwrap();
            if identity.os == "darwin" {
                assert!(ua.contains("Darwin"), "Darwin OS must reflect in User-Agent: {}", ua);
            } else {
                assert!(ua.contains("Linux"), "Linux OS must reflect in User-Agent: {}", ua);
            }
        }
    }

    #[test]
    fn account_vs_inference_header_fail_closed() {
        let mut account_headers = HeaderMap::new();
        account_headers.insert(HeaderName::from_static("authorization"), HeaderValue::from_static("Bearer token123"));
        account_headers.insert(HeaderName::from_static("chatgpt-account-id"), HeaderValue::from_static("acc_org_123"));
        account_headers.insert(HeaderName::from_static("x-openai-fedramp"), HeaderValue::from_static("true"));
        account_headers.insert(HeaderName::from_static("traceparent"), HeaderValue::from_static("00-trace-01"));
        account_headers.insert(HeaderName::from_static("x-oai-attestation"), HeaderValue::from_static("attest_token"));

        // Account path (e.g. /wham/usage, /api/codex/usage, /status):
        assert!(sanitize_and_inject_headers(&mut account_headers, "seed", None, None, "salt", Some("0.1.183"), 0, false, UnknownFieldPolicy::Forbidden).is_ok());

        assert!(account_headers.get("authorization").is_some());
        assert!(account_headers.get("chatgpt-account-id").is_some());
        assert!(account_headers.get("x-openai-fedramp").is_some());
        assert!(account_headers.get("user-agent").is_some());
        assert!(account_headers.get("traceparent").is_none());
        assert!(account_headers.get("x-oai-attestation").is_none());

        // Unknown extra x- header on account path -> Err(ForbiddenHeader) (HTTP 403) under Forbidden policy
        let mut bad_account_headers = HeaderMap::new();
        bad_account_headers.insert(HeaderName::from_static("x-custom-leak"), HeaderValue::from_static("drop_me"));
        let err = sanitize_and_inject_headers(&mut bad_account_headers, "seed", None, None, "salt", Some("0.1.183"), 0, false, UnknownFieldPolicy::Forbidden);
        assert_eq!(err, Err(MimicError::ForbiddenHeader("x-custom-leak".to_string())));

        // Unknown extra x- header on account path under Strip policy -> Ok(()) and stripped
        let mut strip_account_headers = HeaderMap::new();
        strip_account_headers.insert(HeaderName::from_static("x-custom-leak"), HeaderValue::from_static("drop_me"));
        let res_strip = sanitize_and_inject_headers(&mut strip_account_headers, "seed", None, None, "salt", Some("0.1.183"), 0, false, UnknownFieldPolicy::Strip);
        assert!(res_strip.is_ok());
        assert!(strip_account_headers.get("x-custom-leak").is_none());

        let mut inference_headers = HeaderMap::new();
        inference_headers.insert(HeaderName::from_static("authorization"), HeaderValue::from_static("Bearer token123"));
        inference_headers.insert(HeaderName::from_static("chatgpt-account-id"), HeaderValue::from_static("acc_org_123"));
        inference_headers.insert(HeaderName::from_static("originator"), HeaderValue::from_static("codex_cli_rs"));
        inference_headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_123"));
        inference_headers.insert(HeaderName::from_static("thread-id"), HeaderValue::from_static("thread_123"));
        inference_headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("thread_123:0"));
        inference_headers.insert(HeaderName::from_static("x-codex-turn-state"), HeaderValue::from_static("state_token"));
        inference_headers.insert(HeaderName::from_static("traceparent"), HeaderValue::from_static("00-trace-01"));
        inference_headers.insert(HeaderName::from_static("x-oai-attestation"), HeaderValue::from_static("attest_token"));

        // Inference path (e.g. /responses, /responses/compact):
        assert!(sanitize_and_inject_headers(&mut inference_headers, "seed", None, None, "salt", Some("0.1.183"), 0, true, UnknownFieldPolicy::Forbidden).is_ok());

        assert!(inference_headers.get("authorization").is_some());
        assert!(inference_headers.get("chatgpt-account-id").is_some());
        assert!(inference_headers.get("originator").is_some());
        assert!(inference_headers.get("session-id").is_some());
        assert!(inference_headers.get("thread-id").is_some());
        assert!(inference_headers.get("x-codex-window-id").is_some());
        assert!(inference_headers.get("x-codex-turn-state").is_some());
        assert!(inference_headers.get("traceparent").is_none());
        assert!(inference_headers.get("x-oai-attestation").is_none());

        // Unknown extra x- header on inference path -> Err(ForbiddenHeader) (HTTP 403) under Forbidden policy
        let mut bad_inference_headers = HeaderMap::new();
        bad_inference_headers.insert(HeaderName::from_static("x-custom-leak"), HeaderValue::from_static("drop_me"));
        let err2 = sanitize_and_inject_headers(&mut bad_inference_headers, "seed", None, None, "salt", Some("0.1.183"), 0, true, UnknownFieldPolicy::Forbidden);
        assert_eq!(err2, Err(MimicError::ForbiddenHeader("x-custom-leak".to_string())));

        // Unknown extra x- header on inference path under Strip policy -> Ok(()) and stripped
        let mut strip_inference_headers = HeaderMap::new();
        strip_inference_headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_123"));
        strip_inference_headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("th_123:0"));
        strip_inference_headers.insert(HeaderName::from_static("x-custom-leak"), HeaderValue::from_static("drop_me"));
        let res_strip2 = sanitize_and_inject_headers(&mut strip_inference_headers, "seed", None, None, "salt", Some("0.1.183"), 0, true, UnknownFieldPolicy::Strip);
        assert!(res_strip2.is_ok());
        assert!(strip_inference_headers.get("x-custom-leak").is_none());

        // Accept: application/json on inference path -> Err(ForbiddenAcceptHeader) (HTTP 403)
        let mut json_accept_headers = HeaderMap::new();
        json_accept_headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_123"));
        json_accept_headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("th_123:0"));
        json_accept_headers.insert(axum::http::header::ACCEPT, HeaderValue::from_static("application/json"));
        let json_err = sanitize_and_inject_headers(&mut json_accept_headers, "seed", None, None, "salt", Some("0.1.183"), 0, true, UnknownFieldPolicy::Forbidden);
        assert_eq!(json_err, Err(MimicError::ForbiddenAcceptHeader("application/json".to_string())));

        // Accept: text/event-stream on inference path -> Ok(())
        let mut sse_accept_headers = HeaderMap::new();
        sse_accept_headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_123"));
        sse_accept_headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("th_123:0"));
        sse_accept_headers.insert(axum::http::header::ACCEPT, HeaderValue::from_static("text/event-stream"));
        assert!(sanitize_and_inject_headers(&mut sse_accept_headers, "seed", None, None, "salt", Some("0.1.183"), 0, true, UnknownFieldPolicy::Forbidden).is_ok());
        assert_eq!(sse_accept_headers.get("accept").unwrap().to_str().unwrap(), "text/event-stream");
    }

    #[test]
    fn compact_accepts_json_without_changing_gateway_identity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("session-id"),
            HeaderValue::from_static("gateway-session"),
        );
        headers.insert(
            HeaderName::from_static("thread-id"),
            HeaderValue::from_static("gateway-thread"),
        );
        headers.insert(
            HeaderName::from_static("x-codex-window-id"),
            HeaderValue::from_static("gateway-thread:2"),
        );
        headers.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );

        assert!(sanitize_and_inject_headers_for_request(
            &mut headers,
            "profile-seed",
            Some("gateway-session"),
            None,
            "deployment-salt",
            Some("0.1.183"),
            2,
            true,
            true,
            UnknownFieldPolicy::Forbidden,
        )
        .is_ok());
        assert_eq!(
            headers.get("accept").unwrap().to_str().unwrap(),
            "application/json"
        );
        assert_eq!(
            headers.get("session-id").unwrap().to_str().unwrap(),
            "gateway-session"
        );
        assert_eq!(
            headers.get("thread-id").unwrap().to_str().unwrap(),
            "gateway-thread"
        );
    }

    #[test]
    fn upstream_codex_wire_snapshot_exact_fidelity() {
        use std::collections::BTreeSet;

        let snapshot_raw = include_str!("../../tests/fixtures/codex_wire_snapshot.json");
        let snapshot: Value = serde_json::from_str(snapshot_raw).expect("valid codex_wire_snapshot.json");

        // 1. Exact Set Match for Account x- headers (allow + explicit_strip == upstream snapshot)
        let snapshot_account_x: BTreeSet<String> = snapshot
            .pointer("/account_status_check/http_headers")
            .and_then(|v| v.as_array())
            .expect("account http_headers list")
            .iter()
            .map(|h| h.get("name").and_then(|v| v.as_str()).unwrap().to_ascii_lowercase())
            .filter(|n| n.starts_with("x-"))
            .collect();

        let code_account_x: BTreeSet<String> = UPSTREAM_ALLOWED_ACCOUNT_X_HEADERS
            .iter()
            .chain(UPSTREAM_EXPLICITLY_STRIPPED_ACCOUNT_X_HEADERS.iter())
            .map(|s| s.to_ascii_lowercase())
            .collect();

        assert_eq!(
            code_account_x, snapshot_account_x,
            "Account x- headers mismatch with upstream snapshot! Must be EXACT: (allowed + explicitly stripped) == snapshot"
        );

        // 2. Exact Set Match for Responses x- headers (allow + explicit_strip == upstream snapshot)
        let http_resp_x = snapshot
            .pointer("/responses_http/http_headers")
            .and_then(|v| v.as_array())
            .expect("responses_http http_headers list")
            .iter()
            .map(|h| h.get("name").and_then(|v| v.as_str()).unwrap().to_ascii_lowercase())
            .filter(|n| n.starts_with("x-"));

        let ws_resp_x = snapshot
            .pointer("/responses_websocket/handshake_http_headers")
            .and_then(|v| v.as_array())
            .expect("responses_websocket handshake_http_headers list")
            .iter()
            .map(|h| h.get("name").and_then(|v| v.as_str()).unwrap().to_ascii_lowercase())
            .filter(|n| n.starts_with("x-"));

        let snapshot_responses_x: BTreeSet<String> = http_resp_x.chain(ws_resp_x).collect();

        let code_responses_x: BTreeSet<String> = UPSTREAM_ALLOWED_RESPONSES_X_HEADERS
            .iter()
            .chain(UPSTREAM_EXPLICITLY_STRIPPED_RESPONSES_X_HEADERS.iter())
            .map(|s| s.to_ascii_lowercase())
            .collect();

        assert_eq!(
            code_responses_x, snapshot_responses_x,
            "Responses x- headers mismatch with upstream snapshot! Must be EXACT: (allowed + explicitly stripped) == snapshot"
        );

        // 3. Exact Set Match for Flat client_metadata (allow + explicit_strip == upstream snapshot)
        let http_cm = snapshot
            .pointer("/responses_http/client_metadata")
            .and_then(|v| v.as_array())
            .expect("responses_http client_metadata list")
            .iter()
            .map(|item| item.get("name").and_then(|v| v.as_str()).unwrap().to_string());

        let ws_cm = snapshot
            .pointer("/responses_websocket/client_metadata_ws_additions")
            .and_then(|v| v.as_array())
            .expect("responses_websocket client_metadata_ws_additions list")
            .iter()
            .map(|item| item.get("name").and_then(|v| v.as_str()).unwrap().to_string());

        let snapshot_cm: BTreeSet<String> = http_cm.chain(ws_cm).collect();

        let code_cm: BTreeSet<String> = UPSTREAM_ALLOWED_FLAT_CLIENT_METADATA_KEYS
            .iter()
            .chain(UPSTREAM_EXPLICITLY_STRIPPED_FLAT_CLIENT_METADATA_KEYS.iter())
            .map(|s| s.to_string())
            .collect();

        assert_eq!(
            code_cm, snapshot_cm,
            "Flat client_metadata keys mismatch with upstream snapshot! Must be EXACT: (allowed + explicitly stripped) == snapshot"
        );

        // 4. Exact Set Match for Effective ALLOWED_FLAT_CLIENT_METADATA_KEYS & ALLOWED_RESPONSES_X_HEADERS
        let expected_allowed_cm: BTreeSet<String> = UPSTREAM_ALLOWED_FLAT_CLIENT_METADATA_KEYS
            .iter()
            .chain(SUB2API_EXTENDED_FLAT_CLIENT_METADATA_KEYS.iter())
            .map(|s| s.to_string())
            .collect();

        let actual_allowed_cm: BTreeSet<String> = ALLOWED_FLAT_CLIENT_METADATA_KEYS
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            actual_allowed_cm, expected_allowed_cm,
            "ALLOWED_FLAT_CLIENT_METADATA_KEYS must match (UPSTREAM_ALLOWED + SUB2API_EXTENDED) exactly"
        );

        let expected_allowed_resp_x: BTreeSet<String> = UPSTREAM_ALLOWED_RESPONSES_X_HEADERS
            .iter()
            .chain(SUB2API_EXTENDED_RESPONSES_X_HEADERS.iter())
            .map(|s| s.to_ascii_lowercase())
            .collect();

        let actual_allowed_resp_x: BTreeSet<String> = ALLOWED_RESPONSES_X_HEADERS
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        assert_eq!(
            actual_allowed_resp_x, expected_allowed_resp_x,
            "ALLOWED_RESPONSES_X_HEADERS must match (UPSTREAM_ALLOWED + SUB2API_EXTENDED) exactly"
        );

        let expected_allowed_acc_x: BTreeSet<String> = UPSTREAM_ALLOWED_ACCOUNT_X_HEADERS
            .iter()
            .chain(SUB2API_EXTENDED_ACCOUNT_X_HEADERS.iter())
            .map(|s| s.to_ascii_lowercase())
            .collect();

        let actual_allowed_acc_x: BTreeSet<String> = ALLOWED_ACCOUNT_X_HEADERS
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        assert_eq!(
            actual_allowed_acc_x, expected_allowed_acc_x,
            "ALLOWED_ACCOUNT_X_HEADERS must match (UPSTREAM_ALLOWED + SUB2API_EXTENDED) exactly"
        );

        // 5. Explicit strip enums must contain the exact names of stripped items
        for stripped in UPSTREAM_EXPLICITLY_STRIPPED_RESPONSES_X_HEADERS {
            assert!(
                EXPLICITLY_STRIPPED_ATTESTATION_NAMES.contains(stripped)
                    || EXPLICITLY_STRIPPED_TRACE_AND_TRACKING_NAMES.contains(stripped),
                "Stripped response header '{stripped}' must be registered in explicit strip enums!"
            );
        }
        for stripped in UPSTREAM_EXPLICITLY_STRIPPED_FLAT_CLIENT_METADATA_KEYS {
            assert!(
                EXPLICITLY_STRIPPED_TRACE_AND_TRACKING_NAMES.contains(stripped)
                    || EXPLICITLY_STRIPPED_ATTESTATION_NAMES.contains(stripped),
                "Stripped metadata key '{stripped}' must be registered in explicit strip enums!"
            );
        }

        // 6. Direct Forbidden 403 test on unrecognized header & metadata key
        let mut test_headers = HeaderMap::new();
        test_headers.insert(HeaderName::from_static("x-future-upstream-unresolved-header"), HeaderValue::from_static("drop"));
        let hdr_res = sanitize_and_inject_headers(&mut test_headers, "seed", None, None, "salt", None, 0, false, UnknownFieldPolicy::Forbidden);
        assert_eq!(
            hdr_res,
            Err(MimicError::ForbiddenHeader("x-future-upstream-unresolved-header".to_string()))
        );

        let mut test_cm = json!({
            "client_metadata": {
                "session_id": "sess_1",
                "unrecognized_key_123": "drop_me"
            }
        });
        let identity = ConvergedIdentity::new("seed", Some("sess_1"), None, "salt", None, 0);
        let cm_res = sanitize_client_metadata(test_cm.get_mut("client_metadata").unwrap(), &identity, UnknownFieldPolicy::Forbidden);
        assert_eq!(
            cm_res,
            Err(MimicError::ForbiddenMetadataKey("unrecognized_key_123".to_string()))
        );
    }
