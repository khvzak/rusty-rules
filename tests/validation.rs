#![cfg(feature = "validation")]

use std::net::IpAddr;

use rusty_rules::{BoolMatcher, Engine, IpMatcher, NumberMatcher, RegexMatcher, StringMatcher};
use serde_json::json;

#[test]
fn test_validation() {
    let mut engine = Engine::<()>::new();

    // Register various matchers
    engine.register_fetcher("string", StringMatcher, |_, _| Ok("test".into()));
    engine.register_fetcher("number", NumberMatcher, |_, _| Ok(42.into()));
    engine.register_fetcher("bool", BoolMatcher, |_, _| Ok(true.into()));
    engine.register_fetcher("ip", IpMatcher, |_, _| {
        Ok("127.0.0.1".parse::<IpAddr>()?.into())
    });
    engine.register_fetcher("ipv6", IpMatcher, |_, _| {
        Ok("::1".parse::<IpAddr>()?.into())
    });
    engine.register_fetcher("pattern", RegexMatcher, |_, _| Ok("abc".into()));

    // Register custom operator
    engine.register_operator("custom_op", |value: serde_json::Value| {
        let value = value.as_bool().unwrap_or(false);
        Ok(rusty_rules::Operator::Custom(Box::new(move |_, _| {
            Ok(value)
        })))
    });

    // Test valid rules
    let valid_rules = vec![
        json!({
            "all": [
                { "string": "value" },
                { "string": { "<": "xyz" } },
                { "string": { "in": ["a", "b", "c"] } },
                { "string": { "re": "\\w+" } },
                { "number": 123 },
                { "number": { ">=": 100 } },
                { "number": { "in": [1, 2, 3] } },
                { "bool": true },
                { "ip": "192.168.0.1" },
                { "ip": "192.168.0.0/24" },
                { "ip": ["10.0.0.1", "172.16.0.0/12"] },
                { "ipv6": "2001:db8::ff00:42:8329" },
                { "ipv6": "2001:db8::/32" },
                { "ipv6": ["2001:db8::ff00:42:8329", "2001:db8::/32"] },
                { "string": { "custom_op": true } },
                { "pattern": "abc\\d+" },
                { "string": { "custom_op": true } }
            ]
        }),
        json!({ "not": { "string": "invalid" } }),
        json!({
            "any": [
                { "string": "value1" },
                { "string": "value2" }
            ]
        }),
    ];

    for (i, rule) in valid_rules.iter().enumerate() {
        let is_valid = engine.validate_rule(rule).is_ok();
        assert!(is_valid, "rule #{i} should be valid");
    }

    // Test invalid rules
    let invalid_rules = vec![
        // Invalid operator
        json!({ "string": { "invalid_op": 123 } }),
        // Type mismatch
        json!({ "number": "not a number" }),
        json!({ "bool": 123 }),
        json!({ "ip": "not an ip" }),
        // Invalid fetcher
        json!({ "unknown_fetcher": "value" }),
        // Wrong operator value type
        json!({ "number": { "<": "string" } }),
        json!({ "string": { "re": 123 } }),
        json!({ "string": { "custom_op": true, "re": false } }),
    ];

    for (i, rule) in invalid_rules.iter().enumerate() {
        let is_valid = engine.validate_rule(rule).is_ok();
        assert!(!is_valid, "rule #{i} should be invalid");
    }
}
