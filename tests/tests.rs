use std::collections::HashMap;
use std::net::IpAddr;

use rusty_rules::{Engine, MatcherType, Value};
use serde_json::json;

// Test context structure
#[derive(Debug)]
struct TestContext {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    params: HashMap<String, String>,
    ip: IpAddr,
    port: i64,
}

fn create_test_context() -> TestContext {
    TestContext {
        method: "GET".to_string(),
        path: "/api/v1/test".to_string(),
        headers: {
            let mut h = HashMap::new();
            h.insert("host".to_string(), "www.example.com".to_string());
            h.insert("user-agent".to_string(), "test-agent".to_string());
            h
        },
        params: {
            let mut p = HashMap::new();
            p.insert("a".to_string(), "1".to_string());
            p.insert("b".to_string(), "2".to_string());
            p
        },
        ip: "127.0.0.1".parse().unwrap(),
        port: 8080,
    }
}

fn setup_engine() -> Engine<TestContext> {
    let mut engine = Engine::new();

    // Register method fetcher
    engine.register_fetcher("method", MatcherType::String, |ctx: &TestContext, _args| {
        Some(Value::from(&ctx.method))
    });

    // Register path fetcher
    engine.register_fetcher("path", MatcherType::StringRe, |ctx, _args| {
        Some(Value::from(&ctx.path))
    });

    // Register header fetcher
    engine.register_fetcher("header", MatcherType::String, |ctx, args| {
        args.first()
            .and_then(|name| ctx.headers.get(name))
            .map(Value::from)
    });

    // Register param fetcher
    engine.register_fetcher("param", MatcherType::String, |ctx, args| {
        args.first()
            .and_then(|name| ctx.params.get(name))
            .map(Value::from)
    });

    // Register ip fetcher
    engine.register_fetcher("ip", MatcherType::Ip, |ctx, _args| Some(Value::Ip(ctx.ip)));

    // Register port fetcher
    engine.register_fetcher("port", MatcherType::Number, |ctx, _args| {
        Some(Value::from(ctx.port))
    });

    engine
}

#[test]
fn test_simple_conditions() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .parse_json(&json!({
            "method": "GET",
            "header(host)": "www.example.com",
            "port": {">": 80}
        }))
        .unwrap();

    assert!(engine.evaluate(&rule, &ctx));
}

#[test]
fn test_logical_operators() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .parse_json(&json!({
            "any": [
                {"method": "POST"},
                {
                    "all": [
                        {"method": "GET"},
                        {"param(a)": "1"}
                    ]
                }
            ],
            "not": {
                "method": "PUT"
            }
        }))
        .unwrap();

    assert!(engine.evaluate(&rule, &ctx));
}

#[test]
fn test_regex_matching() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .parse_json(&json!({
            "path": "^/api/v1/.*$",
            "header(host)": {
                "re": "^www\\.example\\.com$"
            }
        }))
        .unwrap();

    assert!(engine.evaluate(&rule, &ctx));
}

#[test]
fn test_ip_matching() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .parse_json(&json!({
            "ip": ["127.0.0.1", "::1/128"]
        }))
        .unwrap();

    assert!(engine.evaluate(&rule, &ctx));
}

#[test]
fn test_number_comparisons() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .parse_json(&json!([
            {"port": {">=": 8000}},
            {"port": {"<": 9000}},
        ]))
        .unwrap();

    assert!(engine.evaluate(&rule, &ctx));
}

#[test]
fn test_unknown_fetcher() {
    let engine = setup_engine();

    let result = engine.parse_json(&json!({
        "unknown_fetcher": "value"
    }));

    assert!(result.is_err());
}

#[test]
fn test_empty_rule() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine.parse_json(&json!({})).unwrap();
    assert!(engine.evaluate(&rule, &ctx));
}

#[test]
fn test_invalid_regex() {
    let engine = setup_engine();

    let result = engine.parse_json(&json!({
        "path": {
            "re": "[" // invalid regex pattern
        }
    }));

    assert!(result.is_err());
}

#[test]
fn test_invalid_ip() {
    let engine = setup_engine();

    let result = engine.parse_json(&json!({
        "ip": "not.an.ip.address"
    }));

    assert!(result.is_err());
}

#[test]
fn test_type_mismatch() {
    let engine = setup_engine();

    assert!(
        engine
            .parse_json(&json!({
                "port": "8080"  // port expects a number, but got string
            }))
            .is_err()
    );
}

#[test]
fn test_complex_rules() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .parse_json(&json!({
            "all": [
                {
                    "any": [
                        {"method": "GET"},
                        {"method": "POST"}
                    ]
                },
                {
                    "not": {
                        "any": [
                            {"port": {"<": 80}},
                            {"port": {">": 9000}}
                        ]
                    }
                },
                {"header(host)": "www.example.com"},
                {"path": "^/api/v1/.*$"},
                {
                    "not": {
                        "header(user-agent)": "curl"
                    }
                },
                {"param(a)": "1"},
                {"param(b)": "2"}
            ]
        }))
        .unwrap();

    assert!(engine.evaluate(&rule, &ctx));
}
