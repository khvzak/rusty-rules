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
    status: u16,
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
        status: 200,
    }
}

fn setup_engine() -> Engine<TestContext> {
    let mut engine = Engine::new();

    // Register method fetcher
    engine.register_fetcher("method", MatcherType::String, |ctx: &TestContext, _args| {
        Some(Value::from(&ctx.method))
    });

    // Register path fetcher
    engine.register_fetcher("path", MatcherType::Regex, |ctx, _args| {
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

    // Register status fetcher
    engine.register_fetcher("status", MatcherType::Number, |ctx, _args| {
        Some(Value::from(ctx.status as i64))
    });

    engine.register_operator("starts_with", |matcher_type, json| {
        if matcher_type != MatcherType::String {
            return Err("starts_with only supports String matcher type".to_string());
        }
        let prefix = match json {
            serde_json::Value::String(s) => s.clone(),
            _ => return Err("starts_with requires a string prefix".to_string()),
        };
        Ok(Box::new(move |value| {
            (value.as_str())
                .map(|s| s.starts_with(&prefix))
                .unwrap_or_default()
        }))
    });

    engine.register_operator("between", |matcher_type, json| {
        if matcher_type != MatcherType::Number {
            return Err("between only supports Number matcher type".to_string());
        }
        let range = match json {
            serde_json::Value::Array(arr) => {
                if arr.len() != 2 {
                    return Err("between requires an array of two numbers".to_string());
                }
                let min = arr[0].as_i64().ok_or("min value must be a number")?;
                let max = arr[1].as_i64().ok_or("max value must be a number")?;
                (min, max)
            }
            _ => return Err("between requires an array of two numbers".to_string()),
        };
        Ok(Box::new(move |value| {
            (value.as_i64())
                .map(|n| n >= range.0 && n <= range.1)
                .unwrap_or_default()
        }))
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

    assert!(rule.evaluate(&ctx));
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

    assert!(rule.evaluate(&ctx));
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

    assert!(rule.evaluate(&ctx));
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

    assert!(rule.evaluate(&ctx));
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

    assert!(rule.evaluate(&ctx));
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
    assert!(rule.evaluate(&ctx));
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

    assert!(engine
        .parse_json(&json!({
            "port": "8080"  // port expects a number, but got string
        }))
        .is_err());
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

    assert!(rule.evaluate(&ctx));
}

#[test]
fn test_custom_operator() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .parse_json(&json!({
            "header(host)": {
                "starts_with": "www."
            }
        }))
        .unwrap();
    assert!(rule.evaluate(&ctx));

    let rule = engine
        .parse_json(&json!({
            "status": {
                "between": [200, 299]
            }
        }))
        .unwrap();
    assert!(rule.evaluate(&ctx));

    let rule = engine
        .parse_json(&json!({
            "status": {
                "between": [300, 399]
            }
        }))
        .unwrap();
    assert!(!rule.evaluate(&ctx));
}
