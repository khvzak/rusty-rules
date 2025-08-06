use std::collections::HashMap;
use std::net::IpAddr;

use rusty_rules::{Engine, IpMatcher, NumberMatcher, Operator, RegexMatcher, Value};
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
    engine.register_fetcher("method", |ctx: &TestContext, _args| {
        Ok(Value::from(&ctx.method))
    });

    // Register regex-based path fetcher
    engine
        .register_fetcher("path", |ctx, _args| Ok(Value::from(&ctx.path)))
        .with_matcher(RegexMatcher);

    // Register header fetcher
    engine.register_fetcher("header", |ctx, args| {
        Ok(args.first().and_then(|name| ctx.headers.get(name)).into())
    });

    // Register param fetcher
    engine.register_fetcher("param", |ctx, args| {
        Ok((args.first()).and_then(|name| ctx.params.get(name)).into())
    });

    // Register ip fetcher
    engine
        .register_fetcher("ip", |ctx, _args| Ok(Value::Ip(ctx.ip)))
        .with_matcher(IpMatcher);

    // Register port fetcher
    engine
        .register_fetcher("port", |ctx, _args| Ok(Value::from(ctx.port)))
        .with_matcher(NumberMatcher);

    // Register status fetcher
    engine.register_fetcher("status", |ctx, _args| Ok(Value::from(ctx.status as i64)));

    engine.register_operator("starts_with", |value| {
        let prefix = match value {
            serde_json::Value::String(s) => s,
            _ => return Err("`starts_with` requires a string prefix".into()),
        };

        Ok(Operator::new(move |_, value| {
            Ok((value.as_str())
                .map(|s| s.starts_with(&prefix))
                .unwrap_or_default())
        }))
    });

    engine.register_operator("between", |value| {
        let range = match value {
            serde_json::Value::Array(arr) => {
                if arr.len() != 2 {
                    return Err("between requires an array of two numbers".into());
                }
                let min = arr[0].as_i64().ok_or("min value must be a number")?;
                let max = arr[1].as_i64().ok_or("max value must be a number")?;
                (min, max)
            }
            _ => return Err("between requires an array of two numbers".into()),
        };

        Ok(Operator::new(move |_, value| {
            Ok((value.as_i64())
                .map(|n| n >= range.0 && n <= range.1)
                .unwrap_or_default())
        }))
    });

    engine
}

#[test]
fn test_simple_conditions() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .compile_rule(&json!({
            "method": "GET",
            "header(host)": "www.example.com",
            "port": {">": 80}
        }))
        .unwrap();

    assert!(rule.evaluate(&ctx).unwrap());
}

#[test]
fn test_logical_operators() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .compile_rule(&json!({
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

    assert!(rule.evaluate(&ctx).unwrap());
}

#[test]
fn test_regex_matching() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .compile_rule(&json!({
            "path": "^/api/v1/.*$",
            "header(host)": {
                "re": "^www\\.example\\.com$"
            }
        }))
        .unwrap();

    assert!(rule.evaluate(&ctx).unwrap());
}

#[test]
fn test_ip_matching() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .compile_rule(&json!({
            "ip": ["127.0.0.1", "::1/128"]
        }))
        .unwrap();

    assert!(rule.evaluate(&ctx).unwrap());
}

#[test]
fn test_number_comparisons() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .compile_rule(&json!([
            {"port": {">=": 8000}},
            {"port": {"<": 9000}},
        ]))
        .unwrap();

    assert!(rule.evaluate(&ctx).unwrap());
}

#[test]
fn test_unknown_fetcher() {
    let engine = setup_engine();

    let result = engine.compile_rule(&json!({
        "unknown_fetcher": "value"
    }));

    assert!(result.is_err());
    assert!(
        (result.unwrap_err())
            .to_string()
            .contains("Error in 'unknown_fetcher' fetcher: fetcher is not registered")
    )
}

#[test]
fn test_empty_rule() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine.compile_rule(&json!({})).unwrap();
    assert!(rule.evaluate(&ctx).unwrap());
}

#[test]
fn test_invalid_regex() {
    let engine = setup_engine();

    let result = engine.compile_rule(&json!({
        "path": "[" // invalid regex pattern
    }));

    assert!(result.is_err());
    assert!(
        (result.unwrap_err())
            .to_string()
            .contains("Error in 'path' matcher: regex parse error")
    )
}

#[test]
fn test_invalid_ip() {
    let engine = setup_engine();

    let result = engine.compile_rule(&json!({
        "ip": "not.an.ip.address"
    }));

    assert!(result.is_err());
    assert!(
        (result.unwrap_err())
            .to_string()
            .contains("Error in 'ip' matcher: invalid IP address")
    )
}

#[test]
fn test_type_mismatch() {
    let engine = setup_engine();

    let result = engine.compile_rule(&json!({
        "port": "8080"  // port expects a number, but got string
    }));

    assert!(result.is_err());
    assert!(
        (result.unwrap_err())
            .to_string()
            .contains("Error in 'port' matcher: unexpected JSON string")
    )
}

#[test]
fn test_complex_rules() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .compile_rule(&json!({
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

    assert!(rule.evaluate(&ctx).unwrap());
}

#[test]
fn test_custom_operator() {
    let engine = setup_engine();
    let ctx = create_test_context();

    let rule = engine
        .compile_rule(&json!({
            "header(host)": {
                "starts_with": "www."
            }
        }))
        .unwrap();
    assert!(rule.evaluate(&ctx).unwrap());

    let rule = engine
        .compile_rule(&json!({
            "status": {
                "between": [200, 299]
            }
        }))
        .unwrap();
    assert!(rule.evaluate(&ctx).unwrap());

    let rule = engine
        .compile_rule(&json!({
            "status": {
                "between": [300, 399]
            }
        }))
        .unwrap();
    assert!(!rule.evaluate(&ctx).unwrap());
}

#[test]
fn test_raw_args() {
    let mut engine = setup_engine();
    let ctx = create_test_context();

    // Register a fetcher that doesn't split arguments
    engine
        .register_fetcher("raw_args", |_ctx: &TestContext, args| {
            Ok(Value::from(args.first().cloned().unwrap()))
        })
        .with_raw_args(true);

    let rule = engine
        .compile_rule(&json!({
            "raw_args(key1, key2,   key3)": "key1, key2,   key3"
        }))
        .unwrap();
    assert!(rule.evaluate(&ctx).unwrap());
}
