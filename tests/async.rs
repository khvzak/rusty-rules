use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

// use futures::future::{BoxFuture, FutureExt};
use rusty_rules::{Engine, IpMatcher, Operator, RegexMatcher, Value};
use serde_json::json;
use tokio::time::sleep;

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

fn setup_async_engine() -> Engine<TestContext> {
    let mut engine = Engine::new();

    // Register async method fetcher
    engine.register_async_fetcher("method", |ctx: &TestContext, _args| {
        Box::pin(async move {
            // Simulate async operation with delay
            sleep(Duration::from_millis(10)).await;
            Ok(Value::from(&ctx.method))
        })
    });

    // Register async path fetcher
    engine
        .register_async_fetcher("path", |ctx, _args| {
            Box::pin(async move {
                sleep(Duration::from_millis(10)).await;
                Ok(Value::from(&ctx.path))
            })
        })
        .with_matcher(RegexMatcher);

    // Register async header fetcher
    engine.register_async_fetcher("header", |ctx, args| {
        // Clone the args to avoid lifetime issues
        let name = args.first().cloned();
        Box::pin(async move {
            sleep(Duration::from_millis(10)).await;
            Ok(name.and_then(|name| ctx.headers.get(&name)).into())
        })
    });

    // Register async param fetcher
    engine.register_async_fetcher("param", |ctx, args| {
        let name = args.first().cloned();
        Box::pin(async move {
            sleep(Duration::from_millis(10)).await;
            Ok(name.and_then(|name| ctx.params.get(&name)).into())
        })
    });

    // Register async ip fetcher
    engine
        .register_async_fetcher("ip", |ctx, _args| {
            Box::pin(async move {
                sleep(Duration::from_millis(10)).await;
                Ok(Value::Ip(ctx.ip))
            })
        })
        .with_matcher(IpMatcher);

    // Register async port fetcher
    engine.register_async_fetcher("port", |ctx, _args| {
        Box::pin(async move {
            sleep(Duration::from_millis(10)).await;
            Ok(Value::from(ctx.port))
        })
    });

    // Register async status fetcher
    engine.register_async_fetcher("status", |ctx, _args| {
        Box::pin(async move {
            sleep(Duration::from_millis(10)).await;
            Ok(Value::from(ctx.status as i64))
        })
    });

    // Register custom operator that works with async
    engine.register_operator("starts_with", |json| {
        let prefix = match json {
            serde_json::Value::String(s) => s,
            _ => return Err("`starts_with` requires a string prefix".into()),
        };
        Ok(Operator::new_async(move |_, value| {
            let prefix = prefix.clone();
            Box::pin(async move {
                sleep(Duration::from_millis(10)).await;
                Ok((value.as_str())
                    .map(|s| s.starts_with(&prefix))
                    .unwrap_or_default())
            })
        }))
    });

    engine
}

#[tokio::test]
async fn test_async_simple_conditions() {
    let engine = setup_async_engine();
    let ctx = create_test_context();

    let rule = engine
        .parse_rule(&json!({
            "path": "^/api/v1/.*",
            "method": "GET",
            "header(host)": "www.example.com",
            "port": {">": 80}
        }))
        .unwrap();

    assert!(rule.evaluate_async(&ctx).await.unwrap());

    // Check error in sync context
    let err = rule.evaluate(&ctx).unwrap_err();
    assert!(err
        .to_string()
        .contains("async operations are not supported in sync context"));
}

#[tokio::test]
async fn test_async_logical_operators() {
    let engine = setup_async_engine();
    let ctx = create_test_context();

    let rule = engine
        .parse_rule(&json!({
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

    assert!(rule.evaluate_async(&ctx).await.unwrap());
}

#[tokio::test]
async fn test_async_custom_operator() {
    let engine = setup_async_engine();
    let ctx = create_test_context();

    let rule = engine
        .parse_rule(&json!({
            "header(host)": {
                "starts_with": "www."
            }
        }))
        .unwrap();
    assert!(rule.evaluate_async(&ctx).await.unwrap());
}
