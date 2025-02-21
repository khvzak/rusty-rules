use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rusty_rules::{Engine, MatcherType, Value};
use serde_json::json;

// Test context structure (copied from your tests)
#[derive(Debug, Clone)]
struct TestContext {
    method: &'static str,
    path: String,
    headers: HashMap<String, String>,
    params: HashMap<String, String>,
    ip: IpAddr,
    port: i64,
}

fn create_context() -> TestContext {
    TestContext {
        method: "POST",
        path: "/api/v2/users/123/profile".to_string(),
        headers: {
            let mut h = HashMap::new();
            h.insert("host".to_string(), "api.example.com".to_string());
            h.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
            h.insert("x-forwarded-for".to_string(), "10.0.0.1".to_string());
            h.insert("content-type".to_string(), "application/json".to_string());
            h.insert("authorization".to_string(), "Bearer token123".to_string());
            h
        },
        params: {
            let mut p = HashMap::new();
            p.insert("user_id".to_string(), "123".to_string());
            p.insert("version".to_string(), "2".to_string());
            p.insert("format".to_string(), "json".to_string());
            p.insert("include_meta".to_string(), "true".to_string());
            p.insert("fields".to_string(), "name,email,address".to_string());
            p
        },
        ip: IpAddr::from_str("192.168.1.100").unwrap(),
        port: 8443,
    }
}

fn setup_benchmark_engine() -> Engine<TestContext> {
    let mut engine = Engine::new();

    // Register all fetchers
    engine.register_fetcher("method", MatcherType::String, |ctx: &TestContext, _args| {
        Some(Value::from(ctx.method))
    });

    engine.register_fetcher("path", MatcherType::StringRe, |ctx, _args| {
        Some(Value::from(&ctx.path))
    });

    engine.register_fetcher("header", MatcherType::String, |ctx, args| {
        args.first()
            .and_then(|name| ctx.headers.get(name))
            .map(Value::from)
    });

    engine.register_fetcher("param", MatcherType::String, |ctx, args| {
        args.first()
            .and_then(|name| ctx.params.get(name))
            .map(Value::from)
    });

    engine.register_fetcher("ip", MatcherType::Ip, |ctx, _args| Some(Value::Ip(ctx.ip)));

    engine.register_fetcher("port", MatcherType::Number, |ctx, _args| {
        Some(Value::from(ctx.port))
    });

    engine
}

fn create_rule() -> serde_json::Value {
    json!([
        {
            "any": [
                {"method": ["POST", "PUT", "PATCH"]},
                {
                    "all": [
                        {"method": "GET"},
                        {"param(fields)": {"re": "^[a-z,]+$"}},
                        {"param(include_meta)": "true"}
                    ]
                }
            ]
        },
        {
            "not": {
                "any": [
                    {"port": {"<": 1024}},
                    {"port": {">": 49151}},
                    {"ip": ["10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8"]}
                ]
            }
        },
        {
            "all": [
                {"header(host)": {"re": "^[a-z0-9.-]+\\.example\\.com$"}},
                {"header(content-type)": "application/json"},
                {"header(authorization)": {"re": "^Bearer [A-Za-z0-9]+$"}}
            ]
        },
        {"path": "^/api/v[0-9]+/users/[0-9]+/profile$"},
        {
            "any": [
                {"param(version)": ["1", "2", "3"]},
                {
                    "all": [
                        {"param(version)": "beta"},
                        {"header(x-beta-access)": "true"}
                    ]
                }
            ]
        }
    ])
}

fn benchmark_evaluation(c: &mut Criterion) {
    let engine = setup_benchmark_engine();
    let context = create_context();
    let rule = engine.parse_json(&create_rule()).unwrap();

    let mut group = c.benchmark_group("evaluation");
    group.sample_size(100);

    group.bench_function("rules_evaluation", |b| {
        b.iter(|| {
            black_box(rule.evaluate(&context));
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_evaluation);
criterion_main!(benches);
