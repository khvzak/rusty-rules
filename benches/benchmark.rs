use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rusty_rules::{Engine, IpMatcher, RegexMatcher, Value};
use serde_json::json;
use vrl::compiler::{state::RuntimeState, Context, Program, TargetValue, TimeZone};
use vrl::diagnostic::Formatter;
use vrl::value::{ObjectMap, Secrets, Value as VrlValue};

// A unified context for both engines
fn create_context() -> VrlValue {
    vrl::value!({
        method: "POST",
        path: "/api/v2/users/123/profile",
        headers: {
            "host": "api.example.com",
            "user-agent": "Mozilla/5.0",
            "x-forwarded-for": "10.0.0.1",
            "content-type": "application/json",
            "authorization":  "Bearer token123",
            "x-beta-access": "true",
        },
        params: {
            "user_id": "123",
            "version": "beta",
            "format": "json",
            "include_meta": "true",
            "fields": "name,email,address",
        },
        ip: "192.168.1.100",
        port: 8443,
    })
}

fn setup_rules_engine() -> Engine<ObjectMap> {
    let mut engine = Engine::new();

    // Register all fetchers
    engine.register_fetcher("method", |ctx: &ObjectMap, _args| {
        Ok(Value::from(ctx.get("method").unwrap().as_str()))
    });

    engine
        .register_fetcher("path", |ctx, _args| {
            Ok(Value::from(ctx.get("path").unwrap().as_str()))
        })
        .with_matcher(RegexMatcher);

    engine.register_fetcher("header", |ctx, args| {
        let headers = ctx.get("headers").unwrap().as_object().unwrap();
        let name = args.first().unwrap();
        let value = headers.get(name.as_str()).unwrap().as_str();
        Ok(Value::from(value))
    });

    engine.register_fetcher("param", |ctx, args| {
        let params = ctx.get("params").unwrap().as_object().unwrap();
        let name = args.first().unwrap();
        let value = params.get(name.as_str()).unwrap().as_str();
        Ok(Value::from(value))
    });

    engine
        .register_fetcher("ip", |ctx, _args| {
            let ip_str = ctx.get("ip").unwrap().as_str().unwrap();
            let ip = IpAddr::from_str(&ip_str).unwrap();
            Ok(Value::Ip(ip))
        })
        .with_matcher(IpMatcher);

    engine.register_fetcher("port", |ctx, _args| {
        let port = ctx.get("port").unwrap().as_integer();
        Ok(Value::from(port))
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
        {"path": "^/api/v[0-9]/users/[0-9]+/profile$"},
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

fn setup_vrl_engine() -> Program {
    // Create a VRL program that evaluates the same rules as the rusty-rules implementation
    let vrl_program = r#"
    # Condition 1: Method check
    result = .method == "POST" || .method == "PUT" || .method == "PATCH" ||
        (.method == "GET" && match!(.params.fields, r'^[a-z,]+$') && .params.include_meta == "true");

    # Condition 2: Port and IP check
    result = result &&
        !(to_int!(.port) < 1024 ||
        to_int!(.port) > 49151 ||
        ip_cidr_contains!("10.0.0.0/8", .ip) ||
        ip_cidr_contains!("172.16.0.0/12", .ip) ||
        ip_cidr_contains!("127.0.0.0/8", .ip));

    # Condition 3: Header checks
    result = result &&
        match!(.headers.host, r'^[a-z0-9.-]+\.example\.com$') &&
        get!(.headers, ["content-type"]) == "application/json" &&
        match!(.headers.authorization, r'^Bearer [A-Za-z0-9]+$');

    # Condition 4: Path check
    result = result && match!(.path, r'^/api/v[0-9]/users/[0-9]+/profile$');

    # Condition 5: Version check
    result = result &&
        (.params.version == "1" || .params.version == "2" || .params.version == "3" ||
        (.params.version == "beta" && get!(.headers, ["x-beta-access"]) == "true"));

    result
    "#;

    let fns = vrl::stdlib::all();

    let compilation = match vrl::compiler::compile(vrl_program, &fns) {
        Ok(compilation_result) => compilation_result,
        Err(e) => {
            panic!("{}", Formatter::new(vrl_program, e));
        }
    };

    compilation.program
}

fn benchmark_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluation");
    group.sample_size(100);

    group.bench_function("rusty_rules_evaluation", |b| {
        let engine = setup_rules_engine();
        let vrl_value = create_context();
        let context = vrl_value.as_object().unwrap();
        let rule = engine.parse_rule(&create_rule()).unwrap();

        b.iter(|| {
            let result = black_box(rule.evaluate(context).unwrap());
            assert!(result);
        });
    });

    group.bench_function("vrl_evaluation", |b| {
        let vrl_program = setup_vrl_engine();
        let mut target = TargetValue {
            value: create_context(),
            metadata: VrlValue::Object(BTreeMap::new()),
            secrets: Secrets::default(),
        };
        let mut state = RuntimeState::default();
        let timezone = TimeZone::default();
        let mut ctx = Context::new(&mut target, &mut state, &timezone);

        b.iter(|| {
            let result = black_box(vrl_program.resolve(&mut ctx).unwrap());
            assert!(result.as_boolean().unwrap());
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_evaluation);
criterion_main!(benches);
