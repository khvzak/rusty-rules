# rusty-rules

[![Latest Version]][crates.io] [![API Documentation]][docs.rs] [![Coverage Status]][codecov.io]

[Latest Version]: https://img.shields.io/crates/v/rusty-rules.svg
[crates.io]: https://crates.io/crates/rusty-rules
[API Documentation]: https://docs.rs/rusty-rules/badge.svg
[docs.rs]: https://docs.rs/rusty-rules
[Coverage Status]: https://codecov.io/gh/khvzak/rusty-rules/graph/badge.svg?token=GAMBBWY7K1
[codecov.io]: https://codecov.io/gh/khvzak/rusty-rules

A blazingly fast, flexible, and extensible rules engine written in Rust. Evaluate complex logical rules against custom data structures using a simple JSON-based DSL. Supports both synchronous and asynchronous fetchers, custom operators, and a variety of matchers.

## Features

- **Composable rules**: Combine conditions with `all`, `any`, and `not` logical blocks for complex rule hierarchies
- **Custom fetchers**: Extract values from data structures with named fetchers that accept arguments
- **Matcher support**: String, regex, IP address, numeric, and boolean matchers out of the box
- **Custom operators**: Define operators for advanced matching and domain-specific logic
- **Async support**: Register async fetchers and operators for use with async/await contexts
- **JSON-schema validation**: Validate rules with automatically generated JSON schema (requires `validation` feature)
- **Thread-safety option**: Optional `Send`/`Sync` trait bounds with the `send` feature flag
- **Performance-focused**: Designed for high-throughput rule evaluation with minimal overhead

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
rusty-rules = "0.1"
```

## Basic Usage

### Define context

```rust
use std::collections::HashMap;
use std::net::IpAddr;

struct MyContext {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    addr: IpAddr,
}
```

### Register fetchers

```rust
use rusty_rules::{Engine, Value};

let mut engine = Engine::new();

engine.register_fetcher("method", |ctx: &MyContext, _args| {
    Ok(Value::from(&ctx.method))
});

engine.register_fetcher("header", |ctx: &MyContext, args| {
    Ok(args.first().and_then(|name| ctx.headers.get(name)).into())
});

engine.register_fetcher("addr", |ctx: &MyContext, _args| {
    Ok(ctx.addr.into())
});

// ...register other fetchers...
```

### Parse and evaluate a rule

```rust
use serde_json::json;

let rule = engine.parse_rule(&json!({
    "method": "GET",
    "header(host)": "www.example.com",
    "addr": {
        "ip": ["10.0.0.0/8"]
    }
})).unwrap();

let ctx = /* MyContext instance */;
assert!(rule.evaluate(&ctx).unwrap());
```
