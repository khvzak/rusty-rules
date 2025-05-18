# rusty-rules

A blazingly fast, flexible, and extensible rules engine written in Rust. Evaluate complex logical rules against custom data structures using a simple JSON-based DSL. Supports both synchronous and asynchronous fetchers, custom operators, and a variety of matchers.

## Features

- **Composable rules**: Combine conditions with `all`, `any`, and `not` logical blocks.
- **Custom fetchers**: Extract values from your own data structures.
- **Matcher support**: String, regex, IP address, and number matchers out of the box.
- **Custom operators**: Easily define your own operators for advanced matching.
- **Async support**: Register async fetchers and operators for use in async contexts.
- **JSON-schema**: Validate your rules with automatically generated json-schema.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rusty-rules = "0.1"
```

## Basic Usage

### Define your context

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

let ctx = /* your MyContext instance */;
assert!(rule.evaluate(&ctx).unwrap());
```
