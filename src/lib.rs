//! # Rusty Rules
//!
//! A blazingly fast, flexible, and extensible rules engine written in Rust.
//! Evaluate complex logical rules against custom data structures using a simple JSON-based DSL.
//!
//! ## Features
//!
//! - **Composable rules**: Combine conditions with `all`, `any`, and `not` logical blocks for complex rule hierarchies
//! - **Custom fetchers**: Extract values from data structures with named fetchers that accept arguments
//! - **Matcher support**: String, regex, IP address, numeric, and boolean matchers out of the box
//! - **Custom operators**: Define operators for advanced matching and domain-specific logic
//! - **Async support**: Register async fetchers and operators for use with async/await contexts
//! - **JSON-schema validation**: Validate rules with automatically generated JSON schema (requires `validation` feature)
//! - **Thread-safety option**: Optional `Send`/`Sync` trait bounds with the `send` feature flag
//! - **Performance-focused**: Designed for high-throughput rule evaluation with minimal overhead
//!
//! ## Basic Usage
//!
//! Here's how to use Rusty Rules with a custom context type:
//!
//! ```rust
//! use std::collections::HashMap;
//! use std::net::IpAddr;
//! use rusty_rules::{Engine, Value};
//! use serde_json::json;
//!
//! // 1. Define context type
//! struct MyContext {
//!     method: String,
//!     path: String,
//!     headers: HashMap<String, String>,
//!     addr: IpAddr,
//! }
//!
//! // 2. Create a new engine
//! let mut engine = Engine::new();
//!
//! // 3. Register fetchers to extract values from context
//! engine.register_fetcher("method", |ctx: &MyContext, _args| {
//!     Ok(Value::from(&ctx.method))
//! });
//!
//! engine.register_fetcher("header", |ctx: &MyContext, args| {
//!     Ok(args.first().and_then(|name| ctx.headers.get(name)).into())
//! });
//!
//! engine.register_fetcher("addr", |ctx: &MyContext, _args| {
//!     Ok(Value::Ip(ctx.addr))
//! });
//!
//! // 4. Compile a rule from JSON
//! let rule = engine.compile_rule(&json!({
//!     "all": [
//!         {"method": "GET"},
//!         {"header(host)": "www.example.com"},
//!         {"addr": {"ip": ["10.0.0.0/8"]}}
//!     ]
//! })).unwrap();
//!
//! // 5. Evaluate the rule against a context
//! let ctx = MyContext {
//!     method: "GET".to_string(),
//!     path: "/api/v1/users".to_string(),
//!     headers: {
//!         let mut h = HashMap::new();
//!         h.insert("host".to_string(), "www.example.com".to_string());
//!         h
//!     },
//!     addr: "10.1.2.3".parse().unwrap(),
//! };
//!
//! assert!(rule.evaluate(&ctx).unwrap());
//! ```
//!
//! ## Rule Composition
//!
//! Rules can be composed using logical operators:
//!
//! ```json
//! {
//!     "all": [              // All conditions must match (logical AND)
//!         { "method": "GET" },
//!         { "path": { "regex": "^/api/v\\d+" } },
//!         {
//!             "any": [      // Any condition must match (logical OR)
//!                 { "header(auth)": { "exists": true } },
//!                 { "ip": { "cidr": "10.0.0.0/8" } }
//!             ]
//!         },
//!         {
//!             "not": [      // Negate the condition (logical NOT)
//!                 { "header(user-agent)": "BadBot/1.0" }
//!             ]
//!         }
//!     ]
//! }
//! ```
//!
//! ## Custom Operators
//!
//! You can extend the engine with custom operators:
//!
//! ```rust
//! # use rusty_rules::{Engine, Operator, Value};
//! # use serde_json::{json, Value as JsonValue};
//! # struct MyContext {}
//! # let mut engine = Engine::new();
//! #
//! # engine.register_fetcher("path", |ctx: &MyContext, _args| {
//! #     Ok(Value::from("/api/v1/users"))
//! # });
//! #
//! // Register a custom string prefix operator
//! engine.register_operator("starts_with", |value: JsonValue| {
//!     let prefix = value.as_str().ok_or("prefix must be a string")?.to_string();
//!     Ok(Operator::new(move |_, value| {
//!         Ok(value.as_str()
//!             .map(|s| s.starts_with(&prefix))
//!             .unwrap_or_default())
//!     }))
//! });
//!
//! // Use the custom operator in a rule
//! let rule = engine.compile_rule(&json!({
//!     "path": {
//!         "starts_with": "/api/v1"
//!     }
//! })).unwrap();
//!
//! # assert!(rule.evaluate(&MyContext {}).unwrap());
//! ```
//!
//! ## JSON Schema Validation
//!
//! With the `validation` feature enabled, you can validate rules against a dynamically generated schema:
//!
//! ```rust
//! # #[cfg(feature = "validation")]
//! # {
//! # use rusty_rules::Engine;
//! # use serde_json::json;
//! # struct MyContext {}
//! #
//! # let engine = Engine::<MyContext>::new();
//! let rule = json!({
//!     "all": [
//!         {"method": "GET"},
//!         {"path": {
//!             "re": "^/api/v\\d+"
//!         }}
//!     ]
//! });
//!
//! // Validate the rule against the engine's schema
//! let result = engine.validate_rule(&rule);
//! # _ = result;
//! # }
//! ```
//!
//! ## Feature Flags
//!
//! - **send** - Enables `Send` and `Sync` trait bounds on all public types, making them safe to use across thread boundaries
//! - **validation** - Enables JSON schema generation and validation functionality (adds `jsonschema` dependency)

#![cfg_attr(docsrs, feature(doc_cfg))]

use std::collections::HashMap;
use std::fmt::Debug;
use std::result::Result as StdResult;
use std::sync::Arc;

use ipnet::IpNet;
use serde_json::{Map, Value as JsonValue, json};

// Re-export commonly used types from external crates
#[cfg(feature = "validation")]
#[cfg_attr(docsrs, doc(cfg(feature = "validation")))]
pub use jsonschema::ValidationError;

// Re-export public types
pub use error::Error;
pub use matcher::{
    BoolMatcher, DefaultMatcher, IpMatcher, Matcher, NumberMatcher, Operator, RegexMatcher,
    StringMatcher,
};
pub use types::{AsyncCheckFn, BoxFuture, CheckFn, MaybeSend, MaybeSync, ToOperator};
pub use value::Value;

use crate::types::{AsyncEvalFn, AsyncFetcherFn, DynError, EvalFn, FetcherFn};

pub(crate) type Result<T> = StdResult<T, error::Error>;

/// Represents a rule, which can be a condition or a logical combination of other rules.
///
/// Rules can be composed using logical operators:
/// - `Any`: At least one sub-rule must evaluate to `true`
/// - `All`: All sub-rules must evaluate to `true`
/// - `Not`: Negates the result of the contained rule
/// - `Leaf`: A single condition that evaluates to a boolean
pub enum Rule<Ctx: ?Sized + 'static> {
    Any(Vec<Self>),
    All(Vec<Self>),
    Not(Box<Self>),
    Leaf(Condition<Ctx>),
}

impl<Ctx: ?Sized> Debug for Rule<Ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rule::Any(rules) => f.debug_tuple("Any").field(rules).finish(),
            Rule::All(rules) => f.debug_tuple("All").field(rules).finish(),
            Rule::Not(rule) => f.debug_tuple("Not").field(rule).finish(),
            Rule::Leaf(_) => f.debug_tuple("Leaf").finish(),
        }
    }
}

impl<Ctx: ?Sized> Clone for Rule<Ctx> {
    fn clone(&self) -> Self {
        match self {
            Rule::Any(rules) => Rule::Any(rules.clone()),
            Rule::All(rules) => Rule::All(rules.clone()),
            Rule::Not(rule) => Rule::Not(rule.clone()),
            Rule::Leaf(condition) => Rule::Leaf(condition.clone()),
        }
    }
}

/// Represents a condition that can be evaluated.
///
/// The condition is a wrapper around a function that takes a context and returns a boolean.
#[doc(hidden)]
pub struct Condition<Ctx: ?Sized>(AnyEvalFn<Ctx>);

impl<Ctx: ?Sized> Clone for Condition<Ctx> {
    fn clone(&self) -> Self {
        Condition(self.0.clone())
    }
}

impl<Ctx: ?Sized> Rule<Ctx> {
    #[inline(always)]
    fn any(mut rules: Vec<Rule<Ctx>>) -> Self {
        if rules.len() == 1 {
            return rules.pop().unwrap();
        }
        Rule::Any(rules)
    }

    #[inline(always)]
    fn all(mut rules: Vec<Rule<Ctx>>) -> Self {
        if rules.len() == 1 {
            return rules.pop().unwrap();
        }
        Rule::All(rules)
    }

    #[inline(always)]
    fn not(mut rules: Vec<Rule<Ctx>>) -> Self {
        if rules.len() == 1 {
            return Rule::Not(Box::new(rules.pop().unwrap()));
        }
        Rule::Not(Box::new(Rule::All(rules)))
    }

    #[inline(always)]
    fn leaf(eval_fn: AnyEvalFn<Ctx>) -> Self {
        Rule::Leaf(Condition(eval_fn))
    }

    #[inline(always)]
    fn into_vec(self) -> Vec<Self> {
        match self {
            Rule::Any(rules) | Rule::All(rules) => rules,
            Rule::Not(_) | Rule::Leaf(_) => vec![self],
        }
    }
}

/// Represents a fetcher key like `header(host)` with name and arguments.
#[derive(Debug)]
pub(crate) struct FetcherKey {
    name: String,
    args: Vec<String>,
}

enum AnyFetcherFn<Ctx: ?Sized> {
    Sync(Arc<FetcherFn<Ctx>>),
    Async(Arc<AsyncFetcherFn<Ctx>>),
}

impl<Ctx: ?Sized> Clone for AnyFetcherFn<Ctx> {
    fn clone(&self) -> Self {
        match self {
            AnyFetcherFn::Sync(func) => AnyFetcherFn::Sync(func.clone()),
            AnyFetcherFn::Async(func) => AnyFetcherFn::Async(func.clone()),
        }
    }
}

enum AnyEvalFn<Ctx: ?Sized> {
    Sync(EvalFn<Ctx>),
    Async(AsyncEvalFn<Ctx>),
}

impl<Ctx: ?Sized> Clone for AnyEvalFn<Ctx> {
    fn clone(&self) -> Self {
        match self {
            AnyEvalFn::Sync(func) => AnyEvalFn::Sync(func.clone()),
            AnyEvalFn::Async(func) => AnyEvalFn::Async(func.clone()),
        }
    }
}

/// Holds a fetcher's required matcher type and function.
///
/// A fetcher is responsible for extracting values from the context type.
/// Each fetcher has:
/// - A function that extracts values from the context
/// - A matcher that determines how to compare these values to the rule conditions
pub struct Fetcher<Ctx: ?Sized> {
    matcher: Arc<dyn Matcher<Ctx>>,
    func: AnyFetcherFn<Ctx>,
    raw_args: bool,
}

impl<Ctx: ?Sized> Clone for Fetcher<Ctx> {
    fn clone(&self) -> Self {
        Fetcher {
            matcher: self.matcher.clone(),
            func: self.func.clone(),
            raw_args: self.raw_args,
        }
    }
}

impl<Ctx: ?Sized> Fetcher<Ctx> {
    /// Changes the fetcher's matcher
    pub fn with_matcher<M>(&mut self, matcher: M) -> &mut Self
    where
        M: Matcher<Ctx> + 'static,
    {
        self.matcher = Arc::new(matcher);
        self
    }

    /// Sets whether the fetcher should receive raw arguments instead of splitting them.
    pub fn with_raw_args(&mut self, raw_args: bool) -> &mut Self {
        self.raw_args = raw_args;
        self
    }
}

/// Rules engine for registering fetchers/operators and parsing rules.
///
/// # Type Parameters
///
/// - `Ctx`: The context type that rules will be evaluated against
///
/// # Example
///
/// ```rust
/// # use std::collections::HashMap;
/// # use rusty_rules::{Engine, Value};
/// # use serde_json::json;
/// struct User {
///     name: String,
///     age: u32,
///     roles: Vec<String>,
/// }
///
/// let mut engine = Engine::new();
///
/// engine.register_fetcher("name", |user: &User, _args| {
///     Ok(Value::from(&user.name))
/// });
///
/// engine.register_fetcher("age", |user: &User, _args| {
///     Ok(Value::from(user.age))
/// });
///
/// engine.register_fetcher("has_role", |user: &User, args| {
///     let role = args.first().ok_or("Role name required")?;
///     Ok(Value::from(user.roles.contains(&role)))
/// });
///
/// let rule = engine.compile_rule(&json!([
///     {"age": {">=": 18}},
///     {"has_role(admin)": true}
/// ])).unwrap();
/// ```
pub struct Engine<Ctx: MaybeSync + ?Sized + 'static> {
    fetchers: HashMap<String, Fetcher<Ctx>>,
    operators: HashMap<String, Arc<dyn ToOperator<Ctx>>>,
}

impl<Ctx: MaybeSync + ?Sized> Default for Engine<Ctx> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Ctx: MaybeSync + ?Sized> Clone for Engine<Ctx> {
    fn clone(&self) -> Self {
        Engine {
            fetchers: self.fetchers.clone(),
            operators: self.operators.clone(),
        }
    }
}

impl<Ctx: MaybeSync + ?Sized> Engine<Ctx> {
    /// Creates a new rules engine instance.
    pub fn new() -> Self {
        Engine {
            fetchers: HashMap::new(),
            operators: HashMap::new(),
        }
    }

    /// Registers a synchronous fetcher with its name and function, using the default matcher.
    ///
    /// A fetcher is a function that extracts values from the context type. The fetcher name is used
    /// in rule definitions to reference this fetcher. By default, the `DefaultMatcher` is used, which
    /// supports basic equality and comparison operations.
    ///
    /// # Returns
    ///
    /// A mutable reference to the created `Fetcher`, allowing you to customize it (e.g., change the matcher)
    pub fn register_fetcher<F>(&mut self, name: &str, func: F) -> &mut Fetcher<Ctx>
    where
        F: for<'a> Fn(&'a Ctx, &[String]) -> StdResult<Value<'a>, DynError>
            + MaybeSend
            + MaybeSync
            + 'static,
    {
        let fetcher = Fetcher {
            matcher: Arc::new(DefaultMatcher),
            func: AnyFetcherFn::Sync(Arc::new(func)),
            raw_args: false,
        };
        self.fetchers
            .entry(name.to_string())
            .insert_entry(fetcher)
            .into_mut()
    }

    /// Registers an async fetcher with its name and function, using the default matcher.
    ///
    /// See [`Self::register_fetcher`] for more details.
    pub fn register_async_fetcher<F>(&mut self, name: &str, func: F) -> &mut Fetcher<Ctx>
    where
        F: for<'a> Fn(&'a Ctx, Arc<[String]>) -> BoxFuture<'a, StdResult<Value<'a>, DynError>>
            + MaybeSend
            + MaybeSync
            + 'static,
    {
        let fetcher = Fetcher {
            matcher: Arc::new(DefaultMatcher),
            func: AnyFetcherFn::Async(Arc::new(func)),
            raw_args: false,
        };
        self.fetchers
            .entry(name.to_string())
            .insert_entry(fetcher)
            .into_mut()
    }

    /// Registers a custom operator
    pub fn register_operator<O>(&mut self, name: &str, op: O)
    where
        O: ToOperator<Ctx> + 'static,
    {
        self.operators.insert(name.to_string(), Arc::new(op));
    }

    /// Compiles a JSON value into a [`Rule::All`] using the registered fetchers and operators.
    pub fn compile_rule(&self, value: &JsonValue) -> Result<Rule<Ctx>> {
        match value {
            JsonValue::Object(map) => {
                let mut subrules = Vec::with_capacity(map.len());
                for (key, value) in map {
                    match key.as_str() {
                        "any" => subrules.push(Rule::any(self.compile_rule(value)?.into_vec())),
                        "all" => subrules.push(Rule::all(self.compile_rule(value)?.into_vec())),
                        "not" => subrules.push(Rule::not(self.compile_rule(value)?.into_vec())),
                        _ => {
                            let FetcherKey { name, args } = Self::parse_fetcher_key(key)?;
                            let fetcher = (self.fetchers.get(&name)).ok_or_else(|| {
                                Error::fetcher(&name, "fetcher is not registered")
                            })?;
                            let args = Self::parse_fetcher_args(args.clone(), fetcher.raw_args);

                            let mut operator = fetcher.matcher.compile(value);
                            // Try custom operator
                            if let Err(Error::UnknownOperator(ref op)) = operator
                                && let Some(op_builder) = self.operators.get(op)
                            {
                                operator = op_builder
                                    .to_operator(&value[op])
                                    .map_err(|err| Error::operator(op, err));
                            }
                            let operator = operator.map_err(|err| Error::matcher(&name, err))?;
                            let fetcher_fn = fetcher.func.clone();
                            let eval_fn =
                                Self::compile_condition(fetcher_fn, args.into(), operator);

                            subrules.push(Rule::leaf(eval_fn));
                        }
                    }
                }
                Ok(Rule::all(subrules))
            }
            JsonValue::Array(seq) => (seq.iter())
                .try_fold(Vec::with_capacity(seq.len()), |mut subrules, v| {
                    subrules.push(self.compile_rule(v)?);
                    Result::Ok(subrules)
                })
                .map(Rule::all),
            _ => Err(Error::json("rule must be a JSON object or array")),
        }
    }

    /// Validates a JSON rule against dynamically generated JSON Schema of this engine.
    #[cfg(feature = "validation")]
    #[cfg_attr(docsrs, doc(cfg(feature = "validation")))]
    #[allow(clippy::result_large_err)]
    pub fn validate_rule<'a>(&self, value: &'a JsonValue) -> StdResult<(), ValidationError<'a>> {
        // build dynamic JSON Schema based on registered fetchers
        let schema = self.json_schema();
        let validator = jsonschema::options()
            .with_pattern_options(jsonschema::PatternOptions::regex())
            .build(&schema)?;
        validator.validate(value)
    }

    /// Builds a JSON Schema for rules, including dynamic properties.
    pub fn json_schema(&self) -> JsonValue {
        let mut pattern_props = Map::new();

        // Get custom operator schemas
        let custom_ops: Vec<(&str, JsonValue)> = (self.operators.iter())
            .map(|(k, v)| (k.as_str(), v.json_schema()))
            .collect();

        // For each fetcher, get its matcher's schema or use a default
        for (name, fetcher) in &self.fetchers {
            let pattern = format!(r"^{}(:?\(([^)]*)\))?$", regex::escape(name));
            let schema = fetcher.matcher.json_schema(&custom_ops);
            pattern_props.insert(pattern, schema);
        }

        json!({
            "$schema": "http://json-schema.org/draft-07/schema",
            "$ref": "#/definitions/rule_object",
            "definitions": {
                "rule_object": {
                    "type": "object",
                    "properties": {
                        "any": { "$ref": "#/definitions/rule" },
                        "all": { "$ref": "#/definitions/rule" },
                        "not": { "$ref": "#/definitions/rule" }
                    },
                    "patternProperties": pattern_props,
                    "additionalProperties": false,
                },
                "rule_array": {
                    "type": "array",
                    "minItems": 1,
                    "items": { "$ref": "#/definitions/rule_object" },
                },
                "rule": {
                    "if": { "type": "array" },
                    "then": { "$ref": "#/definitions/rule_array" },
                    "else": { "$ref": "#/definitions/rule_object" }
                },
            }
        })
    }

    fn compile_condition(
        fetcher_fn: AnyFetcherFn<Ctx>,
        fetcher_args: Arc<[String]>,
        operator: Operator<Ctx>,
    ) -> AnyEvalFn<Ctx> {
        match (fetcher_fn, operator) {
            // Equal
            (AnyFetcherFn::Sync(fetcher_fn), Operator::Equal(right)) => {
                AnyEvalFn::Sync(Arc::new(move |ctx| {
                    Ok(fetcher_fn(ctx, &fetcher_args)? == right)
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::Equal(right)) => {
                let right = Arc::new(right);
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let right = right.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move { Ok(value.await? == *right) })
                }))
            }

            // LessThan
            (AnyFetcherFn::Sync(fetcher_fn), Operator::LessThan(right)) => {
                AnyEvalFn::Sync(Arc::new(move |ctx| {
                    Ok(fetcher_fn(ctx, &fetcher_args)? < right)
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::LessThan(right)) => {
                let right = Arc::new(right);
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let right = right.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move { Ok(value.await? < *right) })
                }))
            }

            // LessThanOrEqual
            (AnyFetcherFn::Sync(fetcher_fn), Operator::LessThanOrEqual(right)) => {
                AnyEvalFn::Sync(Arc::new(move |ctx| {
                    Ok(fetcher_fn(ctx, &fetcher_args)? <= right)
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::LessThanOrEqual(right)) => {
                let right = Arc::new(right);
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let right = right.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move { Ok(value.await? <= *right) })
                }))
            }

            // GreaterThan
            (AnyFetcherFn::Sync(fetcher_fn), Operator::GreaterThan(right)) => {
                AnyEvalFn::Sync(Arc::new(move |ctx| {
                    Ok(fetcher_fn(ctx, &fetcher_args)? > right)
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::GreaterThan(right)) => {
                let right = Arc::new(right);
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let right = right.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move { Ok(value.await? > *right) })
                }))
            }

            // GreaterThanOrEqual
            (AnyFetcherFn::Sync(fetcher_fn), Operator::GreaterThanOrEqual(right)) => {
                AnyEvalFn::Sync(Arc::new(move |ctx| {
                    Ok(fetcher_fn(ctx, &fetcher_args)? >= right)
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::GreaterThanOrEqual(right)) => {
                let right = Arc::new(right);
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let right = right.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move { Ok(value.await? >= *right) })
                }))
            }

            // InSet
            (AnyFetcherFn::Sync(fetcher_fn), Operator::InSet(set)) => {
                AnyEvalFn::Sync(Arc::new(move |ctx| {
                    fetcher_fn(ctx, &fetcher_args).map(|val| set.contains(&val))
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::InSet(set)) => {
                let set = Arc::new(set);
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let set = set.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move { value.await.map(|val| set.contains(&val)) })
                }))
            }

            // Regex
            (AnyFetcherFn::Sync(fetcher_fn), Operator::Regex(regex)) => {
                AnyEvalFn::Sync(Arc::new(move |ctx| {
                    fetcher_fn(ctx, &fetcher_args)
                        .map(|val| val.as_str().map(|s| regex.is_match(s)).unwrap_or(false))
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::Regex(regex)) => {
                let regex = Arc::new(regex);
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let regex = regex.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move {
                        (value.await)
                            .map(|val| val.as_str().map(|s| regex.is_match(s)).unwrap_or(false))
                    })
                }))
            }

            // RegexSet
            (AnyFetcherFn::Sync(fetcher_fn), Operator::RegexSet(regex_set)) => {
                AnyEvalFn::Sync(Arc::new(move |ctx| {
                    fetcher_fn(ctx, &fetcher_args)
                        .map(|val| val.as_str().map(|s| regex_set.is_match(s)).unwrap_or(false))
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::RegexSet(regex_set)) => {
                let regex_set = Arc::new(regex_set);
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let regex_set = regex_set.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move {
                        (value.await)
                            .map(|val| val.as_str().map(|s| regex_set.is_match(s)).unwrap_or(false))
                    })
                }))
            }

            // IpSet
            (AnyFetcherFn::Sync(fetcher_fn), Operator::IpSet(set)) => {
                AnyEvalFn::Sync(Arc::new(move |ctx| {
                    Ok((fetcher_fn(ctx, &fetcher_args)?.to_ip())
                        .map(|ip| set.longest_match(&IpNet::from(ip)).is_some())
                        .unwrap_or(false))
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::IpSet(set)) => {
                let set = Arc::new(set);
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let set = set.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move {
                        Ok((value.await?.to_ip())
                            .map(|ip| set.longest_match(&IpNet::from(ip)).is_some())
                            .unwrap_or(false))
                    })
                }))
            }

            // Custom operator
            (AnyFetcherFn::Sync(fetcher_fn), Operator::Custom(op_fn)) => {
                AnyEvalFn::Sync(Arc::new(move |ctx| {
                    let value = fetcher_fn(ctx, &fetcher_args)?;
                    op_fn(ctx, value)
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::Custom(op_fn)) => {
                let op_fn: Arc<CheckFn<Ctx>> = op_fn.into();
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let op_fn = op_fn.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move { op_fn(ctx, value.await?) })
                }))
            }

            // Custom async operator
            (AnyFetcherFn::Sync(fetcher_fn), Operator::CustomAsync(op_fn)) => {
                let op_fn: Arc<AsyncCheckFn<Ctx>> = op_fn.into();
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let op_fn = op_fn.clone();
                    let value = fetcher_fn(ctx, &fetcher_args);
                    Box::pin(async move { op_fn(ctx, value?).await })
                }))
            }
            (AnyFetcherFn::Async(fetcher_fn), Operator::CustomAsync(op_fn)) => {
                let op_fn: Arc<AsyncCheckFn<Ctx>> = op_fn.into();
                AnyEvalFn::Async(Arc::new(move |ctx| {
                    let op_fn = op_fn.clone();
                    let value = fetcher_fn(ctx, fetcher_args.clone());
                    Box::pin(async move { op_fn(ctx, value.await?).await })
                }))
            }
        }
    }

    /// Parses a key like "header(host)" into [`FetcherKey`]
    fn parse_fetcher_key(key: &str) -> Result<FetcherKey> {
        if let Some((name, args_str)) = key.split_once('(') {
            if !args_str.ends_with(')') {
                return Err(Error::fetcher(name, "missing closing parenthesis"));
            }
            let args_str = &args_str[..args_str.len() - 1];
            let args = if args_str.is_empty() {
                vec![]
            } else {
                vec![args_str.to_string()]
            };
            Ok(FetcherKey {
                name: name.to_string(),
                args,
            })
        } else {
            Ok(FetcherKey {
                name: key.to_string(),
                args: Vec::new(),
            })
        }
    }

    /// Parses fetcher arguments, splitting them and trimming whitespace if `raw` is false.
    fn parse_fetcher_args(mut args: Vec<String>, raw: bool) -> Vec<String> {
        if raw || args.is_empty() {
            args
        } else {
            let arg = args.pop().unwrap_or_default();
            arg.split(',').map(|s| s.trim().to_string()).collect()
        }
    }
}

impl<Ctx: ?Sized> Rule<Ctx> {
    /// Evaluates a rule synchronously using the provided context.
    ///
    /// This method evaluates the rule against the provided context and returns
    /// a boolean result indicating whether the rule matched. If the rule contains
    /// any async operations, this method will return an error.
    pub fn evaluate(&self, context: &Ctx) -> StdResult<bool, DynError> {
        match self {
            Rule::Leaf(Condition(AnyEvalFn::Sync(eval_fn))) => eval_fn(context),
            Rule::Leaf(Condition(AnyEvalFn::Async(_))) => {
                Err("async operations are not supported in sync context".into())
            }
            Rule::Any(subrules) => {
                for rule in subrules {
                    if rule.evaluate(context)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Rule::All(subrules) => {
                for rule in subrules {
                    if !rule.evaluate(context)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Rule::Not(subrule) => Ok(!subrule.evaluate(context)?),
        }
    }

    /// Evaluates a rule asynchronously using the provided context.
    ///
    /// This method evaluates the rule against the provided context and returns
    /// a boolean result indicating whether the rule matched. It supports rules
    /// containing both synchronous and asynchronous operations.
    pub async fn evaluate_async(&self, context: &Ctx) -> StdResult<bool, DynError> {
        match self {
            Rule::Leaf(Condition(AnyEvalFn::Sync(eval_fn))) => eval_fn(context),
            Rule::Leaf(Condition(AnyEvalFn::Async(eval_fn))) => eval_fn(context).await,
            Rule::Any(subrules) => {
                for rule in subrules {
                    if Box::pin(rule.evaluate_async(context)).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Rule::All(subrules) => {
                for rule in subrules {
                    if !Box::pin(rule.evaluate_async(context)).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Rule::Not(subrule) => Ok(!Box::pin(subrule.evaluate_async(context)).await?),
        }
    }
}

pub(crate) trait JsonValueExt {
    fn type_name(&self) -> &'static str;
}

impl JsonValueExt for JsonValue {
    fn type_name(&self) -> &'static str {
        match self {
            JsonValue::String(_) => "string",
            JsonValue::Number(_) => "number",
            JsonValue::Bool(_) => "boolean",
            JsonValue::Array(_) => "array",
            JsonValue::Object(_) => "object",
            JsonValue::Null => "null",
        }
    }
}

mod error;
mod matcher;
mod types;
mod value;

#[cfg(test)]
mod tests {
    #[cfg(feature = "send")]
    static_assertions::assert_impl_all!(super::Engine<()>: Send, Sync);
    #[cfg(feature = "send")]
    static_assertions::assert_impl_all!(super::Rule<()>: Send, Sync);
}
