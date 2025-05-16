use std::collections::HashMap;
use std::fmt::Debug;
use std::result::Result as StdResult;
use std::sync::Arc;

use ipnet::IpNet;
use serde_json::Value as JsonValue;

// Re-export public types
pub use error::Error;
pub use matcher::{
    BoolMatcher, IpMatcher, Matcher, NumberMatcher, Operator, RegexMatcher, StringMatcher,
};
pub use types::{AsyncCheckFn, AsyncFetcherFn, CheckFn, FetcherFn, ToOperator};
pub use value::Value;

use crate::types::{AsyncEvalFn, DynError, EvalFn, MaybeSync};

pub(crate) type Result<T> = StdResult<T, error::Error>;

/// Represents a rule, which can be a condition or a logical combination of other rules
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

/// Represents a condition that can be evaluated
///
/// The condition is a wrapper around a function that takes a context and returns a boolean
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
}

/// Represents a fetcher key like `header(host)` with name and arguments
#[derive(Debug)]
pub(crate) struct FetcherKey {
    name: String,
    args: Vec<String>,
}

enum AnyFetcherFn<Ctx: ?Sized> {
    Sync(FetcherFn<Ctx>),
    Async(AsyncFetcherFn<Ctx>),
}

impl<Ctx: ?Sized> Clone for AnyFetcherFn<Ctx> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Ctx: ?Sized> Copy for AnyFetcherFn<Ctx> {}

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

/// Holds a fetcher's required matcher type and function
struct Fetcher<Ctx: ?Sized> {
    matcher: Arc<dyn Matcher<Ctx>>,
    func: AnyFetcherFn<Ctx>,
}

impl<Ctx: ?Sized> Clone for Fetcher<Ctx> {
    fn clone(&self) -> Self {
        Fetcher {
            matcher: self.matcher.clone(),
            func: self.func,
        }
    }
}

/// Rules engine for registering fetchers/operators and parsing rules
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
    /// Creates a new rules engine
    pub fn new() -> Self {
        Engine {
            fetchers: HashMap::new(),
            operators: HashMap::new(),
        }
    }

    /// Registers a fetcher with its name, matcher, and function
    pub fn register_fetcher<M>(&mut self, name: &str, matcher: M, func: FetcherFn<Ctx>)
    where
        M: Matcher<Ctx> + 'static,
    {
        let matcher = Arc::new(matcher);
        let func = AnyFetcherFn::Sync(func);
        let fetcher = Fetcher { matcher, func };
        self.fetchers.insert(name.to_string(), fetcher);
    }

    /// Registers an async fetcher with its name, matcher, and function
    pub fn register_async_fetcher<M>(&mut self, name: &str, matcher: M, func: AsyncFetcherFn<Ctx>)
    where
        M: Matcher<Ctx> + 'static,
    {
        let matcher = Arc::new(matcher);
        let func = AnyFetcherFn::Async(func);
        let fetcher = Fetcher { matcher, func };
        self.fetchers.insert(name.to_string(), fetcher);
    }

    /// Registers a custom operator
    pub fn register_operator<O>(&mut self, name: &str, op: O)
    where
        O: ToOperator<Ctx> + 'static,
    {
        self.operators.insert(name.to_string(), Arc::new(op));
    }

    /// Parses a JSON value into a [`Rule::All`] using the registered fetchers and operators
    pub fn parse_rule(&self, value: &JsonValue) -> Result<Rule<Ctx>> {
        self.parse_rules(value).map(Rule::all)
    }

    /// Parses a JSON value into a `Vec<Rule>`
    fn parse_rules(&self, value: &JsonValue) -> Result<Vec<Rule<Ctx>>> {
        match value {
            JsonValue::Object(map) => {
                let mut rules = Vec::with_capacity(map.len());
                for (key, value) in map {
                    match key.as_str() {
                        "any" => rules.push(Rule::any(self.parse_rules(value)?)),
                        "all" => rules.push(Rule::all(self.parse_rules(value)?)),
                        "not" => rules.push(Rule::not(self.parse_rules(value)?)),
                        _ => {
                            let FetcherKey { name, args } = Self::parse_fetcher_key(key)?;
                            let fetcher = (self.fetchers.get(&name)).ok_or_else(|| {
                                Error::fetcher(&name, "fetcher is not registered")
                            })?;

                            let mut operator = fetcher.matcher.parse(&name, value);
                            // Try custom operator
                            if let Err(Error::UnknownOperator(ref op)) = operator {
                                if let Some(op_builder) = self.operators.get(op) {
                                    operator = op_builder
                                        .to_operator(&value[op])
                                        .map_err(|err| Error::operator(op, &name, err));
                                }
                            }
                            let eval_fn =
                                Self::compile_condition(fetcher.func, args.into(), operator?);

                            rules.push(Rule::leaf(eval_fn));
                        }
                    }
                }
                Ok(rules)
            }
            JsonValue::Array(seq) => {
                seq.iter()
                    .try_fold(Vec::with_capacity(seq.len()), |mut rules, v| {
                        rules.extend(self.parse_rules(v)?);
                        Ok(rules)
                    })
            }
            _ => Err(Error::json("rule must be a JSON object or array")),
        }
    }

    /// Validates a JSON rule against dynamically generated JSON Schema of this engine.
    #[cfg(feature = "validation")]
    #[cfg_attr(docsrs, doc(cfg(feature = "validation")))]
    pub fn validate_rule(&self, value: &JsonValue) -> StdResult<(), String> {
        // build dynamic JSON Schema based on registered fetchers
        let schema = self.json_schema();
        let validator = jsonschema::draft7::new(&schema)
            .map_err(|e| format!("failed to compile JSON Schema: {e}"))?;
        validator.validate(value).map_err(|e| e.to_string())
    }

    /// Builds a JSON Schema for rules, including dynamic properties.
    pub fn json_schema(&self) -> JsonValue {
        let mut pattern_props = serde_json::Map::new();

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

        serde_json::json!({
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
                    Ok((fetcher_fn(ctx, &fetcher_args)?.as_ip())
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
                        Ok((value.await?.as_ip())
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
            let args = args_str.split(',').map(|s| s.trim().to_string()).collect();
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
}

impl<Ctx: ?Sized> Rule<Ctx> {
    /// Evaluates a rule using the provided context
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

    /// Evaluates a rule asynchronously using the provided context
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
