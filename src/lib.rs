use std::result::Result as StdResult;
use std::sync::Arc;
use std::{collections::HashMap, fmt::Debug};

use ipnet::IpNet;
use serde_json::Value as JsonValue;

// Re-export public types
pub use error::Error;
pub use matcher::{
    BoolMatcher, IpMatcher, Matcher, NumberMatcher, Operator, RegexMatcher, StringMatcher,
};
pub use value::Value;

pub(crate) type Result<T> = std::result::Result<T, error::Error>;

/// Represents a rule, which can be a condition or a logical combination
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
            Rule::Leaf(_) => write!(f, "Leaf(...)"),
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

#[doc(hidden)]
pub struct Condition<Ctx: ?Sized>(TestFn<Ctx>, FetcherFn<Ctx>);

impl<Ctx: ?Sized> Clone for Condition<Ctx> {
    fn clone(&self) -> Self {
        Condition(self.0.clone(), self.1)
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
    fn leaf(test_fn: TestFn<Ctx>, fetcher_fn: FetcherFn<Ctx>) -> Self {
        Rule::Leaf(Condition(test_fn, fetcher_fn))
    }
}

/// Represents a fetcher key like "header(host)" with name and arguments
#[derive(Debug)]
struct FetcherKey {
    name: String,
    args: Vec<String>,
}

/// Callback type for fetchers
pub type FetcherFn<Ctx> = for<'a> fn(&'a Ctx, &[String]) -> Option<Value<'a>>;

/// Callback type for operators
#[cfg(not(feature = "send"))]
pub type OperatorFn<Ctx> = Arc<dyn Fn(&JsonValue) -> StdResult<CheckFn<Ctx>, String>>;

/// Callback type for operators
#[cfg(feature = "send")]
pub type OperatorFn<Ctx> = Arc<dyn Fn(&JsonValue) -> StdResult<CheckFn<Ctx>, String> + Send + Sync>;

/// Callback type for operator check function
#[cfg(not(feature = "send"))]
pub type CheckFn<Ctx> = Box<dyn Fn(&Ctx, Value) -> bool>;

/// Callback type for operator check function
#[cfg(feature = "send")]
pub type CheckFn<Ctx> = Box<dyn Fn(&Ctx, Value) -> bool + Send + Sync>;

#[cfg(not(feature = "send"))]
type TestFn<Ctx> = Arc<dyn Fn(FetcherFn<Ctx>, &Ctx) -> bool>;

#[cfg(feature = "send")]
type TestFn<Ctx> = Arc<dyn Fn(FetcherFn<Ctx>, &Ctx) -> bool + Send + Sync>;

/// Holds a fetcher's required matcher type and function
struct Fetcher<Ctx: ?Sized> {
    matcher: Arc<dyn Matcher<Ctx>>,
    func: FetcherFn<Ctx>,
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
pub struct Engine<Ctx: ?Sized + 'static> {
    fetchers: HashMap<String, Fetcher<Ctx>>,
    operators: HashMap<String, OperatorFn<Ctx>>,
}

impl<Ctx: ?Sized> Default for Engine<Ctx> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Ctx: ?Sized> Clone for Engine<Ctx> {
    fn clone(&self) -> Self {
        Engine {
            fetchers: self.fetchers.clone(),
            operators: self.operators.clone(),
        }
    }
}

impl<Ctx: ?Sized> Engine<Ctx> {
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
        let fetcher = Fetcher { matcher, func };
        self.fetchers.insert(name.to_string(), fetcher);
    }

    /// Registers a custom operator
    #[cfg(not(feature = "send"))]
    pub fn register_operator<F>(&mut self, op: &str, func: F)
    where
        F: Fn(&JsonValue) -> StdResult<CheckFn<Ctx>, String> + 'static,
    {
        self.operators.insert(op.to_string(), Arc::new(func));
    }

    /// Registers a custom operator
    #[cfg(feature = "send")]
    pub fn register_operator<F>(&mut self, op: &str, func: F)
    where
        F: Fn(&JsonValue) -> StdResult<CheckFn<Ctx>, String> + Send + Sync + 'static,
    {
        self.operators.insert(op.to_string(), Arc::new(func));
    }

    /// Parses a JSON value into a [`Rule`] using the registered fetchers and operators
    pub fn parse_value(&self, json: &JsonValue) -> Result<Rule<Ctx>> {
        self.parse_rules(json).map(Rule::all)
    }

    /// Parses a JSON value into a `Vec<Rule>`
    fn parse_rules(&self, json: &JsonValue) -> Result<Vec<Rule<Ctx>>> {
        match json {
            JsonValue::Object(map) => {
                let mut rules = Vec::with_capacity(map.len());
                for (key, value) in map {
                    match key.as_str() {
                        "any" => rules.push(Rule::any(self.parse_rules(value)?)),
                        "all" => rules.push(Rule::all(self.parse_rules(value)?)),
                        "not" => rules.push(Rule::not(self.parse_rules(value)?)),
                        _ => {
                            let FetcherKey { name, args } = Self::parse_fetcher_key(key)?;
                            let fetcher = (self.fetchers.get(&name))
                                .ok_or_else(|| Error::UnknownFetcher(name.clone()))?;

                            let mut operator = fetcher.matcher.parse(&name, value);
                            // Try custom operator
                            if let Err(Error::UnknownOperator(ref op)) = operator {
                                if let Some(op_fn) = self.operators.get(op) {
                                    let check_fn = op_fn(&value[op])
                                        .map_err(|err| Error::operator(op, &name, err))?;
                                    operator = Ok(Operator::Custom(check_fn));
                                }
                            }
                            let test_fn = Self::compile_condition(args, operator?);

                            rules.push(Rule::leaf(test_fn, fetcher.func));
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
            _ => Err(Error::InvalidJson(
                "Rule must be a JSON object or array".to_string(),
            )),
        }
    }

    fn compile_condition(fetcher_args: Vec<String>, operator: Operator<Ctx>) -> TestFn<Ctx> {
        match operator {
            Operator::Equal(right) => Arc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left == right)
                    .unwrap_or_default()
            }),
            Operator::LessThan(right) => Arc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left < right)
                    .unwrap_or_default()
            }),
            Operator::LessThanOrEqual(right) => Arc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left <= right)
                    .unwrap_or_default()
            }),
            Operator::GreaterThan(right) => Arc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left > right)
                    .unwrap_or_default()
            }),
            Operator::GreaterThanOrEqual(right) => Arc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left >= right)
                    .unwrap_or_default()
            }),
            Operator::InList(list) => Arc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|val| list.contains(&val))
                    .unwrap_or_default()
            }),
            Operator::Regex(regex) => Arc::new(move |fetcher, ctx| {
                (fetcher(ctx, &fetcher_args).as_ref())
                    .and_then(|val| val.as_str())
                    .map(|s| regex.is_match(s))
                    .unwrap_or_default()
            }),
            Operator::RegexSet(regex_set) => Arc::new(move |fetcher, ctx| {
                (fetcher(ctx, &fetcher_args).as_ref())
                    .and_then(|val| val.as_str())
                    .map(|s| regex_set.is_match(s))
                    .unwrap_or_default()
            }),
            Operator::IpSet(set) => Arc::new(move |fetcher, ctx| {
                (fetcher(ctx, &fetcher_args).as_ref())
                    .and_then(|val| val.as_ip())
                    .map(|ip| set.longest_match(&IpNet::from(ip)).is_some())
                    .unwrap_or_default()
            }),
            Operator::Custom(check_fn) => {
                Arc::new(move |fetcher, ctx| match fetcher(ctx, &fetcher_args) {
                    Some(val) => check_fn(ctx, val),
                    None => false,
                })
            }
        }
    }

    /// Parses a key like "header(host)" into [`FetcherKey`]
    fn parse_fetcher_key(key: &str) -> Result<FetcherKey> {
        if let Some((name, args_str)) = key.split_once('(') {
            if !args_str.ends_with(')') {
                return Err(Error::invalid_fetcher(name, "Missing closing parenthesis"));
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
    pub fn evaluate(&self, context: &Ctx) -> bool {
        match self {
            Rule::Leaf(Condition(test_fn, fetcher_fn)) => test_fn(*fetcher_fn, context),
            Rule::Any(subrules) => subrules.iter().any(|r| r.evaluate(context)),
            Rule::All(subrules) => subrules.iter().all(|r| r.evaluate(context)),
            Rule::Not(subrule) => !subrule.evaluate(context),
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
mod value;

#[cfg(test)]
mod tests {
    #[cfg(feature = "send")]
    static_assertions::assert_impl_all!(super::Engine<()>: Send, Sync);
    #[cfg(feature = "send")]
    static_assertions::assert_impl_all!(super::Rule<()>: Send, Sync);
}
