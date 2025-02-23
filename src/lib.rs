use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::rc::Rc;
use std::result::Result as StdResult;

use ipnet_trie::IpnetTrie;
use serde_json::{Number, Value as JsonValue};

pub use error::Error;

pub(crate) type Result<T> = std::result::Result<T, error::Error>;

/// Represents possible values returned by fetchers
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value<'a> {
    String(Cow<'a, str>),
    Number(Number),
    Bool(bool),
    Ip(IpAddr),
}

impl Value<'_> {
    fn into_static(self) -> Value<'static> {
        match self {
            Value::String(s) => Value::String(Cow::Owned(s.into_owned())),
            Value::Number(n) => Value::Number(n),
            Value::Bool(b) => Value::Bool(b),
            Value::Ip(ip) => Value::Ip(ip),
        }
    }

    /// Returns the value as a string if it is a string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the value as an integer if it is a number
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(n) => n.as_i64(),
            _ => None,
        }
    }

    /// Returns the value as a float if it is a number
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => n.as_f64(),
            _ => None,
        }
    }

    /// Returns the value as a boolean if it is a boolean
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the value as an IP address if it is an IP address
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Value::Ip(ip) => Some(*ip),
            _ => None,
        }
    }
}

impl PartialOrd for Value<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Value::String(s), Value::String(t)) => s.partial_cmp(t),
            (Value::Number(i), Value::Number(j)) => {
                if let (Some(i), Some(j)) = (i.as_i64(), j.as_i64()) {
                    i.partial_cmp(&j)
                } else if let (Some(i), Some(j)) = (i.as_f64(), j.as_f64()) {
                    i.partial_cmp(&j)
                } else {
                    None
                }
            }
            (Value::Bool(i), Value::Bool(j)) => i.partial_cmp(j),
            (Value::Ip(i), Value::Ip(j)) => i.partial_cmp(j),
            _ => None,
        }
    }
}

impl<'a> TryFrom<&'a serde_json::Value> for Value<'a> {
    type Error = ();

    fn try_from(value: &'a serde_json::Value) -> StdResult<Self, Self::Error> {
        match value {
            serde_json::Value::String(s) => Ok(Value::String(Cow::Borrowed(s))),
            serde_json::Value::Number(n) => Ok(Value::Number(n.clone())),
            serde_json::Value::Bool(b) => Ok(Value::Bool(*b)),
            _ => Err(()),
        }
    }
}

impl From<String> for Value<'_> {
    #[inline(always)]
    fn from(s: String) -> Self {
        Value::String(Cow::Owned(s))
    }
}

impl<'a> From<&'a String> for Value<'a> {
    #[inline(always)]
    fn from(s: &'a String) -> Self {
        Value::String(Cow::Borrowed(s))
    }
}

impl<'a> From<&'a str> for Value<'a> {
    #[inline(always)]
    fn from(s: &'a str) -> Self {
        Value::String(Cow::Borrowed(s))
    }
}

impl From<i64> for Value<'_> {
    #[inline(always)]
    fn from(i: i64) -> Self {
        Value::Number(serde_json::Number::from(i))
    }
}

impl TryFrom<f64> for Value<'_> {
    type Error = ();

    #[inline(always)]
    fn try_from(f: f64) -> StdResult<Self, Self::Error> {
        Ok(Value::Number(serde_json::Number::from_f64(f).ok_or(())?))
    }
}

/// Represents conditions to match against fetched values
enum Matcher {
    Equal(Value<'static>),
    LessThan(Value<'static>),
    LessThanOrEqual(Value<'static>),
    GreaterThan(Value<'static>),
    GreaterThanOrEqual(Value<'static>),
    InList(HashSet<Value<'static>>),
    Regex(regex::Regex),
    RegexSet(regex::RegexSet),
    IpSet(IpnetTrie<()>),
    Custom(OperatorCheckFn),
}

/// Represents a rule, which can be a condition or a logical combination
pub enum Rule<Ctx> {
    Any(Vec<Self>),
    All(Vec<Self>),
    Not(Box<Self>),
    Leaf(Condition<Ctx>),
}

impl<Ctx> Clone for Rule<Ctx> {
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
pub struct Condition<Ctx>(Rc<dyn Fn(FetcherFn<Ctx>, &Ctx) -> bool>, FetcherFn<Ctx>);

impl<Ctx> Clone for Condition<Ctx> {
    fn clone(&self) -> Self {
        Condition(self.0.clone(), self.1)
    }
}

impl<Ctx> Rule<Ctx> {
    #[inline(always)]
    fn any(rules: Vec<Rule<Ctx>>) -> Self {
        Rule::Any(rules)
    }

    #[inline(always)]
    fn all(rules: Vec<Rule<Ctx>>) -> Self {
        Rule::All(rules)
    }

    #[inline(always)]
    fn not(rule: Rule<Ctx>) -> Self {
        Rule::Not(Box::new(rule))
    }

    #[inline(always)]
    fn leaf(test_fn: Rc<dyn Fn(FetcherFn<Ctx>, &Ctx) -> bool>, fetcher_fn: FetcherFn<Ctx>) -> Self {
        Rule::Leaf(Condition(test_fn, fetcher_fn))
    }
}

/// Represents a fetcher key like "header(host)" with name and arguments
#[derive(Debug)]
struct FetcherKey {
    name: String,
    args: Vec<String>,
}

/// Specifies the expected matcher type for a fetcher
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherType {
    /// String with default exact matching
    String,
    /// String with default regex matching
    Regex,
    Number,
    Bool,
    Ip,
}

/// Callback type for fetchers (zero-sized)
pub type FetcherFn<Ctx> = for<'a> fn(&'a Ctx, &[String]) -> Option<Value<'a>>;

/// Callback type for operators (zero-sized)
pub type OperatorFn = fn(MatcherType, &JsonValue) -> StdResult<OperatorCheckFn, String>;

/// Callback type for operator check function
pub type OperatorCheckFn = Box<dyn Fn(Value) -> bool>;

/// Holds a fetcher's required matcher type and function
struct Fetcher<Ctx> {
    matcher_type: MatcherType,
    func: FetcherFn<Ctx>,
}

impl<Ctx> Clone for Fetcher<Ctx> {
    fn clone(&self) -> Self {
        Fetcher {
            matcher_type: self.matcher_type,
            func: self.func,
        }
    }
}

/// Rules engine for registering fetchers and parsing rules
pub struct Engine<Ctx> {
    fetchers: HashMap<String, Fetcher<Ctx>>,
    operators: HashMap<String, OperatorFn>,
}

impl<Ctx> Default for Engine<Ctx> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Ctx> Clone for Engine<Ctx> {
    fn clone(&self) -> Self {
        Engine {
            fetchers: self.fetchers.clone(),
            operators: self.operators.clone(),
        }
    }
}

impl<Ctx> Engine<Ctx> {
    /// Creates a new rules engine
    pub fn new() -> Self {
        Engine {
            fetchers: HashMap::new(),
            operators: HashMap::new(),
        }
    }

    /// Registers a fetcher with its name, matcher type, and function
    pub fn register_fetcher(
        &mut self,
        name: &str,
        matcher_type: MatcherType,
        func: FetcherFn<Ctx>,
    ) {
        let fetcher = Fetcher { matcher_type, func };
        self.fetchers.insert(name.to_string(), fetcher);
    }

    /// Registers a custom operator
    pub fn register_operator(&mut self, op: &str, func: OperatorFn) {
        self.operators.insert(op.to_string(), func);
    }

    /// Parses a JSON value into a [`Rule`] using the registered fetchers
    pub fn parse_json(&self, json: &JsonValue) -> Result<Rule<Ctx>> {
        self.parse_rules(json).map(Rule::all)
    }
}

impl<Ctx> Rule<Ctx> {
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
mod parser;
