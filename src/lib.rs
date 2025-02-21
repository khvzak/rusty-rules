use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use regex::{Regex, RegexSet};
use serde_json::{Map, Number, Value as JsonValue};

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

impl TryFrom<&serde_json::Value> for Value<'_> {
    type Error = ();

    fn try_from(value: &serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::String(s) => Ok(Value::String(Cow::Owned(s.clone()))),
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
    fn try_from(f: f64) -> Result<Self, Self::Error> {
        Ok(Value::Number(serde_json::Number::from_f64(f).ok_or(())?))
    }
}

/// Represents conditions to match against fetched values
pub enum Matcher {
    Equal(Value<'static>),
    LessThan(Value<'static>),
    LessThanOrEqual(Value<'static>),
    GreaterThan(Value<'static>),
    GreaterThanOrEqual(Value<'static>),
    InList(HashSet<Value<'static>>),
    Regex(regex::Regex),
    RegexSet(regex::RegexSet),
    IpSet(IpnetTrie<()>),
}

/// Represents a rule, which can be a condition or a logical combination
pub enum Rule<Ctx> {
    Any(Vec<Self>),
    All(Vec<Self>),
    Not(Box<Self>),
    Leaf(Box<dyn Fn(FetcherFn<Ctx>, &Ctx) -> bool>, FetcherFn<Ctx>),
}

/// Represents a fetcher key like "header(host)" with name and arguments
#[derive(Debug)]
pub struct FetcherKey {
    name: String,
    args: Vec<String>,
}

/// Specifies the expected matcher type for a fetcher
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherType {
    /// String with default exact matching
    String,
    /// String with default regex matching
    StringRe,
    Number,
    Bool,
    Ip,
}

pub type FetcherFn<Ctx> = for<'a> fn(&'a Ctx, &[String]) -> Option<Value<'a>>;

/// Holds a fetcher's required matcher type and function
struct Fetcher<Ctx> {
    matcher_type: MatcherType,
    func: FetcherFn<Ctx>,
}

pub struct Engine<Ctx> {
    registry: HashMap<String, Fetcher<Ctx>>,
}

impl<Ctx> Default for Engine<Ctx> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Ctx> Engine<Ctx> {
    /// Creates a new rules engine
    pub fn new() -> Self {
        Engine {
            registry: HashMap::new(),
        }
    }

    /// Registers a fetcher with its name, return type, and function
    pub fn register_fetcher(
        &mut self,
        name: &str,
        matcher_type: MatcherType,
        func: FetcherFn<Ctx>,
    ) {
        let fetcher = Fetcher { matcher_type, func };
        self.registry.insert(name.to_string(), fetcher);
    }

    /// Parses a JSON value into a Rule
    pub fn parse_json(&self, json: &JsonValue) -> Result<Rule<Ctx>, String> {
        Ok(Rule::All(self.parse_rules(&json)?))
    }

    /// Evaluates a rule against a context
    pub fn evaluate(&self, rule: &Rule<Ctx>, context: &Ctx) -> bool {
        match rule {
            Rule::Leaf(test_fn, fetcher_fn) => test_fn(*fetcher_fn, context),
            Rule::Any(subrules) => subrules.iter().any(|r| self.evaluate(r, context)),
            Rule::All(subrules) => subrules.iter().all(|r| self.evaluate(r, context)),
            Rule::Not(subrule) => !self.evaluate(subrule, context),
        }
    }

    /// Parses a JSON value into a Vec<Rule>
    fn parse_rules(&self, json: &JsonValue) -> Result<Vec<Rule<Ctx>>, String> {
        match json {
            JsonValue::Object(map) => {
                let mut rules = Vec::with_capacity(map.len());
                for (key, value) in map {
                    match key.as_str() {
                        "any" => {
                            rules.push(Rule::Any(self.parse_rules(value)?));
                        }
                        "all" => {
                            rules.push(Rule::All(self.parse_rules(value)?));
                        }
                        "not" => {
                            rules.push(Rule::Not(Box::new(Rule::All(self.parse_rules(value)?))));
                        }
                        _ => {
                            let FetcherKey { name, args } = self.parse_fetcher_key(key)?;
                            let fetcher = self
                                .registry
                                .get(&name)
                                .ok_or_else(|| format!("Unknown fetcher: {}", name))?;
                            let matcher = self.parse_matcher(fetcher.matcher_type, value)?;

                            let test_fn = Self::compile_condition(args, matcher);
                            rules.push(Rule::Leaf(test_fn, fetcher.func));
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
            _ => Err("Rule must be a JSON object or array".to_string()),
        }
    }

    fn compile_condition(
        fetcher_args: Vec<String>,
        matcher: Matcher,
    ) -> Box<dyn Fn(FetcherFn<Ctx>, &Ctx) -> bool> {
        match matcher {
            Matcher::Equal(right) => Box::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left == right)
                    .unwrap_or_default()
            }),
            Matcher::LessThan(right) => Box::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left < right)
                    .unwrap_or_default()
            }),
            Matcher::LessThanOrEqual(right) => Box::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left <= right)
                    .unwrap_or_default()
            }),
            Matcher::GreaterThan(right) => Box::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left > right)
                    .unwrap_or_default()
            }),
            Matcher::GreaterThanOrEqual(right) => Box::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left >= right)
                    .unwrap_or_default()
            }),
            Matcher::InList(list) => Box::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|val| list.contains(&val))
                    .unwrap_or_default()
            }),
            Matcher::Regex(regex) => Box::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|val| match val {
                        Value::String(s) => regex.is_match(&s),
                        _ => false,
                    })
                    .unwrap_or_default()
            }),
            Matcher::RegexSet(regex_set) => Box::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|val| match val {
                        Value::String(s) => regex_set.is_match(&s),
                        _ => false,
                    })
                    .unwrap_or_default()
            }),
            Matcher::IpSet(set) => Box::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|val| match val {
                        Value::Ip(ip) => set.longest_match(&IpNet::from(ip)).is_some(),
                        _ => false,
                    })
                    .unwrap_or_default()
            }),
        }
    }

    /// Parses a key like "header(host)" into [`FetcherKey`]
    fn parse_fetcher_key(&self, key: &str) -> Result<FetcherKey, String> {
        if let Some((name, args_str)) = key.split_once('(') {
            if !args_str.ends_with(')') {
                return Err("Missing closing parenthesis".to_string());
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

    /// Parses a JSON value into a Matcher
    fn parse_matcher(
        &self,
        matcher_type: MatcherType,
        json: &JsonValue,
    ) -> Result<Matcher, String> {
        match matcher_type {
            MatcherType::String => match json {
                JsonValue::String(s) => Ok(Matcher::Equal(Value::String(Cow::Owned(s.clone())))),
                JsonValue::Number(n) => {
                    Ok(Matcher::Equal(Value::String(Cow::Owned(n.to_string()))))
                }
                JsonValue::Array(seq) => {
                    let list = seq
                        .iter()
                        .map(|v| match v {
                            JsonValue::String(s) => Ok(Value::String(Cow::Owned(s.clone()))),
                            _ => Err("Array items must be strings".to_string()),
                        })
                        .collect::<Result<HashSet<_>, _>>()?;
                    Ok(Matcher::InList(list))
                }
                JsonValue::Object(map) => self.parse_string_op(map),
                _ => Err("Invalid value type for string matcher".to_string()),
            },
            MatcherType::StringRe => match json {
                JsonValue::String(pattern) => {
                    let regex = Regex::new(pattern).map_err(|e| format!("Invalid regex: {e}"))?;
                    Ok(Matcher::Regex(regex))
                }
                JsonValue::Array(patterns) => {
                    let patterns = patterns
                        .iter()
                        .map(|p| {
                            if let JsonValue::String(s) = p {
                                Ok(s)
                            } else {
                                Err("Regex patterns must be strings".to_string())
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let regex_set = RegexSet::new(&patterns).map_err(|e| e.to_string())?;
                    Ok(Matcher::RegexSet(regex_set))
                }
                _ => Err("Invalid value type for string regex matcher".to_string()),
            },
            MatcherType::Number => match json {
                JsonValue::Number(n) => Ok(Matcher::Equal(Value::Number(n.clone()))),
                JsonValue::Array(seq) => {
                    let list = seq
                        .iter()
                        .map(|v| match v {
                            JsonValue::Number(n) => Ok(Value::Number(n.clone())),
                            _ => Err("Array items must be numbers".to_string()),
                        })
                        .collect::<Result<HashSet<_>, _>>()?;
                    Ok(Matcher::InList(list))
                }
                JsonValue::Object(map) => self.parse_number_op(map),
                _ => Err("Invalid value type for number matcher".to_string()),
            },
            MatcherType::Bool => match json {
                JsonValue::Bool(b) => Ok(Matcher::Equal(Value::Bool(*b))),
                _ => Err("Invalid value type for boolean matcher".to_string()),
            },
            MatcherType::Ip => match json {
                JsonValue::String(s) => {
                    let net = if s.contains('/') {
                        IpNet::from_str(s).map_err(|e| e.to_string())?
                    } else {
                        IpNet::from(IpAddr::from_str(s).map_err(|e| e.to_string())?)
                    };
                    let mut table = IpnetTrie::new();
                    table.insert(net, ());
                    Ok(Matcher::IpSet(table))
                }
                JsonValue::Array(seq) => {
                    let mut table = IpnetTrie::new();
                    for v in seq {
                        if let JsonValue::String(s) = v {
                            let net = if s.contains('/') {
                                IpNet::from_str(s).map_err(|e| e.to_string())?
                            } else {
                                IpNet::from(IpAddr::from_str(s).map_err(|e| e.to_string())?)
                            };
                            table.insert(net, ());
                        } else {
                            return Err("Array items must be ip addresses".to_string());
                        }
                    }
                    Ok(Matcher::IpSet(table))
                }
                _ => Err("Invalid value type for ip matcher".to_string()),
            },
        }
    }

    fn parse_string_op(&self, map: &Map<String, JsonValue>) -> Result<Matcher, String> {
        if map.len() != 1 {
            return Err("Operator object must have exactly one key".to_string());
        }
        let (op, value) = map.iter().next().unwrap();
        match (op.as_str(), value) {
            ("<", JsonValue::String(s)) => Ok(Matcher::LessThan(Value::from(s).into_static())),
            ("<=", JsonValue::String(s)) => {
                Ok(Matcher::LessThanOrEqual(Value::from(s).into_static()))
            }
            (">", JsonValue::String(s)) => Ok(Matcher::GreaterThan(Value::from(s).into_static())),
            (">=", JsonValue::String(s)) => {
                Ok(Matcher::GreaterThanOrEqual(Value::from(s).into_static()))
            }
            ("==", JsonValue::String(s)) => Ok(Matcher::Equal(Value::from(s).into_static())),
            ("<" | "<=" | ">" | ">=" | "==" | "!=", _) => {
                Err(format!("`{op}` value must be a string"))
            }
            ("in", JsonValue::Array(seq)) => {
                let list = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::String(s) => Ok(Value::from(s).into_static()),
                        _ => Err("Array items must be strings".to_string()),
                    })
                    .collect::<Result<HashSet<_>, _>>()?;
                Ok(Matcher::InList(list))
            }
            ("in", _) => Err("`in` value must be an array of strings".to_string()),
            ("re", JsonValue::String(pattern)) => {
                let regex = Regex::new(pattern).map_err(|e| format!("Invalid regex: {e}"))?;
                Ok(Matcher::Regex(regex))
            }
            ("re", JsonValue::Array(patterns)) => {
                let patterns = patterns
                    .iter()
                    .map(|p| match p {
                        JsonValue::String(s) => Ok(s.clone()),
                        _ => Err("Regex patterns must be strings".to_string()),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let regex_set = RegexSet::new(&patterns).map_err(|e| e.to_string())?;
                Ok(Matcher::RegexSet(regex_set))
            }
            ("re", _) => Err("`re` value must be a string or array of strings".to_string()),
            (op, _) => Err(format!("Unsupported operator: {op}")),
        }
    }

    /// Parses number-specific operators
    fn parse_number_op(&self, map: &Map<String, JsonValue>) -> Result<Matcher, String> {
        if map.len() != 1 {
            return Err("Operator object must have exactly one key".to_string());
        }
        let (op, value) = map.iter().next().unwrap();
        match (op.as_str(), value) {
            ("<", JsonValue::Number(n)) => Ok(Matcher::LessThan(Value::Number(n.clone()))),
            ("<=", JsonValue::Number(n)) => Ok(Matcher::LessThanOrEqual(Value::Number(n.clone()))),
            (">", JsonValue::Number(n)) => Ok(Matcher::GreaterThan(Value::Number(n.clone()))),
            (">=", JsonValue::Number(n)) => {
                Ok(Matcher::GreaterThanOrEqual(Value::Number(n.clone())))
            }
            ("==", JsonValue::Number(n)) => Ok(Matcher::Equal(Value::Number(n.clone()))),
            ("<" | "<=" | ">" | ">=" | "==" | "!=", _) => Err("Value must be a number".to_string()),
            ("in", JsonValue::Array(seq)) => {
                let list = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::Number(n) => Ok(Value::Number(n.clone())),
                        _ => Err("Array items must be numbers".to_string()),
                    })
                    .collect::<Result<HashSet<_>, _>>()?;
                Ok(Matcher::InList(list))
            }
            ("in", _) => Err("`in` value must be an array of numbers".to_string()),
            _ => Err(format!("Unsupported operator: {op}")),
        }
    }
}
