use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use regex::{Regex, RegexSet};
use serde_json::{Map, Value as JsonValue};

use crate::{CheckFn, Error, JsonValueExt as _, Result, Value};

/// Represents an operator that used to check if a fetched value satisfies the condition.
pub enum Operator {
    Equal(Value<'static>),
    LessThan(Value<'static>),
    LessThanOrEqual(Value<'static>),
    GreaterThan(Value<'static>),
    GreaterThanOrEqual(Value<'static>),
    InList(HashSet<Value<'static>>),
    Regex(regex::Regex),
    RegexSet(regex::RegexSet),
    IpSet(IpnetTrie<()>),
    Custom(CheckFn),
}

/// Trait for types matchers
#[cfg(not(feature = "send"))]
pub trait Matcher {
    /// Parses the JSON configuration and returns an [`Operator`].
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator>;
}

/// Trait for types matchers
#[cfg(feature = "send")]
pub trait Matcher: Send + Sync {
    /// Parses the JSON configuration and returns an [`Operator`].
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator>;
}

/// A matcher for string values.
///
/// It supports custom operators.
pub struct StringMatcher;

impl Matcher for StringMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator> {
        macro_rules! type_mismatch {
            ($($arg:tt)*) => {
                Err(Error::matcher("String", fetcher, format!($($arg)*)))
            };
        }

        match value {
            JsonValue::String(s) => Ok(Operator::Equal(Value::String(Cow::Owned(s.clone())))),
            JsonValue::Number(n) => Ok(Operator::Equal(Value::String(Cow::Owned(n.to_string())))),
            JsonValue::Array(seq) => {
                let list = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::String(s) => Ok(Value::String(Cow::Owned(s.clone()))),
                        JsonValue::Number(n) => Ok(Value::String(Cow::Owned(n.to_string()))),
                        _ => type_mismatch!("unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<HashSet<_>>>()?;
                Ok(Operator::InList(list))
            }
            JsonValue::Object(map) => Self::parse_op(fetcher, map),
            _ => type_mismatch!("unexpected JSON {}", value.type_name()),
        }
    }
}

impl StringMatcher {
    fn parse_op(fetcher: &str, map: &Map<String, JsonValue>) -> Result<Operator> {
        let len = map.len();
        if len != 1 {
            let msg = format!("'{fetcher}' operator object must have exactly one key (got {len})",);
            return Err(Error::InvalidJson(msg));
        }

        macro_rules! type_mismatch {
            ($op:expr, $($arg:tt)*) => {
                Err(Error::operator($op, fetcher, format!($($arg)*)))
            };
        }

        let (op, value) = map.iter().next().unwrap();
        match (op.as_str(), value) {
            ("<", JsonValue::String(s)) => Ok(Operator::LessThan(Value::from(s).into_static())),
            ("<=", JsonValue::String(s)) => {
                Ok(Operator::LessThanOrEqual(Value::from(s).into_static()))
            }
            (">", JsonValue::String(s)) => Ok(Operator::GreaterThan(Value::from(s).into_static())),
            (">=", JsonValue::String(s)) => {
                Ok(Operator::GreaterThanOrEqual(Value::from(s).into_static()))
            }
            ("==", JsonValue::String(s)) => Ok(Operator::Equal(Value::from(s).into_static())),
            ("<" | "<=" | ">" | ">=" | "==", _) => {
                type_mismatch!(op, "unexpected JSON {}", value.type_name())
            }
            ("in", JsonValue::Array(seq)) => {
                let list = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::String(s) => Ok(Value::from(s).into_static()),
                        _ => type_mismatch!(op, "unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<HashSet<_>>>()?;
                Ok(Operator::InList(list))
            }
            ("in", _) => type_mismatch!(op, "unexpected JSON {}", value.type_name()),
            ("re", JsonValue::String(pattern)) => {
                let regex = Regex::new(pattern).map_err(|err| Error::operator(op, fetcher, err))?;
                Ok(Operator::Regex(regex))
            }
            ("re", JsonValue::Array(patterns)) => {
                let patterns = patterns
                    .iter()
                    .map(|v| match v {
                        JsonValue::String(s) => Ok(s.clone()),
                        _ => type_mismatch!(op, "unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let regex_set =
                    RegexSet::new(&patterns).map_err(|err| Error::operator(op, fetcher, err))?;
                Ok(Operator::RegexSet(regex_set))
            }
            ("re", _) => type_mismatch!(op, "unexpected JSON {}", value.type_name()),
            _ => Err(Error::UnknownOperator(op.clone())),
        }
    }
}

/// A matcher for string values with regular expressions by default.
///
/// Does not support custom operators.
pub struct RegexMatcher;

impl Matcher for RegexMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator> {
        macro_rules! type_mismatch {
            ($($arg:tt)*) => {
                Err(Error::matcher("Regex", fetcher, format!($($arg)*)))
            };
        }

        match value {
            JsonValue::String(pattern) => Ok(Operator::Regex(
                Regex::new(pattern).map_err(|err| Error::matcher("Regex", fetcher, err))?,
            )),
            JsonValue::Array(patterns) => {
                let patterns = patterns
                    .iter()
                    .map(|v| match v {
                        JsonValue::String(s) => Ok(s),
                        _ => type_mismatch!("unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let regex_set = RegexSet::new(&patterns)
                    .map_err(|err| Error::matcher("Regex", fetcher, err))?;
                Ok(Operator::RegexSet(regex_set))
            }
            _ => type_mismatch!("unexpected JSON {}", value.type_name()),
        }
    }
}

/// A matcher for number values.
///
/// It supports custom operators.
pub struct NumberMatcher;

impl Matcher for NumberMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator> {
        macro_rules! type_mismatch {
            ($($arg:tt)*) => {
                Err(Error::matcher("Number", fetcher, format!($($arg)*)))
            };
        }

        match value {
            JsonValue::Number(n) => Ok(Operator::Equal(Value::Number(n.clone()))),
            JsonValue::Array(seq) => {
                let list = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::Number(n) => Ok(Value::Number(n.clone())),
                        _ => type_mismatch!("unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<HashSet<_>>>()?;
                Ok(Operator::InList(list))
            }
            JsonValue::Object(map) => Self::parse_op(fetcher, map),
            _ => type_mismatch!("unexpected JSON {}", value.type_name()),
        }
    }
}

impl NumberMatcher {
    fn parse_op(fetcher: &str, map: &Map<String, JsonValue>) -> Result<Operator> {
        let len = map.len();
        if len != 1 {
            let msg = format!("'{fetcher}' operator object must have exactly one key (got {len})",);
            return Err(Error::InvalidJson(msg));
        }

        macro_rules! type_mismatch {
            ($op:expr, $($arg:tt)*) => {
                Err(Error::operator($op, fetcher, format!($($arg)*)))
            };
        }

        let (op, value) = map.iter().next().unwrap();
        match (op.as_str(), value) {
            ("<", JsonValue::Number(n)) => Ok(Operator::LessThan(Value::Number(n.clone()))),
            ("<=", JsonValue::Number(n)) => Ok(Operator::LessThanOrEqual(Value::Number(n.clone()))),
            (">", JsonValue::Number(n)) => Ok(Operator::GreaterThan(Value::Number(n.clone()))),
            (">=", JsonValue::Number(n)) => {
                Ok(Operator::GreaterThanOrEqual(Value::Number(n.clone())))
            }
            ("==", JsonValue::Number(n)) => Ok(Operator::Equal(Value::Number(n.clone()))),
            ("<" | "<=" | ">" | ">=" | "==", _) => {
                type_mismatch!(op, "unexpected JSON {}", value.type_name())
            }
            ("in", JsonValue::Array(seq)) => {
                let list = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::Number(n) => Ok(Value::Number(n.clone())),
                        _ => type_mismatch!(op, "unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<HashSet<_>>>()?;
                Ok(Operator::InList(list))
            }
            ("in", _) => type_mismatch!(op, "unexpected JSON {}", value.type_name()),
            _ => Err(Error::UnknownOperator(op.clone())),
        }
    }
}

/// A matcher for boolean values.
///
/// Does not support custom operators.
pub struct BoolMatcher;

impl Matcher for BoolMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator> {
        macro_rules! type_mismatch {
            ($($arg:tt)*) => {
                Err(Error::matcher("Bool", fetcher, format!($($arg)*)))
            };
        }

        match value {
            JsonValue::Bool(b) => Ok(Operator::Equal(Value::Bool(*b))),
            _ => type_mismatch!("unexpected JSON {}", value.type_name()),
        }
    }
}

/// A matcher for IP subnets.
///
/// Does not support custom operators.
pub struct IpMatcher;

impl Matcher for IpMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator> {
        macro_rules! type_mismatch {
            ($($arg:tt)*) => {
                Err(Error::matcher("Ip", fetcher, format!($($arg)*)))
            };
        }

        let addrs = match value {
            JsonValue::String(s) => vec![s],
            JsonValue::Array(seq) => seq
                .iter()
                .map(|v| match v {
                    JsonValue::String(s) => Ok(s),
                    _ => type_mismatch!("unexpected JSON {} in array", v.type_name()),
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return type_mismatch!("unexpected JSON {}", value.type_name()),
        };

        let mut table = IpnetTrie::new();
        for addr in addrs {
            let net = if addr.contains('/') {
                IpNet::from_str(addr).map_err(|err| Error::matcher("Ip", fetcher, err))?
            } else {
                IpNet::from(
                    IpAddr::from_str(addr).map_err(|err| Error::matcher("Ip", fetcher, err))?,
                )
            };
            table.insert(net, ());
        }
        Ok(Operator::IpSet(table))
    }
}
