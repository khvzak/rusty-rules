use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use regex::{Regex, RegexSet};
use serde_json::{Map, Value as JsonValue};

use crate::{CheckFn, Error, JsonValueExt as _, Result, Value};

use crate::AsyncCheckFn;

/// Represents an operator that used to check if a fetched value satisfies the condition.
pub enum Operator<Ctx: ?Sized> {
    Equal(Value<'static>),
    LessThan(Value<'static>),
    LessThanOrEqual(Value<'static>),
    GreaterThan(Value<'static>),
    GreaterThanOrEqual(Value<'static>),
    InSet(HashSet<Value<'static>>),
    Regex(regex::Regex),
    RegexSet(regex::RegexSet),
    IpSet(IpnetTrie<()>),
    Custom(Box<CheckFn<Ctx>>),
    CustomAsync(Box<AsyncCheckFn<Ctx>>),
}

/// Trait for types matchers
#[cfg(not(feature = "send"))]
pub trait Matcher<Ctx: ?Sized> {
    /// Parses the JSON configuration and returns an [`Operator`].
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>>;
}

/// Trait for types matchers
#[cfg(feature = "send")]
pub trait Matcher<Ctx: ?Sized>: Send + Sync {
    /// Parses the JSON configuration and returns an [`Operator`].
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>>;
}

macro_rules! matcher_error {
    ($mtype:expr, $fetcher:expr, $($arg:tt)*) => {
        Err(Error::matcher($mtype, $fetcher, format!($($arg)*)))
    };
}

macro_rules! operator_error {
    ($op:expr, $fetcher:expr, $($arg:tt)*) => {
        Err(Error::operator($op, $fetcher, format!($($arg)*)))
    };
}

macro_rules! check_operator {
    ($fetcher:expr, $map:expr) => {{
        let len = $map.len();
        if len != 1 {
            #[rustfmt::skip]
            let msg = format!("'{}' operator object must have exactly one key (got {len})", $fetcher);
            return Err(Error::InvalidJson(msg));
        }
        $map.iter().next().unwrap()
    }};
}

/// A matcher for string values.
///
/// It supports custom operators.
pub struct StringMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for StringMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>> {
        macro_rules! type_mismatch {
            ($($arg:tt)*) => {
                Err(Error::matcher("String", fetcher, format!($($arg)*)))
            };
        }

        match value {
            JsonValue::String(s) => Ok(Operator::Equal(Value::String(Cow::Owned(s.clone())))),
            JsonValue::Number(n) => Ok(Operator::Equal(Value::String(Cow::Owned(n.to_string())))),
            JsonValue::Array(seq) => {
                let set = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::String(s) => Ok(Value::String(Cow::Owned(s.clone()))),
                        JsonValue::Number(n) => Ok(Value::String(Cow::Owned(n.to_string()))),
                        _ => type_mismatch!("unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<HashSet<_>>>()?;
                Ok(Operator::InSet(set))
            }
            JsonValue::Object(map) => Self::parse_op(fetcher, map),
            _ => type_mismatch!("unexpected JSON {}", value.type_name()),
        }
    }
}

impl StringMatcher {
    fn parse_op<Ctx: ?Sized>(fetcher: &str, map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
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
                let set = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::String(s) => Ok(Value::from(s).into_static()),
                        _ => type_mismatch!(op, "unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<HashSet<_>>>()?;
                Ok(Operator::InSet(set))
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

impl<Ctx: ?Sized> Matcher<Ctx> for RegexMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>> {
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

impl<Ctx: ?Sized> Matcher<Ctx> for NumberMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>> {
        macro_rules! type_mismatch {
            ($($arg:tt)*) => {
                Err(Error::matcher("Number", fetcher, format!($($arg)*)))
            };
        }

        match value {
            JsonValue::Number(n) => Ok(Operator::Equal(Value::Number(n.clone()))),
            JsonValue::Array(seq) => {
                let set = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::Number(n) => Ok(Value::Number(n.clone())),
                        _ => type_mismatch!("unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<HashSet<_>>>()?;
                Ok(Operator::InSet(set))
            }
            JsonValue::Object(map) => Self::parse_op(fetcher, map),
            _ => type_mismatch!("unexpected JSON {}", value.type_name()),
        }
    }
}

impl NumberMatcher {
    fn parse_op<Ctx: ?Sized>(fetcher: &str, map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
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
                let set = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::Number(n) => Ok(Value::Number(n.clone())),
                        _ => type_mismatch!(op, "unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<HashSet<_>>>()?;
                Ok(Operator::InSet(set))
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

impl<Ctx: ?Sized> Matcher<Ctx> for BoolMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>> {
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
/// It supports custom operators.
pub struct IpMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for IpMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::String(_) => {
                Self::make_ipnet(fetcher, &[value.clone()]).map(Operator::IpSet)
            }
            JsonValue::Array(addrs) => Self::make_ipnet(fetcher, &addrs).map(Operator::IpSet),
            JsonValue::Object(map) => Self::parse_op(fetcher, map),
            _ => matcher_error!("Ip", fetcher, "unexpected JSON {}", value.type_name()),
        }
    }
}

impl IpMatcher {
    fn parse_op<Ctx: ?Sized>(fetcher: &str, map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
        let (op, value) = check_operator!(fetcher, map);
        match (op.as_str(), value) {
            ("in", JsonValue::Array(addrs)) => {
                Self::make_ipnet(fetcher, &addrs).map(Operator::IpSet)
            }
            ("in", _) => operator_error!(op, fetcher, "unexpected JSON {}", value.type_name()),
            _ => Err(Error::UnknownOperator(op.clone())),
        }
    }

    /// Creates an [`IpnetTrie`] from a list of IP addresses or CIDR ranges.
    pub fn make_ipnet(fetcher: &str, addrs: &[JsonValue]) -> Result<IpnetTrie<()>> {
        let mut table = IpnetTrie::new();
        for addr in addrs {
            let addr = match addr {
                JsonValue::String(s) => s,
                #[rustfmt::skip]
                _ => matcher_error!("Ip", fetcher, "unexpected JSON {} in array", addr.type_name())?,
            };
            let net = if addr.contains('/') {
                IpNet::from_str(addr).map_err(|err| Error::matcher("Ip", fetcher, err))?
            } else {
                IpNet::from(
                    IpAddr::from_str(addr).map_err(|err| Error::matcher("Ip", fetcher, err))?,
                )
            };
            table.insert(net, ());
        }
        Ok(table)
    }
}
