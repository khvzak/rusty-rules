use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use std::rc::Rc;
use std::str::FromStr;

use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use regex::{Regex, RegexSet};
use serde_json::{Map, Value as JsonValue};

use crate::{
    Engine, Error, FetcherFn, FetcherKey, JsonValueExt, Matcher, MatcherType, Result, Rule, Value,
};

impl<Ctx> Engine<Ctx> {
    /// Parses a JSON value into a Vec<Rule>
    pub(crate) fn parse_rules(&self, json: &JsonValue) -> Result<Vec<Rule<Ctx>>> {
        match json {
            JsonValue::Object(map) => {
                let mut rules = Vec::with_capacity(map.len());
                for (key, value) in map {
                    match key.as_str() {
                        "any" => {
                            rules.push(Rule::any(self.parse_rules(value)?));
                        }
                        "all" => {
                            rules.push(Rule::all(self.parse_rules(value)?));
                        }
                        "not" => {
                            rules.push(Rule::not(Rule::all(self.parse_rules(value)?)));
                        }
                        _ => {
                            let FetcherKey { name, args } = Self::parse_fetcher_key(key)?;
                            let fetcher = self
                                .fetchers
                                .get(&name)
                                .ok_or_else(|| Error::UnknownFetcher(name.clone()))?;
                            let matcher = self.parse_matcher(&name, fetcher.matcher_type, value)?;

                            let test_fn = Self::compile_condition(args, matcher);
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

    fn compile_condition(
        fetcher_args: Vec<String>,
        matcher: Matcher,
    ) -> Rc<dyn Fn(FetcherFn<Ctx>, &Ctx) -> bool> {
        match matcher {
            Matcher::Equal(right) => Rc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left == right)
                    .unwrap_or_default()
            }),
            Matcher::LessThan(right) => Rc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left < right)
                    .unwrap_or_default()
            }),
            Matcher::LessThanOrEqual(right) => Rc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left <= right)
                    .unwrap_or_default()
            }),
            Matcher::GreaterThan(right) => Rc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left > right)
                    .unwrap_or_default()
            }),
            Matcher::GreaterThanOrEqual(right) => Rc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|left| left >= right)
                    .unwrap_or_default()
            }),
            Matcher::InList(list) => Rc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|val| list.contains(&val))
                    .unwrap_or_default()
            }),
            Matcher::Regex(regex) => Rc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|val| match val {
                        Value::String(s) => regex.is_match(&s),
                        _ => false,
                    })
                    .unwrap_or_default()
            }),
            Matcher::RegexSet(regex_set) => Rc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|val| match val {
                        Value::String(s) => regex_set.is_match(&s),
                        _ => false,
                    })
                    .unwrap_or_default()
            }),
            Matcher::IpSet(set) => Rc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(|val| match val {
                        Value::Ip(ip) => set.longest_match(&IpNet::from(ip)).is_some(),
                        _ => false,
                    })
                    .unwrap_or_default()
            }),
            Matcher::Custom(check_fn) => Rc::new(move |fetcher, ctx| {
                fetcher(ctx, &fetcher_args)
                    .map(&check_fn)
                    .unwrap_or_default()
            }),
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

    /// Parses a JSON value into a Matcher
    fn parse_matcher(
        &self,
        fetcher_name: &str,
        matcher_type: MatcherType,
        json: &JsonValue,
    ) -> Result<Matcher> {
        macro_rules! type_mismatch {
            ($($arg:tt)*) => {
                Err(Error::matcher(matcher_type, fetcher_name, format!($($arg)*)))
            };
        }

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
                            JsonValue::Number(n) => Ok(Value::String(Cow::Owned(n.to_string()))),
                            _ => type_mismatch!("unexpected JSON {} in array", v.type_name()),
                        })
                        .collect::<Result<HashSet<_>>>()?;
                    Ok(Matcher::InList(list))
                }
                JsonValue::Object(map) => self.parse_string_op(fetcher_name, map),
                _ => type_mismatch!("unexpected JSON {}", json.type_name()),
            },
            MatcherType::Regex => match json {
                JsonValue::String(pattern) => {
                    Ok(Matcher::Regex(Regex::new(pattern).map_err(|err| {
                        Error::matcher(matcher_type, fetcher_name, err)
                    })?))
                }
                JsonValue::Array(patterns) => {
                    let patterns = patterns
                        .iter()
                        .map(|v| match v {
                            JsonValue::String(s) => Ok(s),
                            _ => type_mismatch!("unexpected JSON {} in array", v.type_name()),
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let regex_set = RegexSet::new(&patterns)
                        .map_err(|err| Error::matcher(matcher_type, fetcher_name, err))?;
                    Ok(Matcher::RegexSet(regex_set))
                }
                _ => type_mismatch!("unexpected JSON {}", json.type_name()),
            },
            MatcherType::Number => match json {
                JsonValue::Number(n) => Ok(Matcher::Equal(Value::Number(n.clone()))),
                JsonValue::Array(seq) => {
                    let list = seq
                        .iter()
                        .map(|v| match v {
                            JsonValue::Number(n) => Ok(Value::Number(n.clone())),
                            _ => type_mismatch!("unexpected JSON {} in array", v.type_name()),
                        })
                        .collect::<Result<HashSet<_>>>()?;
                    Ok(Matcher::InList(list))
                }
                JsonValue::Object(map) => self.parse_number_op(fetcher_name, map),
                _ => type_mismatch!("unexpected JSON {}", json.type_name()),
            },
            MatcherType::Bool => match json {
                JsonValue::Bool(b) => Ok(Matcher::Equal(Value::Bool(*b))),
                _ => type_mismatch!("unexpected JSON {}", json.type_name()),
            },
            MatcherType::Ip => {
                let addrs = match json {
                    JsonValue::String(s) => vec![s],
                    JsonValue::Array(seq) => seq
                        .iter()
                        .map(|v| match v {
                            JsonValue::String(s) => Ok(s),
                            _ => type_mismatch!("unexpected JSON {} in array", v.type_name()),
                        })
                        .collect::<Result<Vec<_>>>()?,
                    _ => return type_mismatch!("unexpected JSON {}", json.type_name()),
                };
                let mut table = IpnetTrie::new();
                for addr in addrs {
                    let net = if addr.contains('/') {
                        IpNet::from_str(addr)
                            .map_err(|err| Error::matcher(matcher_type, fetcher_name, err))?
                    } else {
                        IpNet::from(
                            IpAddr::from_str(addr)
                                .map_err(|err| Error::matcher(matcher_type, fetcher_name, err))?,
                        )
                    };
                    table.insert(net, ());
                }
                Ok(Matcher::IpSet(table))
            }
        }
    }

    fn parse_string_op(&self, fetcher_name: &str, map: &Map<String, JsonValue>) -> Result<Matcher> {
        let len = map.len();
        if len != 1 {
            let msg =
                format!("'{fetcher_name}' operator object must have exactly one key (got {len})",);
            return Err(Error::InvalidJson(msg));
        }

        macro_rules! op_type_mismatch {
            ($op:expr, $($arg:tt)*) => {
                Err(Error::operator($op, fetcher_name, format!($($arg)*)))
            };
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
                op_type_mismatch!(op, "unexpected JSON {}", value.type_name())
            }
            ("in", JsonValue::Array(seq)) => {
                let list = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::String(s) => Ok(Value::from(s).into_static()),
                        _ => op_type_mismatch!(op, "unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<HashSet<_>>>()?;
                Ok(Matcher::InList(list))
            }
            ("in", _) => op_type_mismatch!(op, "unexpected JSON {}", value.type_name()),
            ("re", JsonValue::String(pattern)) => {
                let regex =
                    Regex::new(pattern).map_err(|err| Error::operator("re", fetcher_name, err))?;
                Ok(Matcher::Regex(regex))
            }
            ("re", JsonValue::Array(patterns)) => {
                let patterns = patterns
                    .iter()
                    .map(|v| match v {
                        JsonValue::String(s) => Ok(s.clone()),
                        _ => op_type_mismatch!("re", "unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let regex_set = RegexSet::new(&patterns)
                    .map_err(|err| Error::operator("re", fetcher_name, err))?;
                Ok(Matcher::RegexSet(regex_set))
            }
            ("re", _) => op_type_mismatch!(op, "unexpected JSON {}", value.type_name()),
            _ => {
                if let Some(op_fn) = self.operators.get(op) {
                    let check_fn = op_fn(MatcherType::String, value)
                        .map_err(|err| Error::operator(op, fetcher_name, err))?;
                    Ok(Matcher::Custom(check_fn))
                } else {
                    Err(Error::UnknownOperator(op.clone()))
                }
            }
        }
    }

    /// Parses number-specific operators
    fn parse_number_op(&self, fetcher_name: &str, map: &Map<String, JsonValue>) -> Result<Matcher> {
        let len = map.len();
        if len != 1 {
            let msg =
                format!("'{fetcher_name}' operator object must have exactly one key (got {len})",);
            return Err(Error::InvalidJson(msg));
        }

        macro_rules! op_type_mismatch {
            ($op:expr, $($arg:tt)*) => {
                Err(Error::operator($op, fetcher_name, format!($($arg)*)))
            };
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
            ("<" | "<=" | ">" | ">=" | "==" | "!=", _) => {
                op_type_mismatch!(op, "unexpected JSON {}", value.type_name())
            }
            ("in", JsonValue::Array(seq)) => {
                let list = seq
                    .iter()
                    .map(|v| match v {
                        JsonValue::Number(n) => Ok(Value::Number(n.clone())),
                        _ => op_type_mismatch!(op, "unexpected JSON {} in array", v.type_name()),
                    })
                    .collect::<Result<HashSet<_>>>()?;
                Ok(Matcher::InList(list))
            }
            ("in", _) => op_type_mismatch!(op, "unexpected JSON {}", value.type_name()),
            _ => {
                if let Some(op_fn) = self.operators.get(op) {
                    let check_fn = op_fn(MatcherType::Number, value)
                        .map_err(|err| Error::operator(op, fetcher_name, err))?;
                    Ok(Matcher::Custom(check_fn))
                } else {
                    Err(Error::UnknownOperator(op.clone()))
                }
            }
        }
    }
}
