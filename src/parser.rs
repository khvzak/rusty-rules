use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use std::rc::Rc;
use std::str::FromStr;

use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use regex::{Regex, RegexSet};
use serde_json::{Map, Value as JsonValue};

use crate::{Engine, FetcherFn, FetcherKey, Matcher, MatcherType, Rule, Value};

impl<Ctx> Engine<Ctx> {
    /// Parses a JSON value into a Vec<Rule>
    pub(crate) fn parse_rules(&self, json: &JsonValue) -> Result<Vec<Rule<Ctx>>, String> {
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
                                .ok_or_else(|| format!("Unknown fetcher: {}", name))?;
                            let matcher = self.parse_matcher(fetcher.matcher_type, value)?;

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
            _ => Err("Rule must be a JSON object or array".to_string()),
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
    fn parse_fetcher_key(key: &str) -> Result<FetcherKey, String> {
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
            _ => {
                if let Some(op_fn) = self.operators.get(op) {
                    let check_fn = op_fn(MatcherType::String, value)?;
                    Ok(Matcher::Custom(check_fn))
                } else {
                    Err(format!("Unknown operator: {op}"))
                }
            }
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
            _ => {
                if let Some(op_fn) = self.operators.get(op) {
                    let check_fn = op_fn(MatcherType::Number, value)?;
                    Ok(Matcher::Custom(check_fn))
                } else {
                    Err(format!("Unknown operator: {op}"))
                }
            }
        }
    }
}
