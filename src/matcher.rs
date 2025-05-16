use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::result::Result as StdResult;
use std::str::FromStr;

use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use regex::{Regex, RegexSet};
use serde_json::{Map, Value as JsonValue};

use crate::{CheckFn, Error, JsonValueExt as _, MaybeSend, MaybeSync, Result, Value};

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

impl<Ctx: ?Sized> fmt::Debug for Operator<Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operator::Equal(v) => write!(f, "Equal({v:?})"),
            Operator::LessThan(v) => write!(f, "LessThan({v:?})"),
            Operator::LessThanOrEqual(v) => write!(f, "LessThanOrEqual({v:?})"),
            Operator::GreaterThan(v) => write!(f, "GreaterThan({v:?})"),
            Operator::GreaterThanOrEqual(v) => write!(f, "GreaterThanOrEqual({v:?})"),
            Operator::InSet(set) => write!(f, "InSet({set:?})",),
            Operator::Regex(regex) => write!(f, "Regex({regex:?})"),
            Operator::RegexSet(regex_set) => write!(f, "RegexSet({regex_set:?})"),
            Operator::IpSet(_) => f.write_str("IpSet"),
            Operator::Custom(_) => f.write_str("Custom"),
            Operator::CustomAsync(_) => f.write_str("CustomAsync"),
        }
    }
}

/// Trait for types matchers
pub trait Matcher<Ctx: ?Sized>: MaybeSend + MaybeSync {
    /// Parses the JSON configuration and returns an [`Operator`].
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>>;

    /// Returns an optional JSON Schema that describes valid inputs for this matcher.
    fn json_schema(&self, custom_ops: &[&str]) -> Option<JsonValue> {
        let _ = custom_ops;
        None
    }
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
        match value {
            JsonValue::String(s) => Ok(Operator::Equal(Value::String(Cow::Owned(s.clone())))),
            JsonValue::Array(seq) => Self::make_hashset(seq)
                .map(Operator::InSet)
                .map_err(|err| Error::matcher("String", fetcher, err)),
            JsonValue::Object(map) => Self::parse_op(fetcher, map),
            _ => {
                let msg = format!("unexpected JSON {}", value.type_name());
                Err(Error::matcher("String", fetcher, msg))
            }
        }
    }

    fn json_schema(&self, custom_ops: &[&str]) -> Option<JsonValue> {
        StringMatcher::json_schema(self, custom_ops)
    }
}

impl StringMatcher {
    fn parse_op<Ctx: ?Sized>(fetcher: &str, map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
        let (op, value) = check_operator!(fetcher, map);
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
                operator_error!(op, fetcher, "unexpected JSON {}", value.type_name())
            }
            ("in", JsonValue::Array(arr)) => Self::make_hashset(arr)
                .map(Operator::InSet)
                .map_err(|err| Error::operator(op, fetcher, err)),
            ("in", _) => operator_error!(op, fetcher, "unexpected JSON {}", value.type_name()),
            ("re", JsonValue::String(pattern)) => {
                let regex = Regex::new(pattern).map_err(|err| Error::operator(op, fetcher, err))?;
                Ok(Operator::Regex(regex))
            }
            ("re", JsonValue::Array(patterns)) => RegexMatcher::make_regex_set(patterns)
                .map(Operator::RegexSet)
                .map_err(|err| Error::operator(op, fetcher, err)),
            ("re", _) => operator_error!(op, fetcher, "unexpected JSON {}", value.type_name()),
            _ => Err(Error::UnknownOperator(op.clone())),
        }
    }

    /// Creates a [`HashSet`] from a list of strings.
    fn make_hashset(arr: &[JsonValue]) -> StdResult<HashSet<Value<'static>>, String> {
        arr.iter()
            .map(|v| match v {
                JsonValue::String(s) => Ok(Value::String(Cow::Owned(s.clone()))),
                _ => Err(format!("unexpected JSON {} in string array", v.type_name())),
            })
            .collect::<StdResult<HashSet<_>, _>>()
    }

    /// Provides a JSON Schema for string matcher inputs.
    fn json_schema(&self, custom_ops: &[&str]) -> Option<JsonValue> {
        // Standard schemas
        let string_schema = serde_json::json!({ "type": "string" });
        let string_array_schema = serde_json::json!({"type": "array", "items": string_schema});

        // Add operator schemas
        let mut properties = serde_json::Map::new();
        properties.insert("<".to_string(), string_schema.clone());
        properties.insert("<=".to_string(), string_schema.clone());
        properties.insert(">".to_string(), string_schema.clone());
        properties.insert(">=".to_string(), string_schema.clone());
        properties.insert("==".to_string(), string_schema.clone());
        properties.insert("in".to_string(), string_array_schema.clone());
        properties.insert(
            "re".to_string(),
            serde_json::json!({"oneOf": [string_schema, string_array_schema]}),
        );

        // Add custom operators
        for op in custom_ops {
            properties.insert(op.to_string(), serde_json::json!({}));
        }

        Some(serde_json::json!({
            "oneOf": [
                string_schema,
                string_array_schema,
                // Object with a single operator
                {
                    "type": "object",
                    "properties": properties,
                    "additionalProperties": false,
                    "minProperties": 1,
                    "maxProperties": 1
                }
            ]
        }))
    }
}

/// A matcher for string values with regular expressions by default.
///
/// It supports custom operators.
pub struct RegexMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for RegexMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::String(pattern) => Ok(Operator::Regex(
                Regex::new(pattern).map_err(|err| Error::matcher("Regex", fetcher, err))?,
            )),
            JsonValue::Array(patterns) => Self::make_regex_set(&patterns)
                .map(Operator::RegexSet)
                .map_err(|err| Error::matcher("Regex", fetcher, err)),
            JsonValue::Object(map) => Self::parse_op(fetcher, map),
            _ => {
                let msg = format!("unexpected JSON {}", value.type_name());
                Err(Error::matcher("Regex", fetcher, msg))
            }
        }
    }

    fn json_schema(&self, custom_ops: &[&str]) -> Option<JsonValue> {
        RegexMatcher::json_schema(self, custom_ops)
    }
}

impl RegexMatcher {
    fn parse_op<Ctx: ?Sized>(fetcher: &str, map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
        let (op, value) = check_operator!(fetcher, map);
        match (op.as_str(), value) {
            ("in", JsonValue::Array(patterns)) => Self::make_regex_set(&patterns)
                .map(Operator::RegexSet)
                .map_err(|err| Error::operator(op, fetcher, err)),
            ("in", _) => operator_error!(op, fetcher, "unexpected JSON {}", value.type_name()),
            _ => Err(Error::UnknownOperator(op.clone())),
        }
    }

    /// Creates a [`RegexSet`] from a list of patterns.
    fn make_regex_set(patterns: &[JsonValue]) -> StdResult<RegexSet, String> {
        let patterns = patterns
            .iter()
            .map(|v| match v {
                JsonValue::String(s) => Ok(s),
                #[rustfmt::skip]
                _ => Err(format!("unexpected JSON {} in patterns array", v.type_name())),
            })
            .collect::<StdResult<Vec<_>, String>>()?;
        RegexSet::new(&patterns).map_err(|err| err.to_string())
    }

    /// Provides a JSON Schema for regex matcher inputs.
    fn json_schema(&self, custom_ops: &[&str]) -> Option<JsonValue> {
        // Standard schemas
        let string_schema = serde_json::json!({ "type": "string" });
        let string_array_schema = serde_json::json!({"type": "array", "items": string_schema});

        // Add operator schemas
        let mut properties = serde_json::Map::new();
        properties.insert("in".to_string(), string_array_schema.clone());

        // Add custom operators
        for op in custom_ops {
            properties.insert(op.to_string(), serde_json::json!({}));
        }

        Some(serde_json::json!({
            "oneOf": [
                string_schema,
                string_array_schema,
                // Object with a single operator
                {
                    "type": "object",
                    "properties": properties,
                    "additionalProperties": false,
                    "minProperties": 1,
                    "maxProperties": 1
                }
            ]
        }))
    }
}

/// A matcher for number values.
///
/// It supports custom operators.
pub struct NumberMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for NumberMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::Number(n) => Ok(Operator::Equal(Value::Number(n.clone()))),
            JsonValue::Array(seq) => Self::make_hashset(seq)
                .map(Operator::InSet)
                .map_err(|err| Error::matcher("Number", fetcher, err)),
            JsonValue::Object(map) => Self::parse_op(fetcher, map),
            _ => {
                let msg = format!("unexpected JSON {}", value.type_name());
                Err(Error::matcher("Number", fetcher, msg))
            }
        }
    }

    fn json_schema(&self, custom_ops: &[&str]) -> Option<JsonValue> {
        NumberMatcher::json_schema(self, custom_ops)
    }
}

impl NumberMatcher {
    fn parse_op<Ctx: ?Sized>(fetcher: &str, map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
        let (op, value) = check_operator!(fetcher, map);
        match (op.as_str(), value) {
            ("<", JsonValue::Number(n)) => Ok(Operator::LessThan(Value::Number(n.clone()))),
            ("<=", JsonValue::Number(n)) => Ok(Operator::LessThanOrEqual(Value::Number(n.clone()))),
            (">", JsonValue::Number(n)) => Ok(Operator::GreaterThan(Value::Number(n.clone()))),
            (">=", JsonValue::Number(n)) => {
                Ok(Operator::GreaterThanOrEqual(Value::Number(n.clone())))
            }
            ("==", JsonValue::Number(n)) => Ok(Operator::Equal(Value::Number(n.clone()))),
            ("<" | "<=" | ">" | ">=" | "==", _) => {
                operator_error!(op, fetcher, "unexpected JSON {}", value.type_name())
            }
            ("in", JsonValue::Array(seq)) => Self::make_hashset(seq)
                .map(Operator::InSet)
                .map_err(|err| Error::operator(op, fetcher, err)),
            ("in", _) => operator_error!(op, fetcher, "unexpected JSON {}", value.type_name()),
            _ => Err(Error::UnknownOperator(op.clone())),
        }
    }

    /// Creates a [`HashSet`] from a list of numbers.
    fn make_hashset(arr: &[JsonValue]) -> StdResult<HashSet<Value<'static>>, String> {
        arr.iter()
            .map(|v| match v {
                JsonValue::Number(n) => Ok(Value::Number(n.clone())),
                _ => Err(format!("unexpected JSON {} in number array", v.type_name())),
            })
            .collect::<StdResult<HashSet<_>, _>>()
    }

    /// Provides a JSON Schema for number matcher inputs.
    fn json_schema(&self, custom_ops: &[&str]) -> Option<JsonValue> {
        // Standard schemas
        let number_schema = serde_json::json!({ "type": "number" });
        let number_array_schema = serde_json::json!({"type": "array", "items": number_schema});

        // Add operator schemas
        let mut properties = serde_json::Map::new();
        properties.insert("<".to_string(), number_schema.clone());
        properties.insert("<=".to_string(), number_schema.clone());
        properties.insert(">".to_string(), number_schema.clone());
        properties.insert(">=".to_string(), number_schema.clone());
        properties.insert("==".to_string(), number_schema.clone());
        properties.insert("in".to_string(), number_array_schema.clone());

        // Add custom operators
        for op in custom_ops {
            properties.insert(op.to_string(), serde_json::json!({}));
        }

        Some(serde_json::json!({
            "oneOf": [
                number_schema,
                number_array_schema,
                // Object with a single operator
                {
                    "type": "object",
                    "properties": properties,
                    "additionalProperties": false,
                    "minProperties": 1,
                    "maxProperties": 1
                }
            ]
        }))
    }
}

/// A matcher for boolean values.
///
/// Does not support custom operators.
pub struct BoolMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for BoolMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::Bool(b) => Ok(Operator::Equal(Value::Bool(*b))),
            _ => {
                let msg = format!("unexpected JSON {}", value.type_name());
                Err(Error::matcher("Bool", fetcher, msg))
            }
        }
    }

    fn json_schema(&self, custom_ops: &[&str]) -> Option<JsonValue> {
        BoolMatcher::json_schema(self, custom_ops)
    }
}

impl BoolMatcher {
    /// Provides a JSON Schema for boolean matcher inputs.
    fn json_schema(&self, _custom_ops: &[&str]) -> Option<JsonValue> {
        // Boolean matcher only accepts boolean values
        Some(serde_json::json!({"type": "boolean"}))
    }
}

/// A matcher for IP subnets.
///
/// It supports custom operators.
pub struct IpMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for IpMatcher {
    fn parse(&self, fetcher: &str, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::String(_) => Self::make_ipnet(&[value.clone()])
                .map(Operator::IpSet)
                .map_err(|err| Error::matcher("Ip", fetcher, err)),
            JsonValue::Array(addrs) => Self::make_ipnet(&addrs)
                .map(Operator::IpSet)
                .map_err(|err| Error::matcher("Ip", fetcher, err)),
            JsonValue::Object(map) => Self::parse_op(fetcher, map),
            _ => {
                let msg = format!("unexpected JSON {}", value.type_name());
                Err(Error::matcher("Ip", fetcher, msg))
            }
        }
    }

    fn json_schema(&self, custom_ops: &[&str]) -> Option<JsonValue> {
        IpMatcher::json_schema(self, custom_ops)
    }
}

impl IpMatcher {
    fn parse_op<Ctx: ?Sized>(fetcher: &str, map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
        let (op, value) = check_operator!(fetcher, map);
        match (op.as_str(), value) {
            ("in", JsonValue::Array(addrs)) => Self::make_ipnet(&addrs)
                .map(Operator::IpSet)
                .map_err(|err| Error::operator(op, fetcher, err)),
            ("in", _) => operator_error!(op, fetcher, "unexpected JSON {}", value.type_name()),
            _ => Err(Error::UnknownOperator(op.clone())),
        }
    }

    /// Creates an [`IpnetTrie`] from a list of IP addresses or CIDR ranges.
    fn make_ipnet(addrs: &[JsonValue]) -> StdResult<IpnetTrie<()>, String> {
        let mut table = IpnetTrie::new();
        for addr in addrs {
            let addr = match addr {
                JsonValue::String(s) => s,
                _ => Err(format!("unexpected JSON {} in array", addr.type_name()))?,
            };
            let net = if addr.contains('/') {
                IpNet::from_str(addr).map_err(|err| err.to_string())?
            } else {
                IpNet::from(IpAddr::from_str(addr).map_err(|err| err.to_string())?)
            };
            table.insert(net, ());
        }
        Ok(table)
    }

    /// Provides a JSON Schema for IP matcher inputs
    fn json_schema(&self, custom_ops: &[&str]) -> Option<JsonValue> {
        // IP address pattern
        let ipv4_pattern =
            r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?";
        let ipv6_pattern = r"(?:[0-9a-f]{1,4}:){1,7}[0-9a-f]{0,4}|::(?:[0-9a-f:]{1,})?|[0-9a-f]{1,4}::(?:[0-9a-f:]{1,})?(?:/\d{1,3})?";
        let ip_pattern = format!(r"^(?:{ipv4_pattern}|(?i:{ipv6_pattern}))");

        // Standard schemas
        let ip_schema = serde_json::json!({"type": "string", "pattern": ip_pattern});
        let ip_array_schema = serde_json::json!({"type": "array", "items": ip_schema});

        // Add operator schemas
        let mut properties = serde_json::Map::new();
        properties.insert("in".to_string(), ip_array_schema.clone());

        // Add custom operators
        for op in custom_ops {
            properties.insert(op.to_string(), serde_json::json!({}));
        }

        Some(serde_json::json!({
            "oneOf": [
                ip_schema,
                ip_array_schema,
                // Object with a single operator
                {
                    "type": "object",
                    "properties": properties,
                    "additionalProperties": false,
                    "minProperties": 1,
                    "maxProperties": 1
                }
            ]
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::any::{Any, TypeId};

    use serde_json::json;

    use super::*;

    /// Helper to test if parsing results in an error
    #[track_caller]
    fn assert_parse_error<M>(matcher: M, fetcher: &str, value: JsonValue, expected_msg: &str)
    where
        M: Matcher<()>,
    {
        let result = matcher.parse(fetcher, &value);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains(expected_msg),
            "Expected error message to contain `{expected_msg}` but got `{err}`",
        );
    }

    // Helper function to parse JSON value and extract operator
    fn parse_op<T: Any>(matcher: impl Matcher<()>, value: JsonValue) -> (T, &'static str) {
        let type_id = TypeId::of::<T>();
        let op = (matcher.parse("test_field", &value)).expect("Failed to parse operator");
        let (boxed, variant): (Box<dyn Any>, &'static str) = match op {
            Operator::Equal(val) if type_id == val.type_id() => (Box::new(val), "Equal"),
            Operator::LessThan(val) if type_id == val.type_id() => (Box::new(val), "LessThan"),
            Operator::LessThanOrEqual(val) if type_id == val.type_id() => {
                (Box::new(val), "LessThanOrEqual")
            }
            Operator::GreaterThan(val) if type_id == val.type_id() => {
                (Box::new(val), "GreaterThan")
            }
            Operator::GreaterThanOrEqual(val) if type_id == val.type_id() => {
                (Box::new(val), "GreaterThanOrEqual")
            }
            Operator::InSet(val) if type_id == val.type_id() => (Box::new(val), "InSet"),
            Operator::Regex(val) if type_id == val.type_id() => (Box::new(val), "Regex"),
            Operator::RegexSet(val) if type_id == val.type_id() => (Box::new(val), "RegexSet"),
            Operator::IpSet(val) if type_id == TypeId::of::<IpnetTrie<()>>() => {
                (Box::new(val), "IpSet")
            }
            op => panic!("Unexpected operator type or value type mismatch: {op:?}"),
        };
        // Downcast to the expected type
        (*boxed.downcast::<T>().unwrap(), variant)
    }

    #[test]
    fn test_string_matcher() {
        #[track_caller]
        fn assert_str_parse_error(value: JsonValue, expected_msg: &str) {
            assert_parse_error(StringMatcher, "test_field", value, expected_msg);
        }

        // Test equality with a string literal
        let (s, variant) = parse_op::<Value>(StringMatcher, json!("hello"));
        assert_eq!(variant, "Equal");
        assert_eq!(s, Value::String(Cow::Borrowed("hello")));

        // Test array of strings (creates InSet operator)
        let (set, variant) = parse_op::<HashSet<Value>>(StringMatcher, json!(["hello", "world"]));
        assert_eq!(variant, "InSet");
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Value::String(Cow::Borrowed("hello"))));
        assert!(set.contains(&Value::String(Cow::Borrowed("world"))));

        // Test comparison operators
        let (s, variant) = parse_op::<Value>(StringMatcher, json!({"<": "hello"}));
        assert_eq!(variant, "LessThan");
        assert_eq!(s, Value::String(Cow::Borrowed("hello")));

        let (s, variant) = parse_op::<Value>(StringMatcher, json!({"<=": "hello"}));
        assert_eq!(variant, "LessThanOrEqual");
        assert_eq!(s, Value::String(Cow::Borrowed("hello")));

        let (s, variant) = parse_op::<Value>(StringMatcher, json!({">": "hello"}));
        assert_eq!(variant, "GreaterThan");
        assert_eq!(s, Value::String(Cow::Borrowed("hello")));

        let (s, variant) = parse_op::<Value>(StringMatcher, json!({">=": "hello"}));
        assert_eq!(variant, "GreaterThanOrEqual");
        assert_eq!(s, Value::String(Cow::Borrowed("hello")));

        let (s, variant) = parse_op::<Value>(StringMatcher, json!({"==": "hello"}));
        assert_eq!(variant, "Equal");
        assert_eq!(s, Value::String(Cow::Borrowed("hello")));

        // Test in operator
        let (set, variant) =
            parse_op::<HashSet<Value>>(StringMatcher, json!({"in": ["hello", "world"]}));
        assert_eq!(variant, "InSet");
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Value::String(Cow::Borrowed("hello"))));
        assert!(set.contains(&Value::String(Cow::Borrowed("world"))));

        // Test regex operator with single pattern
        let (re, variant) = parse_op::<Regex>(StringMatcher, json!({"re": "^hello$"}));
        assert_eq!(variant, "Regex");
        assert!(re.is_match("hello"));

        // Test regex operator with multiple patterns
        let (re, variant) =
            parse_op::<RegexSet>(StringMatcher, json!({"re": ["^hello$", "^world$"]}));
        assert_eq!(variant, "RegexSet");
        assert!(re.is_match("hello"));
        assert!(!re.is_match("hello world"));

        // Test error cases
        assert_str_parse_error(
            json!(true),
            "Error in 'String' matcher for 'test_field': unexpected JSON boolean",
        );
        assert_str_parse_error(
            json!({"in": true}),
            "Error in 'in' operator for 'test_field': unexpected JSON boolean",
        );
        assert_str_parse_error(
            json!({"<": true}),
            "Error in '<' operator for 'test_field': unexpected JSON boolean",
        );
        assert_str_parse_error(
            json!({"re": true}),
            "Error in 're' operator for 'test_field': unexpected JSON boolean",
        );
        assert_str_parse_error(json!({"unknown": "value"}), "Unknown operator 'unknown'");
    }

    #[test]
    fn test_regex_matcher() {
        #[track_caller]
        fn assert_regex_parse_error(value: JsonValue, expected_msg: &str) {
            assert_parse_error(RegexMatcher, "regex_field", value, expected_msg);
        }

        // Test with a single regex pattern
        let (re, variant) = parse_op::<Regex>(RegexMatcher, json!("^hello$"));
        assert_eq!(variant, "Regex");
        assert!(re.is_match("hello"));
        assert!(!re.is_match("hello world"));

        // Test with multiple patterns as array
        let (re_set, variant) = parse_op::<RegexSet>(RegexMatcher, json!(["^hello$", "^world$"]));
        assert_eq!(variant, "RegexSet");
        assert!(re_set.is_match("hello"));
        assert!(re_set.is_match("world"));
        assert!(!re_set.is_match("hello world"));

        // Test with 'in' operator for RegexSet
        let (re_set, variant) =
            parse_op::<RegexSet>(RegexMatcher, json!({"in": ["^hello$", "^world$"]}));
        assert_eq!(variant, "RegexSet");
        assert!(re_set.is_match("hello"));
        assert!(re_set.is_match("world"));
        assert!(!re_set.is_match("hello world"));

        // Test error cases
        assert_regex_parse_error(
            json!(123),
            "Error in 'Regex' matcher for 'regex_field': unexpected JSON number",
        );
        assert_regex_parse_error(
            json!(true),
            "Error in 'Regex' matcher for 'regex_field': unexpected JSON boolean",
        );
        assert_regex_parse_error(
            json!({"in": "not-an-array"}),
            "Error in 'in' operator for 'regex_field': unexpected JSON string",
        );
        assert_regex_parse_error(
            json!({"in": [123, "pattern"]}),
            "Error in 'in' operator for 'regex_field': unexpected JSON number in patterns array",
        );
        assert_regex_parse_error(json!({"invalid": "pattern"}), "Unknown operator 'invalid'");
        assert_regex_parse_error(
            json!("(invalid"),
            "Error in 'Regex' matcher for 'regex_field': regex parse error",
        );
    }

    #[test]
    fn test_number_matcher() {
        #[track_caller]
        fn assert_num_parse_error(value: JsonValue, expected_msg: &str) {
            assert_parse_error(NumberMatcher, "num_field", value, expected_msg);
        }

        // Test equality with a number literal
        let (n, variant) = parse_op::<Value>(NumberMatcher, json!(42));
        assert_eq!(variant, "Equal");
        assert_eq!(n, Value::Number(serde_json::Number::from(42)));

        // Test with a decimal number
        let (n, variant) = parse_op::<Value>(NumberMatcher, json!(3.14));
        assert_eq!(variant, "Equal");
        assert_eq!(
            n,
            Value::Number(serde_json::Number::from_f64(3.14).unwrap())
        );

        // Test array of numbers (creates InSet operator)
        let (set, variant) = parse_op::<HashSet<Value>>(NumberMatcher, json!([1, 3]));
        assert_eq!(variant, "InSet");
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Value::Number(serde_json::Number::from(1))));
        assert!(!set.contains(&Value::Number(serde_json::Number::from(2))));
        assert!(set.contains(&Value::Number(serde_json::Number::from(3))));

        // Test comparison operators
        let (n, variant) = parse_op::<Value>(NumberMatcher, json!({"<": 100}));
        assert_eq!(variant, "LessThan");
        assert_eq!(n, Value::Number(serde_json::Number::from(100)));

        let (n, variant) = parse_op::<Value>(NumberMatcher, json!({"<=": 100}));
        assert_eq!(variant, "LessThanOrEqual");
        assert_eq!(n, Value::Number(serde_json::Number::from(100)));

        let (n, variant) = parse_op::<Value>(NumberMatcher, json!({">": 100}));
        assert_eq!(variant, "GreaterThan");
        assert_eq!(n, Value::Number(serde_json::Number::from(100)));

        let (n, variant) = parse_op::<Value>(NumberMatcher, json!({">=": 100}));
        assert_eq!(variant, "GreaterThanOrEqual");
        assert_eq!(n, Value::Number(serde_json::Number::from(100)));

        let (n, variant) = parse_op::<Value>(NumberMatcher, json!({"==": 100}));
        assert_eq!(variant, "Equal");
        assert_eq!(n, Value::Number(serde_json::Number::from(100)));

        // Test in operator
        let (set, variant) = parse_op::<HashSet<Value>>(NumberMatcher, json!({"in": [1, 3]}));
        assert_eq!(variant, "InSet");
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Value::Number(serde_json::Number::from(1))));
        assert!(!set.contains(&Value::Number(serde_json::Number::from(2))));
        assert!(set.contains(&Value::Number(serde_json::Number::from(3))));

        // Test in operator with decimal numbers
        let (set, variant) = parse_op::<HashSet<Value>>(NumberMatcher, json!({"in": [1.5, 3.5]}));
        assert_eq!(variant, "InSet");
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Value::Number(serde_json::Number::from_f64(1.5).unwrap())));
        assert!(!set.contains(&Value::Number(serde_json::Number::from_f64(2.5).unwrap())));
        assert!(set.contains(&Value::Number(serde_json::Number::from_f64(3.5).unwrap())));

        // Test error cases
        assert_num_parse_error(
            json!("string"),
            "Error in 'Number' matcher for 'num_field': unexpected JSON string",
        );
        assert_num_parse_error(
            json!(true),
            "Error in 'Number' matcher for 'num_field': unexpected JSON boolean",
        );
        assert_num_parse_error(
            json!({"<": "string"}),
            "Error in '<' operator for 'num_field': unexpected JSON string",
        );
        assert_num_parse_error(
            json!({"in": true}),
            "Error in 'in' operator for 'num_field': unexpected JSON boolean",
        );
        assert_num_parse_error(
            json!({"in": [1, "string"]}),
            "Error in 'in' operator for 'num_field': unexpected JSON string in number array",
        );
        assert_num_parse_error(json!({"unknown": 100}), "Unknown operator 'unknown'");
    }

    #[test]
    fn test_bool_matcher() {
        // Test with true value
        let (b, variant) = parse_op::<Value>(BoolMatcher, json!(true));
        assert_eq!(variant, "Equal");
        assert_eq!(b, Value::Bool(true));

        // Test with false value
        let (b, variant) = parse_op::<Value>(BoolMatcher, json!(false));
        assert_eq!(variant, "Equal");
        assert_eq!(b, Value::Bool(false));

        // Test error cases
        assert_parse_error(
            BoolMatcher,
            "bool_field",
            json!("string"),
            "Error in 'Bool' matcher for 'bool_field': unexpected JSON string",
        );
        assert_parse_error(
            BoolMatcher,
            "bool_field",
            json!(123),
            "Error in 'Bool' matcher for 'bool_field': unexpected JSON number",
        );
        assert_parse_error(
            BoolMatcher,
            "bool_field",
            json!([true]),
            "Error in 'Bool' matcher for 'bool_field': unexpected JSON array",
        );
        assert_parse_error(
            BoolMatcher,
            "bool_field",
            json!({"==": true}),
            "Error in 'Bool' matcher for 'bool_field': unexpected JSON object",
        );
    }

    #[test]
    fn test_ip_matcher() {
        // IP Matcher specific test helpers
        fn ip(s: &str) -> IpNet {
            IpNet::from(IpAddr::from_str(s).unwrap())
        }

        #[track_caller]
        fn assert_ip_parse_error(value: JsonValue, expected_msg: &str) {
            assert_parse_error(IpMatcher, "ip_field", value, expected_msg);
        }

        #[track_caller]
        fn assert_ip_matches(trie: &IpnetTrie<()>, addr: &str) {
            let ip = ip(addr);
            assert!(trie.longest_match(&ip).is_some(), "{addr} should match");
        }

        #[track_caller]
        fn assert_ip_not_matches(trie: &IpnetTrie<()>, addr: &str) {
            let ip = ip(addr);
            assert!(trie.longest_match(&ip).is_none(), "{addr} should not match");
        }

        // Test with a single IP address string
        let (trie, variant) = parse_op::<IpnetTrie<()>>(IpMatcher, json!("192.168.1.1"));
        assert_eq!(variant, "IpSet");
        assert_ip_matches(&trie, "192.168.1.1");
        assert_ip_not_matches(&trie, "192.168.1.2");

        // Test with a CIDR notation string
        let (trie, variant) = parse_op::<IpnetTrie<()>>(IpMatcher, json!("192.168.1.0/24"));
        assert_eq!(variant, "IpSet");
        assert_ip_matches(&trie, "192.168.1.1");
        assert_ip_matches(&trie, "192.168.1.254");
        assert_ip_not_matches(&trie, "192.168.2.1");

        // Test with an array of mixed IP addresses and CIDR notations
        let (trie, variant) =
            parse_op::<IpnetTrie<()>>(IpMatcher, json!(["192.168.1.1", "10.0.0.0/8"]));
        assert_eq!(variant, "IpSet");
        assert_ip_matches(&trie, "192.168.1.1");
        assert_ip_matches(&trie, "10.1.2.3");
        assert_ip_not_matches(&trie, "11.0.0.1");

        // Test with IPv6 addresses
        let (trie, variant) =
            parse_op::<IpnetTrie<()>>(IpMatcher, json!(["2001:db8::1", "2001:db8::/32"]));
        assert_eq!(variant, "IpSet");
        assert_ip_matches(&trie, "2001:db8:1::1");

        // Test with 'in' operator
        let (trie, variant) =
            parse_op::<IpnetTrie<()>>(IpMatcher, json!({ "in": ["192.168.1.1", "172.16.0.0/8"] }));
        assert_eq!(variant, "IpSet");
        assert_ip_matches(&trie, "172.16.5.6");
        assert_ip_not_matches(&trie, "10.1.2.3");

        // Test error cases
        assert_ip_parse_error(
            json!("invalid-ip"),
            "Error in 'Ip' matcher for 'ip_field': invalid IP address syntax",
        );
        assert_ip_parse_error(
            json!(123),
            "Error in 'Ip' matcher for 'ip_field': unexpected JSON number",
        );
        assert_ip_parse_error(
            json!({ "in": "not-an-array" }),
            "Error in 'in' operator for 'ip_field': unexpected JSON string",
        );
        assert_ip_parse_error(
            json!({ "in": ["bad addr"] }),
            "Error in 'in' operator for 'ip_field': invalid IP address syntax",
        );
        assert_ip_parse_error(
            json!({ "not_in": ["192.168.1.1"] }),
            "Unknown operator 'not_in'",
        );
    }
}
