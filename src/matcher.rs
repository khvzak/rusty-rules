use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::result::Result as StdResult;
use std::str::FromStr;

use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use regex::{Regex, RegexSet};
use serde_json::{json, Map, Value as JsonValue};

use crate::types::{AsyncCheckFn, BoxFuture, CheckFn, DynError, MaybeSend, MaybeSync};
use crate::{Error, JsonValueExt as _, Result, Value};

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

impl<Ctx: ?Sized> Operator<Ctx> {
    /// Creates a new operator that checks if the fetched value is equal to the given value.
    pub fn new<F>(func: F) -> Self
    where
        F: Fn(&Ctx, Value) -> StdResult<bool, DynError> + MaybeSend + MaybeSync + 'static,
    {
        Operator::Custom(Box::new(func))
    }

    /// Creates a new async operator that checks if the fetched value is equal to the given value.
    pub fn new_async<F>(func: F) -> Self
    where
        F: for<'a> Fn(&'a Ctx, Value<'a>) -> BoxFuture<'a, StdResult<bool, DynError>>
            + MaybeSend
            + MaybeSync
            + 'static,
    {
        Operator::CustomAsync(Box::new(func))
    }
}

/// Trait for types matchers
pub trait Matcher<Ctx: ?Sized>: MaybeSend + MaybeSync {
    /// Parses the JSON configuration and returns an [`Operator`].
    fn parse(&self, value: &JsonValue) -> Result<Operator<Ctx>>;

    /// Returns a JSON Schema that describes valid inputs for this matcher.
    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        let _ = custom_ops;
        json!({})
    }
}

macro_rules! operator_error {
    ($op:expr, $($arg:tt)*) => {
        Err(Error::operator($op, format!($($arg)*)))
    };
}

macro_rules! check_operator {
    ($map:expr) => {{
        let len = $map.len();
        if len != 1 {
            let msg = format!("operator object must have exactly one key (got {len})");
            return Err(Error::json(msg));
        }
        $map.iter().next().unwrap()
    }};
}

const IPV4_PATTERN: &str =
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?";
const IPV6_PATTERN: &str = r"(?:[0-9a-f]{1,4}:){1,7}[0-9a-f]{0,4}|::(?:[0-9a-f:]{1,})?|[0-9a-f]{1,4}::(?:[0-9a-f:]{1,})?(?:/\d{1,3})?";

/// A flexible matcher without strict types.
pub struct DefaultMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for DefaultMatcher {
    fn parse(&self, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {
                Ok(Operator::Equal(Value::from(value).into_static()))
            }
            JsonValue::Array(seq) => Ok(Operator::InSet(Self::make_hashset(seq))),
            JsonValue::Object(map) => Self::parse_op(map),
        }
    }

    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        DefaultMatcher::json_schema(self, custom_ops)
    }
}

impl DefaultMatcher {
    fn parse_op<Ctx: ?Sized>(map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
        let (op, value) = check_operator!(map);
        match (op.as_str(), value) {
            ("<", v) => Ok(Operator::LessThan(Value::from(v).into_static())),
            ("<=", v) => Ok(Operator::LessThanOrEqual(Value::from(v).into_static())),
            (">", v) => Ok(Operator::GreaterThan(Value::from(v).into_static())),
            (">=", v) => Ok(Operator::GreaterThanOrEqual(Value::from(v).into_static())),
            ("==", v) => Ok(Operator::Equal(Value::from(v).into_static())),
            ("in", JsonValue::Array(arr)) => Ok(Operator::InSet(Self::make_hashset(arr))),
            ("in", _) => operator_error!(op, "expected array, got {}", value.type_name()),
            ("re", JsonValue::String(pattern)) => {
                let regex = Regex::new(pattern).map_err(|err| Error::operator(op, err))?;
                Ok(Operator::Regex(regex))
            }
            ("re", JsonValue::Array(patterns)) => RegexMatcher::make_regex_set(patterns)
                .map(Operator::RegexSet)
                .map_err(|err| Error::operator(op, err)),
            ("re", _) => operator_error!(op, "expected string or array, got {}", value.type_name()),
            ("ip", JsonValue::Array(arr)) => IpMatcher::make_ipnet(arr)
                .map(Operator::IpSet)
                .map_err(|err| Error::operator(op, err)),
            ("ip", _) => operator_error!(op, "expected array, got {}", value.type_name()),
            _ => Err(Error::UnknownOperator(op.clone())),
        }
    }

    /// Creates a [`HashSet`] from a list of values.
    fn make_hashset(arr: &[JsonValue]) -> HashSet<Value<'static>> {
        arr.iter().map(|v| Value::from(v).into_static()).collect()
    }

    /// Provides a JSON Schema for default matcher inputs.
    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        // Standard schemas
        let any_schema = json!({ "type": ["null", "boolean", "number", "string"] });
        let any_array_schema = json!({ "type": "array", "items": any_schema });
        let string_schema = json!({ "type": "string" });
        let string_array_schema = json!({ "type": "array", "items": string_schema });
        let ip_schema = json!({ "type": "string", "pattern": format!(r"^(?:{IPV4_PATTERN}|(?i:{IPV6_PATTERN}))") });
        let ip_array_schema = json!({ "type": "array", "items": ip_schema });

        // Add operator schemas
        let mut properties = Map::new();
        properties.insert("<".to_string(), any_schema.clone());
        properties.insert("<=".to_string(), any_schema.clone());
        properties.insert(">".to_string(), any_schema.clone());
        properties.insert(">=".to_string(), any_schema.clone());
        properties.insert("==".to_string(), any_schema.clone());
        properties.insert("in".to_string(), any_array_schema.clone());
        properties.insert(
            "re".to_string(),
            json!({ "oneOf": [string_schema, string_array_schema] }),
        );
        properties.insert("ip".to_string(), ip_array_schema);

        // Add custom operators
        for (op, schema) in custom_ops {
            properties.insert(op.to_string(), schema.clone());
        }

        json!({
            "oneOf": [
                any_schema,
                any_array_schema,
                // Object with a single operator
                {
                    "type": "object",
                    "properties": properties,
                    "additionalProperties": false,
                    "minProperties": 1,
                    "maxProperties": 1
                }
            ]
        })
    }
}

/// A matcher for string values.
///
/// It supports custom operators.
pub struct StringMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for StringMatcher {
    fn parse(&self, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::String(s) => Ok(Operator::Equal(Value::String(Cow::Owned(s.clone())))),
            JsonValue::Array(seq) => Ok(Operator::InSet(Self::make_hashset(seq)?)),
            JsonValue::Object(map) => Self::parse_op(map),
            _ => {
                let msg = format!("unexpected JSON {}", value.type_name());
                Err(Error::json(msg))
            }
        }
    }

    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        StringMatcher::json_schema(self, custom_ops)
    }
}

impl StringMatcher {
    fn parse_op<Ctx: ?Sized>(map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
        let (op, value) = check_operator!(map);
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
                operator_error!(op, "expected string, got {}", value.type_name())
            }
            ("in", JsonValue::Array(arr)) => Self::make_hashset(arr)
                .map(Operator::InSet)
                .map_err(|err| Error::operator(op, err)),
            ("in", _) => operator_error!(op, "expected array, got {}", value.type_name()),
            ("re", JsonValue::String(pattern)) => {
                let regex = Regex::new(pattern).map_err(|err| Error::operator(op, err))?;
                Ok(Operator::Regex(regex))
            }
            ("re", JsonValue::Array(patterns)) => RegexMatcher::make_regex_set(patterns)
                .map(Operator::RegexSet)
                .map_err(|err| Error::operator(op, err)),
            ("re", _) => operator_error!(op, "expected string or array, got {}", value.type_name()),
            _ => Err(Error::UnknownOperator(op.clone())),
        }
    }

    /// Creates a [`HashSet`] from a list of strings.
    fn make_hashset(arr: &[JsonValue]) -> Result<HashSet<Value<'static>>> {
        arr.iter()
            .map(|v| match v {
                JsonValue::String(s) => Ok(Value::String(Cow::Owned(s.clone()))),
                _ => {
                    let msg = format!("got {} in string array", v.type_name());
                    Err(Error::json(msg))
                }
            })
            .collect()
    }

    /// Provides a JSON Schema for string matcher inputs.
    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        // Standard schemas
        let string_schema = json!({ "type": "string" });
        let string_array_schema = json!({ "type": "array", "items": string_schema });

        // Add operator schemas
        let mut properties = Map::new();
        properties.insert("<".to_string(), string_schema.clone());
        properties.insert("<=".to_string(), string_schema.clone());
        properties.insert(">".to_string(), string_schema.clone());
        properties.insert(">=".to_string(), string_schema.clone());
        properties.insert("==".to_string(), string_schema.clone());
        properties.insert("in".to_string(), string_array_schema.clone());
        properties.insert(
            "re".to_string(),
            json!({ "oneOf": [string_schema, string_array_schema] }),
        );

        // Add custom operators
        for (op, schema) in custom_ops {
            properties.insert(op.to_string(), schema.clone());
        }

        json!({
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
        })
    }
}

/// A matcher for string values with regular expressions by default.
///
/// It supports custom operators.
pub struct RegexMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for RegexMatcher {
    fn parse(&self, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::String(pattern) => Ok(Operator::Regex(Regex::new(pattern)?)),
            JsonValue::Array(patterns) => Ok(Operator::RegexSet(Self::make_regex_set(patterns)?)),
            JsonValue::Object(map) => Self::parse_op(map),
            _ => {
                let msg = format!("unexpected JSON {}", value.type_name());
                Err(Error::json(msg))
            }
        }
    }

    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        RegexMatcher::json_schema(self, custom_ops)
    }
}

impl RegexMatcher {
    fn parse_op<Ctx: ?Sized>(map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
        let (op, _value) = check_operator!(map);
        Err(Error::UnknownOperator(op.clone()))
    }

    /// Creates a [`RegexSet`] from a list of patterns.
    fn make_regex_set(patterns: &[JsonValue]) -> Result<RegexSet> {
        let patterns = (patterns.iter())
            .map(|v| match v {
                JsonValue::String(s) => Ok(s),
                _ => {
                    let msg = format!("expected string, got {} in regex array", v.type_name());
                    Err(Error::json(msg))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RegexSet::new(&patterns)?)
    }

    /// Provides a JSON Schema for regex matcher inputs.
    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        // Standard schemas
        let string_schema = json!({ "type": "string" });
        let string_array_schema = json!({ "type": "array", "items": string_schema });

        // Add operator schemas
        let mut properties = Map::new();

        // Add custom operators
        for (op, schema) in custom_ops {
            properties.insert(op.to_string(), schema.clone());
        }

        json!({
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
        })
    }
}

/// A matcher for number values.
///
/// It supports custom operators.
pub struct NumberMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for NumberMatcher {
    fn parse(&self, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::Number(n) => Ok(Operator::Equal(Value::Number(n.clone()))),
            JsonValue::Array(seq) => Ok(Operator::InSet(Self::make_hashset(seq)?)),
            JsonValue::Object(map) => Self::parse_op(map),
            _ => {
                let msg = format!("unexpected JSON {}", value.type_name());
                Err(Error::json(msg))
            }
        }
    }

    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        NumberMatcher::json_schema(self, custom_ops)
    }
}

impl NumberMatcher {
    fn parse_op<Ctx: ?Sized>(map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
        let (op, value) = check_operator!(map);
        match (op.as_str(), value) {
            ("<", JsonValue::Number(n)) => Ok(Operator::LessThan(Value::Number(n.clone()))),
            ("<=", JsonValue::Number(n)) => Ok(Operator::LessThanOrEqual(Value::Number(n.clone()))),
            (">", JsonValue::Number(n)) => Ok(Operator::GreaterThan(Value::Number(n.clone()))),
            (">=", JsonValue::Number(n)) => {
                Ok(Operator::GreaterThanOrEqual(Value::Number(n.clone())))
            }
            ("==", JsonValue::Number(n)) => Ok(Operator::Equal(Value::Number(n.clone()))),
            ("<" | "<=" | ">" | ">=" | "==", _) => {
                operator_error!(op, "expected number, got {}", value.type_name())
            }
            ("in", JsonValue::Array(seq)) => Self::make_hashset(seq)
                .map(Operator::InSet)
                .map_err(|err| Error::operator(op, err)),
            ("in", _) => operator_error!(op, "expected array, got {}", value.type_name()),
            _ => Err(Error::UnknownOperator(op.clone())),
        }
    }

    /// Creates a [`HashSet`] from a list of numbers.
    fn make_hashset(arr: &[JsonValue]) -> Result<HashSet<Value<'static>>> {
        arr.iter()
            .map(|v| match v {
                JsonValue::Number(n) => Ok(Value::Number(n.clone())),
                _ => {
                    let msg = format!("got {} in number array", v.type_name());
                    Err(Error::json(msg))
                }
            })
            .collect()
    }

    /// Provides a JSON Schema for number matcher inputs.
    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        // Standard schemas
        let number_schema = json!({ "type": "number" });
        let number_array_schema = json!({ "type": "array", "items": number_schema });

        // Add operator schemas
        let mut properties = Map::new();
        properties.insert("<".to_string(), number_schema.clone());
        properties.insert("<=".to_string(), number_schema.clone());
        properties.insert(">".to_string(), number_schema.clone());
        properties.insert(">=".to_string(), number_schema.clone());
        properties.insert("==".to_string(), number_schema.clone());
        properties.insert("in".to_string(), number_array_schema.clone());

        // Add custom operators
        for (op, schema) in custom_ops {
            properties.insert(op.to_string(), schema.clone());
        }

        json!({
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
        })
    }
}

/// A matcher for boolean values.
///
/// Does not support custom operators.
pub struct BoolMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for BoolMatcher {
    fn parse(&self, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::Bool(b) => Ok(Operator::Equal(Value::Bool(*b))),
            _ => {
                let msg = format!("expected boolean, got {}", value.type_name());
                Err(Error::json(msg))
            }
        }
    }

    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        BoolMatcher::json_schema(self, custom_ops)
    }
}

impl BoolMatcher {
    /// Provides a JSON Schema for boolean matcher inputs.
    fn json_schema(&self, _custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        // Boolean matcher only accepts boolean values
        json!({ "type": "boolean" })
    }
}

/// A matcher for IP subnets.
///
/// It supports custom operators.
pub struct IpMatcher;

impl<Ctx: ?Sized> Matcher<Ctx> for IpMatcher {
    fn parse(&self, value: &JsonValue) -> Result<Operator<Ctx>> {
        match value {
            JsonValue::String(_) => Ok(Operator::IpSet(Self::make_ipnet(&[value.clone()])?)),
            JsonValue::Array(addrs) => Ok(Operator::IpSet(Self::make_ipnet(addrs)?)),
            JsonValue::Object(map) => Self::parse_op(map),
            _ => {
                let msg = format!("unexpected JSON {}", value.type_name());
                Err(Error::json(msg))
            }
        }
    }

    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        IpMatcher::json_schema(self, custom_ops)
    }
}

impl IpMatcher {
    fn parse_op<Ctx: ?Sized>(map: &Map<String, JsonValue>) -> Result<Operator<Ctx>> {
        let (op, _value) = check_operator!(map);
        Err(Error::UnknownOperator(op.clone()))
    }

    /// Creates an [`IpnetTrie`] from a list of IP addresses or CIDR ranges.
    fn make_ipnet(addrs: &[JsonValue]) -> Result<IpnetTrie<()>> {
        let mut table = IpnetTrie::new();
        for addr in addrs {
            let addr = match addr {
                JsonValue::String(s) => s,
                _ => {
                    let msg = format!("got {} in ipnet array", addr.type_name());
                    return Err(Error::json(msg));
                }
            };
            let net = if addr.contains('/') {
                IpNet::from_str(addr)?
            } else {
                IpNet::from(IpAddr::from_str(addr)?)
            };
            table.insert(net, ());
        }
        Ok(table)
    }

    /// Provides a JSON Schema for IP matcher inputs
    fn json_schema(&self, custom_ops: &[(&str, JsonValue)]) -> JsonValue {
        // IP address pattern
        let ip_pattern = format!(r"^(?:{IPV4_PATTERN}|(?i:{IPV6_PATTERN}))");

        // Standard schemas
        let ip_schema = json!({ "type": "string", "pattern": ip_pattern });
        let ip_array_schema = json!({ "type": "array", "items": ip_schema });

        // Add operator schemas
        let mut properties = Map::new();

        // Add custom operators
        for (op, schema) in custom_ops {
            properties.insert(op.to_string(), schema.clone());
        }

        json!({
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
        })
    }
}

#[cfg(test)]
mod tests {
    use std::any::{Any, TypeId};

    use serde_json::json;

    use super::*;

    /// Helper to test if parsing results in an error
    #[track_caller]
    fn assert_parse_error<M>(matcher: M, value: JsonValue, expected_msg: &str)
    where
        M: Matcher<()>,
    {
        let result = matcher.parse(&value);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains(expected_msg),
            "Expected error message to contain `{expected_msg}` but got `{err}`",
        );
    }

    // Helper function to parse JSON value and extract operator
    #[track_caller]
    fn parse_op<T: Any>(matcher: impl Matcher<()>, value: JsonValue) -> (T, &'static str) {
        let type_id = TypeId::of::<T>();
        let op = (matcher.parse(&value)).expect("Failed to parse operator");
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
    fn test_default_matcher() {
        #[track_caller]
        fn assert_default_parse_error(value: JsonValue, expected_msg: &str) {
            assert_parse_error(DefaultMatcher, value, expected_msg);
        }

        // Test with primitive types (all should create Equal operators)

        // Test with null value
        let (v, variant) = parse_op::<Value>(DefaultMatcher, json!(null));
        assert_eq!(variant, "Equal");
        assert_eq!(v, Value::None);

        // Test with boolean value
        let (v, variant) = parse_op::<Value>(DefaultMatcher, json!(true));
        assert_eq!(variant, "Equal");
        assert_eq!(v, Value::Bool(true));

        // Test with number value
        let (v, variant) = parse_op::<Value>(DefaultMatcher, json!(42));
        assert_eq!(variant, "Equal");
        assert_eq!(v, Value::Number(serde_json::Number::from(42)));

        // Test with string value
        let (v, variant) = parse_op::<Value>(DefaultMatcher, json!("hello"));
        assert_eq!(variant, "Equal");
        assert_eq!(v, Value::String(Cow::Borrowed("hello")));

        // Test with array of mixed values (creates InSet operator)
        let (set, variant) = parse_op::<HashSet<Value>>(DefaultMatcher, json!([1, "hello", true]));
        assert_eq!(variant, "InSet");
        assert_eq!(set.len(), 3);
        assert!(set.contains(&Value::Number(serde_json::Number::from(1))));
        assert!(set.contains(&Value::String(Cow::Borrowed("hello"))));
        assert!(set.contains(&Value::Bool(true)));

        // Test comparison operators with different value types

        // Less than with number
        let (v, variant) = parse_op::<Value>(DefaultMatcher, json!({"<": 100}));
        assert_eq!(variant, "LessThan");
        assert_eq!(v, Value::Number(serde_json::Number::from(100)));

        // Less than or equal with string
        let (v, variant) = parse_op::<Value>(DefaultMatcher, json!({"<=": "hello"}));
        assert_eq!(variant, "LessThanOrEqual");
        assert_eq!(v, Value::String(Cow::Borrowed("hello")));

        // Greater than with number
        let (v, variant) = parse_op::<Value>(DefaultMatcher, json!({">": 100}));
        assert_eq!(variant, "GreaterThan");
        assert_eq!(v, Value::Number(serde_json::Number::from(100)));

        // Greater than or equal with boolean
        let (v, variant) = parse_op::<Value>(DefaultMatcher, json!({">=": true}));
        assert_eq!(variant, "GreaterThanOrEqual");
        assert_eq!(v, Value::Bool(true));

        // Equal with null
        let (v, variant) = parse_op::<Value>(DefaultMatcher, json!({"==": null}));
        assert_eq!(variant, "Equal");
        assert_eq!(v, Value::None);

        // Test "in" operator with mixed array
        let (set, variant) =
            parse_op::<HashSet<Value>>(DefaultMatcher, json!({"in": [1, "hello", true, null]}));
        assert_eq!(variant, "InSet");
        assert_eq!(set.len(), 4);
        assert!(set.contains(&Value::Number(serde_json::Number::from(1))));
        assert!(set.contains(&Value::String(Cow::Borrowed("hello"))));
        assert!(set.contains(&Value::Bool(true)));
        assert!(set.contains(&Value::None));

        // Test regex operator
        let (re, variant) = parse_op::<Regex>(DefaultMatcher, json!({"re": "^hello$"}));
        assert_eq!(variant, "Regex");
        assert!(re.is_match("hello"));
        assert!(!re.is_match("hello world"));

        // Test regex set
        let (re_set, variant) =
            parse_op::<RegexSet>(DefaultMatcher, json!({"re": ["^hello$", "^world$"]}));
        assert_eq!(variant, "RegexSet");
        assert!(re_set.is_match("hello"));
        assert!(re_set.is_match("world"));
        assert!(!re_set.is_match("hello world"));

        // Test IP set
        let (_, variant) =
            parse_op::<IpnetTrie<()>>(DefaultMatcher, json!({"ip": ["192.168.1.1", "10.0.0.0/8"]}));
        assert_eq!(variant, "IpSet");

        // Error cases
        assert_default_parse_error(
            json!({"in": true}),
            "Error in 'in' operator: expected array, got boolean",
        );
        assert_default_parse_error(
            json!({"re": true}),
            "Error in 're' operator: expected string or array, got boolean",
        );
        assert_default_parse_error(
            json!({"ip": true}),
            "Error in 'ip' operator: expected array, got boolean",
        );
        assert_default_parse_error(json!({"unknown": "value"}), "Unknown operator 'unknown'");
    }

    #[test]
    fn test_string_matcher() {
        #[track_caller]
        fn assert_str_parse_error(value: JsonValue, expected_msg: &str) {
            assert_parse_error(StringMatcher, value, expected_msg);
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
        assert_str_parse_error(json!(true), "unexpected JSON boolean");
        assert_str_parse_error(json!({"in": true}), "expected array, got boolean");
        assert_str_parse_error(
            json!({"<": true}),
            "Error in '<' operator: expected string, got boolean",
        );
        assert_str_parse_error(
            json!({"re": true}),
            "Error in 're' operator: expected string or array, got boolean",
        );
        assert_str_parse_error(json!({"unknown": "value"}), "Unknown operator 'unknown'");
    }

    #[test]
    fn test_regex_matcher() {
        #[track_caller]
        fn assert_regex_parse_error(value: JsonValue, expected_msg: &str) {
            assert_parse_error(RegexMatcher, value, expected_msg);
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

        // Test error cases
        assert_regex_parse_error(json!(123), "unexpected JSON number");
        assert_regex_parse_error(json!(true), "unexpected JSON boolean");
        assert_regex_parse_error(json!({"invalid": "pattern"}), "Unknown operator 'invalid'");
        assert_regex_parse_error(json!("(invalid"), "regex parse error");
    }

    #[test]
    fn test_number_matcher() {
        #[track_caller]
        fn assert_num_parse_error(value: JsonValue, expected_msg: &str) {
            assert_parse_error(NumberMatcher, value, expected_msg);
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
        assert_num_parse_error(json!("string"), "unexpected JSON string");
        assert_num_parse_error(json!(true), "unexpected JSON boolean");
        assert_num_parse_error(
            json!({"<": "string"}),
            "Error in '<' operator: expected number, got string",
        );
        assert_num_parse_error(
            json!({"in": true}),
            "Error in 'in' operator: expected array, got boolean",
        );
        assert_num_parse_error(
            json!({"in": [1, "string"]}),
            "Error in 'in' operator: got string in number array",
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
        assert_parse_error(BoolMatcher, json!("string"), "expected boolean, got string");
        assert_parse_error(BoolMatcher, json!(123), "expected boolean, got number");
        assert_parse_error(BoolMatcher, json!([true]), "expected boolean, got array");
        assert_parse_error(
            BoolMatcher,
            json!({"==": true}),
            "expected boolean, got object",
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
            assert_parse_error(IpMatcher, value, expected_msg);
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

        // Test error cases
        assert_ip_parse_error(json!("invalid-ip"), "invalid IP address syntax");
        assert_ip_parse_error(json!(123), "unexpected JSON number");
        assert_ip_parse_error(json!({"invalid": "pattern"}), "Unknown operator 'invalid'");
    }
}
