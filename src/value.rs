use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::hash::Hash;
use std::net::{AddrParseError, IpAddr};
use std::result::Result as StdResult;
use std::str::FromStr;

use serde_json::{Number, Value as JsonValue};

/// Represents possible values returned by fetchers
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value<'a> {
    #[default]
    None,
    String(Cow<'a, str>),
    Number(Number),
    Bool(bool),
    Ip(IpAddr),
    Array(Vec<Value<'a>>),
    Map(BTreeMap<String, Value<'a>>),
}

impl<'a> Value<'a> {
    pub(crate) fn into_static(self) -> Value<'static> {
        match self {
            Value::None => Value::None,
            Value::String(s) => Value::String(Cow::Owned(s.into_owned())),
            Value::Number(n) => Value::Number(n),
            Value::Bool(b) => Value::Bool(b),
            Value::Ip(ip) => Value::Ip(ip),
            Value::Array(arr) => Value::Array(arr.into_iter().map(|v| v.into_static()).collect()),
            Value::Map(map) => {
                Value::Map(map.into_iter().map(|(k, v)| (k, v.into_static())).collect())
            }
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

    /// Converts the value to an IP address, returning an error if it cannot be converted
    pub fn to_ip(&self) -> Result<IpAddr, AddrParseError> {
        match self {
            Value::String(s) => IpAddr::from_str(s),
            Value::Ip(ip) => Ok(*ip),
            _ => IpAddr::from_str(""), // Return an error for non-string or non-IP values
        }
    }

    /// Returns the value as an array if it is an array
    pub fn as_array(&self) -> Option<&Vec<Value<'a>>> {
        match self {
            Value::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// Returns the value as a mutable array if it is an array
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value<'a>>> {
        match self {
            Value::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// Returns the value as a map if it is a map
    pub fn as_map(&self) -> Option<&BTreeMap<String, Value<'a>>> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }

    /// Returns the value as a mutable map if it is a map
    pub fn as_map_mut(&mut self) -> Option<&mut BTreeMap<String, Value<'a>>> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }
}

impl PartialOrd for Value<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Value::None, Value::None) => Some(Ordering::Equal),
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
            (Value::Array(i), Value::Array(j)) => i.partial_cmp(j),
            (Value::Map(i), Value::Map(j)) => i.partial_cmp(j),
            _ => None,
        }
    }
}

impl From<JsonValue> for Value<'_> {
    fn from(value: JsonValue) -> Self {
        match value {
            JsonValue::Null => Value::None,
            JsonValue::String(s) => Value::String(Cow::Owned(s)),
            JsonValue::Number(n) => Value::Number(n),
            JsonValue::Bool(b) => Value::Bool(b),
            JsonValue::Array(arr) => {
                let arr = arr.into_iter().map(|v| v.into()).collect();
                Value::Array(arr)
            }
            JsonValue::Object(obj) => {
                let map = obj.into_iter().map(|(k, v)| (k, v.into())).collect();
                Value::Map(map)
            }
        }
    }
}

impl<'a> From<&'a JsonValue> for Value<'a> {
    fn from(value: &'a JsonValue) -> Self {
        match value {
            JsonValue::Null => Value::None,
            JsonValue::String(s) => Value::String(Cow::Borrowed(s)),
            JsonValue::Number(n) => Value::Number(n.clone()),
            JsonValue::Bool(b) => Value::Bool(*b),
            JsonValue::Array(arr) => Value::Array(arr.iter().map(|v| v.into()).collect()),
            JsonValue::Object(obj) => {
                let map = obj.iter().map(|(k, v)| (k.clone(), v.into())).collect();
                Value::Map(map)
            }
        }
    }
}

impl From<Value<'_>> for JsonValue {
    fn from(value: Value<'_>) -> Self {
        match value {
            Value::None => JsonValue::Null,
            Value::String(s) => JsonValue::String(s.into_owned()),
            Value::Number(n) => JsonValue::Number(n),
            Value::Bool(b) => JsonValue::Bool(b),
            Value::Ip(ip) => JsonValue::String(ip.to_string()),
            Value::Array(arr) => JsonValue::Array(arr.into_iter().map(|v| v.into()).collect()),
            Value::Map(map) => {
                JsonValue::Object(map.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
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

impl<'a> From<Cow<'a, str>> for Value<'a> {
    #[inline(always)]
    fn from(s: Cow<'a, str>) -> Self {
        Value::String(s)
    }
}

macro_rules! impl_from_int {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for Value<'_> {
                #[inline(always)]
                fn from(i: $ty) -> Self {
                    Value::Number(Number::from(i))
                }
            }
        )*
    };
}

impl_from_int!(i8, u8, i16, u16, i32, u32, i64, u64, isize, usize);

impl TryFrom<f64> for Value<'_> {
    type Error = ();

    #[inline(always)]
    fn try_from(f: f64) -> StdResult<Self, Self::Error> {
        Ok(Value::Number(Number::from_f64(f).ok_or(())?))
    }
}

impl From<bool> for Value<'_> {
    #[inline(always)]
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<IpAddr> for Value<'_> {
    #[inline(always)]
    fn from(ip: IpAddr) -> Self {
        Value::Ip(ip)
    }
}

impl<'a, T> From<Option<T>> for Value<'a>
where
    T: Into<Value<'a>>,
{
    #[inline(always)]
    fn from(opt: Option<T>) -> Self {
        match opt {
            Some(v) => v.into(),
            None => Value::None,
        }
    }
}

impl<'a, T: Into<Value<'a>>> From<Vec<T>> for Value<'a> {
    #[inline(always)]
    fn from(arr: Vec<T>) -> Self {
        Value::Array(arr.into_iter().map(|v| v.into()).collect())
    }
}

impl<'a, T: Into<Value<'a>>> From<BTreeMap<String, T>> for Value<'a> {
    #[inline(always)]
    fn from(map: BTreeMap<String, T>) -> Self {
        Value::Map(map.into_iter().map(|(k, v)| (k, v.into())).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value() {
        // None value
        assert_eq!(Value::None, Value::None);

        // String value
        let val = Value::from("true").into_static();
        assert_eq!(val.as_str(), Some("true"));
        assert_eq!(val.as_i64(), None);
        assert_eq!(val.as_f64(), None);
        assert_eq!(val.as_bool(), None);
        assert!(val.to_ip().is_err());
        assert!(Value::from("127.0.0.1").to_ip().is_ok());
        assert!(Value::from("0") < Value::from("1"));

        // Number value
        let val = Value::from(42).into_static();
        assert_eq!(val.as_str(), None);
        assert_eq!(val.as_i64(), Some(42));
        assert_eq!(val.as_f64(), Some(42.0));
        assert_eq!(val.as_bool(), None);
        assert!(val.to_ip().is_err());
        assert!(Value::from(42) < Value::from(43));
        assert!(Value::try_from(0.001).unwrap() > Value::from(0));

        // Bool value
        let val = Value::from(true).into_static();
        assert_eq!(val.as_str(), None);
        assert_eq!(val.as_i64(), None);
        assert_eq!(val.as_f64(), None);
        assert_eq!(val.as_bool(), Some(true));
        assert!(val.to_ip().is_err());
        assert!(Value::from(false) < Value::from(true));

        // IP value
        let val = Value::from(IpAddr::from_str("127.0.0.1").unwrap()).into_static();
        assert_eq!(val.as_str(), None);
        assert_eq!(val.as_i64(), None);
        assert_eq!(val.as_f64(), None);
        assert_eq!(val.as_bool(), None);
        assert_eq!(val.to_ip().unwrap(), "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(
            Value::from("127.0.0.1".parse::<IpAddr>().unwrap())
                < Value::from("127.0.0.2".parse::<IpAddr>().unwrap())
        );

        // Array value
        let mut val = Value::from(vec!["a", "b", "c"]).into_static();
        assert_eq!(val.as_array().unwrap().len(), 3);
        assert_eq!(val.as_map(), None);
        if let Some(arr) = val.as_array_mut() {
            arr.push(Value::from("d"));
        }
        assert_eq!(val.as_array().unwrap().len(), 4);
        assert!(Value::from(vec![1, 2, 3]) < Value::from(vec![1, 2, 4]));

        // Map value
        let mut val = Value::from(BTreeMap::from_iter(vec![
            ("key1".to_string(), Value::from("value1")),
            ("key2".to_string(), Value::from(42)),
        ]))
        .into_static();
        assert_eq!(val.as_map().unwrap().len(), 2);
        assert_eq!(val.as_array(), None);
        if let Some(m) = val.as_map_mut() {
            m.insert("key3".to_string(), Value::from(true));
        }
        assert_eq!(val.as_map().unwrap().len(), 3);
        assert!(
            Value::from(BTreeMap::from_iter(vec![("a".to_string(), Value::from(1))]))
                < Value::from(BTreeMap::from_iter(vec![("a".to_string(), Value::from(2))]))
        );

        // From/To serde_json::Value
        let json_val: JsonValue = serde_json::json!({
            "string": "value",
            "number": 42,
            "bool": true,
            "array": [1, 2, 3],
            "map": { "key": "value" },
            "null": null
        });
        assert_eq!(Value::from(&json_val), Value::from(json_val.clone()));
        let back_to_json: JsonValue = Value::from(json_val.clone()).into();
        assert_eq!(back_to_json, json_val);
    }
}
