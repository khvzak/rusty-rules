use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::result::Result as StdResult;

use serde_json::Number;

/// Represents possible values returned by fetchers
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value<'a> {
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

impl From<serde_json::Value> for Value<'_> {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Value::None,
            serde_json::Value::String(s) => Value::String(Cow::Owned(s)),
            serde_json::Value::Number(n) => Value::Number(n),
            serde_json::Value::Bool(b) => Value::Bool(b),
            serde_json::Value::Array(arr) => {
                let arr = arr.into_iter().map(|v| v.into()).collect();
                Value::Array(arr)
            }
            serde_json::Value::Object(obj) => {
                let map = obj.into_iter().map(|(k, v)| (k, v.into())).collect();
                Value::Map(map)
            }
        }
    }
}

impl<'a> From<&'a serde_json::Value> for Value<'a> {
    fn from(value: &'a serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Value::None,
            serde_json::Value::String(s) => Value::String(Cow::Borrowed(s)),
            serde_json::Value::Number(n) => Value::Number(n.clone()),
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Array(arr) => Value::Array(arr.iter().map(|v| v.into()).collect()),
            serde_json::Value::Object(obj) => {
                let map = obj.iter().map(|(k, v)| (k.clone(), v.into())).collect();
                Value::Map(map)
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
