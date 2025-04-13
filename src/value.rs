use std::borrow::Cow;
use std::cmp::Ordering;
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
}

impl Value<'_> {
    pub(crate) fn into_static(self) -> Value<'static> {
        match self {
            Value::None => Value::None,
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
            _ => None,
        }
    }
}

impl TryFrom<serde_json::Value> for Value<'_> {
    type Error = ();

    fn try_from(value: serde_json::Value) -> StdResult<Self, Self::Error> {
        match value {
            serde_json::Value::Null => Ok(Value::None),
            serde_json::Value::String(s) => Ok(Value::String(Cow::Owned(s))),
            serde_json::Value::Number(n) => Ok(Value::Number(n)),
            serde_json::Value::Bool(b) => Ok(Value::Bool(b)),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a serde_json::Value> for Value<'a> {
    type Error = ();

    fn try_from(value: &'a serde_json::Value) -> StdResult<Self, Self::Error> {
        match value {
            serde_json::Value::Null => Ok(Value::None),
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
