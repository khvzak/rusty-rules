/// Represents possible errors that can occur during rules parsing.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Covers general JSON parsing issues, such as missing fields or incorrect types.
    #[error("{0}")]
    Json(String),

    /// Triggered when a fetcher specified in the JSON rule is invalid.
    #[error("error in '{name}' fetcher: {error}")]
    Fetcher { name: String, error: String },

    /// Triggered when an error in the matcher occurs when parsing it.
    #[error("error in '{fetcher}' matcher: {error}")]
    Matcher { fetcher: String, error: String },

    /// Triggered when an operator specified in the JSON rule isn’t registered in the engine.
    #[error("unknown operator '{0}'")]
    UnknownOperator(String),

    /// Triggered when an error in the operator occurs when parsing it.
    #[error("error in '{name}' operator: {error}")]
    Operator { name: String, error: String },

    #[error(transparent)]
    Regex(#[from] regex::Error),

    #[error(transparent)]
    IpAddress(#[from] std::net::AddrParseError),

    #[error(transparent)]
    IpSubnet(#[from] ipnet::AddrParseError),
}

impl Error {
    pub(crate) fn json(error: impl ToString) -> Self {
        Error::Json(error.to_string())
    }

    pub(crate) fn fetcher(name: &str, error: impl ToString) -> Self {
        Error::Fetcher {
            name: name.to_string(),
            error: error.to_string(),
        }
    }

    pub(crate) fn matcher(fetcher: &str, error: impl ToString) -> Self {
        Error::Matcher {
            fetcher: fetcher.to_string(),
            error: error.to_string(),
        }
    }

    pub(crate) fn operator(name: &str, error: impl ToString) -> Self {
        Error::Operator {
            name: name.to_string(),
            error: error.to_string(),
        }
    }
}
