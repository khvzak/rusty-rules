/// Represents possible errors that can occur during rules parsing.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Triggered when a fetcher specified in the JSON rule isn’t registered in the engine.
    #[error("Unknown fetcher: {0}")]
    UnknownFetcher(String),

    /// Triggered when a fetcher specified in the JSON rule is invalid.
    #[error("Invalid fetcher '{name}': {error}")]
    InvalidFetcher { name: String, error: String },

    /// Triggered when an operator specified in the JSON rule isn’t registered in the engine.
    #[error("Unknown operator: {0}")]
    UnknownOperator(String),

    /// Covers general JSON parsing issues, such as missing fields or incorrect types.
    #[error("Invalid JSON: {0}")]
    InvalidJson(String),

    /// Occurs when a matcher is used with an incompatible json value type.
    #[error("Error in {name} matcher for '{fetcher}': {error}")]
    Matcher {
        name: String,
        fetcher: String,
        error: String,
    },

    /// Triggered when an operator is used with an incompatible json value type.
    #[error("Error in '{name}' operator for '{fetcher}': {error}")]
    Operator {
        name: String,
        fetcher: String,
        error: String,
    },
}

impl Error {
    pub(crate) fn invalid_fetcher(name: &str, error: &str) -> Self {
        Error::InvalidFetcher {
            name: name.to_string(),
            error: error.to_string(),
        }
    }

    pub(crate) fn matcher(name: &str, fetcher: &str, error: impl ToString) -> Self {
        Error::Matcher {
            name: name.to_string(),
            fetcher: fetcher.to_string(),
            error: error.to_string(),
        }
    }

    pub(crate) fn operator(name: &str, fetcher: &str, error: impl ToString) -> Self {
        Error::Operator {
            name: name.to_string(),
            fetcher: fetcher.to_string(),
            error: error.to_string(),
        }
    }
}
