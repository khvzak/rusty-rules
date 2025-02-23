use crate::MatcherType;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Triggered when a fetcher specified in the JSON rule isn’t registered in the engine.
    #[error("Unknown fetcher: {0}")]
    UnknownFetcher(String),

    #[error("Invalid fetcher '{name}': {error}")]
    InvalidFetcher { name: String, error: String },

    /// Triggered when an operator specified in the JSON rule isn’t registered in the engine.
    #[error("Unknown operator: {0}")]
    UnknownOperator(String),

    /// Covers general JSON parsing issues, such as missing fields or incorrect types.
    #[error("Invalid JSON: {0}")]
    InvalidJson(String),

    /// Occurs when a matcher is used with an incompatible json value type.
    #[error("Error in {matcher_type:?} matcher for '{fetcher_name}': {error}")]
    Matcher {
        matcher_type: MatcherType,
        fetcher_name: String,
        error: String,
    },

    /// Triggered when an operator specified in the JSON rule is used wrong.
    #[error("Error in '{name}' operator for '{fetcher_name}': {error}")]
    Operator {
        name: String,
        fetcher_name: String,
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

    pub(crate) fn matcher(
        matcher_type: MatcherType,
        fetcher_name: &str,
        error: impl ToString,
    ) -> Self {
        Error::Matcher {
            matcher_type,
            fetcher_name: fetcher_name.to_string(),
            error: error.to_string(),
        }
    }

    pub(crate) fn operator(name: &str, fetcher_name: &str, error: impl ToString) -> Self {
        Error::Operator {
            name: name.to_string(),
            fetcher_name: fetcher_name.to_string(),
            error: error.to_string(),
        }
    }
}
