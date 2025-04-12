use std::sync::Arc;

pub use inner::*;

use crate::Value;

#[cfg(not(feature = "send"))]
mod inner {
    use std::error::Error as StdError;
    use std::future::Future;
    use std::pin::Pin;
    use std::result::Result as StdResult;
    use std::sync::Arc;

    use serde_json::Value as JsonValue;

    pub trait MaybeSend {}
    impl<T: ?Sized> MaybeSend for T {}

    pub trait MaybeSync {}
    impl<T: ?Sized> MaybeSync for T {}

    pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

    pub(crate) type DynError = Box<dyn StdError>;

    /// Callback type for operators
    pub(crate) type OperatorBuilder<Ctx> =
        Arc<dyn Fn(&JsonValue) -> StdResult<crate::Operator<Ctx>, DynError>>;

    /// Callback type for operator check function
    pub type CheckFn<Ctx> = dyn Fn(&Ctx, crate::Value) -> StdResult<bool, DynError>;

    /// Callback type for async operator check function
    pub type AsyncCheckFn<Ctx> =
        dyn for<'a> Fn(&'a Ctx, crate::Value<'a>) -> BoxFuture<'a, StdResult<bool, DynError>>;

    pub(crate) type EvalFn<Ctx> = Arc<dyn Fn(&Ctx) -> StdResult<bool, DynError>>;

    pub(crate) type AsyncEvalFn<Ctx> =
        Arc<dyn for<'a> Fn(&'a Ctx) -> BoxFuture<'a, StdResult<bool, DynError>>>;
}

#[cfg(feature = "send")]
mod inner {
    use std::error::Error as StdError;
    use std::future::Future;
    use std::pin::Pin;
    use std::result::Result as StdResult;
    use std::sync::Arc;

    use serde_json::Value as JsonValue;

    pub trait MaybeSend: Send {}
    impl<T: Send + ?Sized> MaybeSend for T {}

    pub trait MaybeSync: Sync {}
    impl<T: Sync + ?Sized> MaybeSync for T {}

    pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

    pub(crate) type DynError = Box<dyn StdError + Send + Sync>;

    pub(crate) type OperatorBuilder<Ctx> =
        Arc<dyn Fn(&JsonValue) -> StdResult<crate::Operator<Ctx>, DynError> + Send + Sync>;

    /// Callback type for operator check function
    pub type CheckFn<Ctx> = dyn Fn(&Ctx, crate::Value) -> StdResult<bool, DynError> + Send + Sync;

    /// Callback type for async operator check function
    pub type AsyncCheckFn<Ctx> = dyn for<'a> Fn(&'a Ctx, crate::Value<'a>) -> BoxFuture<'a, StdResult<bool, DynError>>
        + Send
        + Sync;

    pub(crate) type EvalFn<Ctx> = Arc<dyn Fn(&Ctx) -> StdResult<bool, DynError> + Send + Sync>;

    pub(crate) type AsyncEvalFn<Ctx> =
        Arc<dyn for<'a> Fn(&'a Ctx) -> BoxFuture<'a, StdResult<bool, DynError>> + Send + Sync>;
}

/// Callback type for fetchers
pub type FetcherFn<Ctx> = for<'a> fn(&'a Ctx, &[String]) -> Option<Value<'a>>;

/// Callback type for async fetchers
pub type AsyncFetcherFn<Ctx> =
    for<'a> fn(&'a Ctx, Arc<[String]>) -> BoxFuture<'a, Option<Value<'a>>>;
