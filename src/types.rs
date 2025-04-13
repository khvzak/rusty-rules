use std::sync::Arc;

pub use inner::*;

use crate::Value;

#[cfg(not(feature = "send"))]
mod inner {
    use std::error::Error as StdError;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use serde_json::Value as JsonValue;

    use crate::{Operator, Value};

    pub trait MaybeSend {}
    impl<T: ?Sized> MaybeSend for T {}

    pub trait MaybeSync {}
    impl<T: ?Sized> MaybeSync for T {}

    pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

    pub(crate) type DynError = Box<dyn StdError>;

    /// Callback type for operators
    pub(crate) type OperatorBuilder<Ctx> =
        Arc<dyn Fn(&JsonValue) -> Result<Operator<Ctx>, DynError>>;

    /// Callback type for operator check function
    pub type CheckFn<Ctx> = dyn Fn(&Ctx, Value) -> Result<bool, DynError>;

    /// Callback type for async operator check function
    pub type AsyncCheckFn<Ctx> =
        dyn for<'a> Fn(&'a Ctx, Value<'a>) -> BoxFuture<'a, Result<bool, DynError>>;

    pub(crate) type EvalFn<Ctx> = Arc<dyn Fn(&Ctx) -> Result<bool, DynError>>;

    pub(crate) type AsyncEvalFn<Ctx> =
        Arc<dyn for<'a> Fn(&'a Ctx) -> BoxFuture<'a, Result<bool, DynError>>>;
}

#[cfg(feature = "send")]
mod inner {
    use std::error::Error as StdError;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use serde_json::Value as JsonValue;

    use crate::{Operator, Value};

    pub trait MaybeSend: Send {}
    impl<T: Send + ?Sized> MaybeSend for T {}

    pub trait MaybeSync: Sync {}
    impl<T: Sync + ?Sized> MaybeSync for T {}

    pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

    pub(crate) type DynError = Box<dyn StdError + Send + Sync>;

    pub(crate) type OperatorBuilder<Ctx> =
        Arc<dyn Fn(&JsonValue) -> Result<Operator<Ctx>, DynError> + Send + Sync>;

    /// Callback type for operator check function
    pub type CheckFn<Ctx> = dyn Fn(&Ctx, Value) -> Result<bool, DynError> + Send + Sync;

    /// Callback type for async operator check function
    pub type AsyncCheckFn<Ctx> =
        dyn for<'a> Fn(&'a Ctx, Value<'a>) -> BoxFuture<'a, Result<bool, DynError>> + Send + Sync;

    pub(crate) type EvalFn<Ctx> = Arc<dyn Fn(&Ctx) -> Result<bool, DynError> + Send + Sync>;

    pub(crate) type AsyncEvalFn<Ctx> =
        Arc<dyn for<'a> Fn(&'a Ctx) -> BoxFuture<'a, Result<bool, DynError>> + Send + Sync>;
}

/// Callback type for fetchers
pub type FetcherFn<Ctx> = for<'a> fn(&'a Ctx, &[String]) -> Result<Value<'a>, DynError>;

/// Callback type for async fetchers
pub type AsyncFetcherFn<Ctx> =
    for<'a> fn(&'a Ctx, Arc<[String]>) -> BoxFuture<'a, Result<Value<'a>, DynError>>;
