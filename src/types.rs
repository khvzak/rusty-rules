use serde_json::Value as JsonValue;

pub use inner::*;

use crate::Operator;

#[cfg(not(feature = "send"))]
mod inner {
    use std::error::Error as StdError;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    pub trait MaybeSend {}
    impl<T: ?Sized> MaybeSend for T {}

    pub trait MaybeSync {}
    impl<T: ?Sized> MaybeSync for T {}

    /// An owned dynamically typed [`Future`]
    pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

    pub(crate) type DynError = Box<dyn StdError>;

    /// Callback type for fetchers
    pub(crate) type FetcherFn<Ctx> =
        dyn for<'a> Fn(&'a Ctx, &[String]) -> Result<crate::Value<'a>, DynError>;

    /// Callback type for async fetchers
    pub(crate) type AsyncFetcherFn<Ctx> =
        for<'a> fn(&'a Ctx, Arc<[String]>) -> BoxFuture<'a, Result<crate::Value<'a>, DynError>>;

    /// Callback type for operator check function
    pub type CheckFn<Ctx> = dyn Fn(&Ctx, crate::Value) -> Result<bool, DynError>;

    /// Callback type for async operator check function
    pub type AsyncCheckFn<Ctx> =
        dyn for<'a> Fn(&'a Ctx, crate::Value<'a>) -> BoxFuture<'a, Result<bool, DynError>>;

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

    pub trait MaybeSend: Send {}
    impl<T: Send + ?Sized> MaybeSend for T {}

    pub trait MaybeSync: Sync {}
    impl<T: Sync + ?Sized> MaybeSync for T {}

    /// An owned dynamically typed [`Future`]
    pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

    pub(crate) type DynError = Box<dyn StdError + Send + Sync>;

    /// Callback type for fetchers
    pub(crate) type FetcherFn<Ctx> =
        dyn for<'a> Fn(&'a Ctx, &[String]) -> Result<crate::Value<'a>, DynError> + Send + Sync;

    /// Callback type for async fetchers
    pub(crate) type AsyncFetcherFn<Ctx> = dyn for<'a> Fn(&'a Ctx, Arc<[String]>) -> BoxFuture<'a, Result<crate::Value<'a>, DynError>>
        + Send
        + Sync;

    /// Callback type for operator check function
    pub type CheckFn<Ctx> = dyn Fn(&Ctx, crate::Value) -> Result<bool, DynError> + Send + Sync;

    /// Callback type for async operator check function
    pub type AsyncCheckFn<Ctx> = dyn for<'a> Fn(&'a Ctx, crate::Value<'a>) -> BoxFuture<'a, Result<bool, DynError>>
        + Send
        + Sync;

    pub(crate) type EvalFn<Ctx> = Arc<dyn Fn(&Ctx) -> Result<bool, DynError> + Send + Sync>;

    pub(crate) type AsyncEvalFn<Ctx> =
        Arc<dyn for<'a> Fn(&'a Ctx) -> BoxFuture<'a, Result<bool, DynError>> + Send + Sync>;
}

pub trait ToOperator<Ctx: ?Sized>: MaybeSend + MaybeSync {
    fn to_operator(&self, value: &JsonValue) -> Result<Operator<Ctx>, DynError>;

    fn json_schema(&self) -> JsonValue {
        serde_json::json!({})
    }
}

impl<Ctx: ?Sized, F> ToOperator<Ctx> for F
where
    F: Fn(JsonValue) -> Result<Operator<Ctx>, DynError> + MaybeSend + MaybeSync + 'static,
{
    fn to_operator(&self, value: &JsonValue) -> Result<Operator<Ctx>, DynError> {
        self(value.clone())
    }
}
