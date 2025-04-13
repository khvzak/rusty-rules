#![cfg(not(feature = "send"))]

use mlua::prelude::*;
use rusty_rules::{Engine, Operator, StringMatcher, Value};
use serde_json::json;

#[test]
fn test_lua_operator() {
    let lua = Lua::new();

    let mut engine = Engine::<str>::new();

    // Register method fetcher
    engine.register_fetcher("sample", StringMatcher, |_ctx, _args| {
        Ok(Value::from("sample string"))
    });

    let lua2 = lua.clone();
    engine.register_operator("eval", move |value| {
        let script = match value {
            serde_json::Value::String(s) => s.clone(),
            _ => return Err("`lua` requires a string script".into()),
        };
        let func = lua2
            .load(script)
            .eval::<LuaFunction>()
            .map_err(|err| err.to_string())?;

        Ok(Operator::Custom(Box::new(move |ctx, value| match value {
            Value::String(s) => Ok(func.call((ctx, s))?),
            Value::Number(n) => Ok(func.call((ctx, n.is_i64()))?),
            _ => Ok(false),
        })))
    });

    // Run the tests
    let rule = engine
        .parse_value(&json!({
            "sample": {
                "eval": "function(ctx, value) return ctx == '1' and string.find(value, 'sample') ~= nil end"
            },
        }))
        .unwrap();

    assert!(rule.evaluate(&"1").unwrap());
    assert!(!rule.evaluate(&"2").unwrap());
}
