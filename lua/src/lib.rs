use std::ops::{Deref, DerefMut};

use mlua::prelude::*;
use rusty_rules::{BoolMatcher, IpMatcher, NumberMatcher, RegexMatcher, StringMatcher, Value};

/// A Lua wrapper for the [`rusty_rules::Engine`] that allows registering fetchers.
pub struct Engine(rusty_rules::Engine<LuaValue>);

impl Deref for Engine {
    type Target = rusty_rules::Engine<LuaValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Engine {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Engine {
    /// Creates a new rules engine instance for Lua.
    pub fn new() -> Self {
        Engine(rusty_rules::Engine::new())
    }
}

impl LuaUserData for Engine {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_function("new", |_, ()| Ok(Self::new()));

        methods.add_method_mut(
            "register_fetcher",
            |lua,
             this,
             (name, params_or_func, func): (
                String,
                LuaEither<LuaTable, LuaFunction>,
                Option<LuaFunction>,
            )| {
                let (params, fetcher) = match (params_or_func, func) {
                    (LuaEither::Left(params), Some(func)) => (Some(params), func),
                    (LuaEither::Right(func), _) => (None, func),
                    _ => Err(LuaError::external("fetcher function must be provided"))?,
                };

                let lua = lua.weak();
                let fetcher = this.0.register_fetcher(&name, move |ctx: &LuaValue, args| {
                    let mut combined_args = LuaVariadic::with_capacity(args.len() + 1);
                    combined_args.push(LuaEither::Left(ctx));
                    combined_args.extend(args.iter().map(|arg| LuaEither::Right(arg.as_str())));

                    Ok(match fetcher.call(combined_args)? {
                        LuaValue::String(s) => Value::String(s.to_string_lossy().into()),
                        value => lua.upgrade().from_value::<serde_json::Value>(value)?.into(),
                    })
                });

                let params = params.as_ref();
                let matcher = params.and_then(|p| p.get::<String>("matcher").ok());
                match matcher.as_deref() {
                    Some("bool") => fetcher.with_matcher(BoolMatcher),
                    Some("ip") => fetcher.with_matcher(IpMatcher),
                    Some("number") => fetcher.with_matcher(NumberMatcher),
                    Some("regex") | Some("re") => fetcher.with_matcher(RegexMatcher),
                    Some("string") => fetcher.with_matcher(StringMatcher),
                    Some(_) => return Ok(Err("unknown matcher type")),
                    None => fetcher,
                };
                let raw_args = params.and_then(|p| p.get("raw_args").ok());
                if raw_args.unwrap_or(false) {
                    fetcher.with_raw_args(true);
                }
                Ok(Ok(()))
            },
        );

        methods.add_method("compile", |lua, this, rule: LuaValue| {
            let rule = lua.from_value::<serde_json::Value>(rule)?;
            match this.0.compile_rule(&rule) {
                Ok(rule) => Ok(Ok(Rule(rule))),
                Err(err) => Ok(Err(err.to_string())),
            }
        });

        #[cfg(feature = "validation")]
        methods.add_method("validate", |lua, this, rule: LuaValue| {
            let rule = lua.from_value::<serde_json::Value>(rule)?;
            match this.0.validate_rule(&rule) {
                Ok(_) => Ok(Ok(true)),
                Err(err) => Ok(Err(err.to_string())),
            }
        });

        methods.add_method("json_schema", |_, this, ()| {
            let schema = this.0.json_schema();
            serde_json::to_string(&schema).into_lua_err()
        });
    }
}

/// A Lua wrapper for the [`rusty_rules::Rule`] that allows evaluating rules.
pub struct Rule(rusty_rules::Rule<LuaValue>);

impl Deref for Rule {
    type Target = rusty_rules::Rule<LuaValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Rule {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl LuaUserData for Rule {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("evaluate", |_, this, ctx| match this.0.evaluate(&ctx) {
            Ok(decision) => Ok(Ok(decision)),
            Err(err) => Ok(Err(err.to_string())),
        });
    }
}

#[cfg(test)]
mod tests {
    use mlua::prelude::*;

    use super::Engine;

    #[test]
    fn test() -> LuaResult<()> {
        let lua = Lua::new();

        let engine = lua.create_proxy::<Engine>()?;
        lua.globals().set("Engine", engine)?;

        lua.load(
            r#"
            local engine = Engine.new()
            engine:register_fetcher("ctx_fetcher", function(ctx, arg)
                return ctx[arg]
            end)

            local rule = engine:compile({["ctx_fetcher(key)"] = "my_value"})
            assert(rule:evaluate({key = "my_value"}) == true, "(1) should evaluate to true")
            assert(rule:evaluate({key = "other_value"}) == false, "(2) should evaluate to false")
            assert(rule:evaluate({}) == false, "(3) should evaluate to false")

            -- Edge cases
            local ok, err = rule:evaluate()
            assert(ok == nil and err:find("attempt to index a nil value"), "(4) should return an error")
            ok, err = engine:compile({["ctx_fetcher(key)"] = {op = 123}})
            assert(ok == nil and err:find("unknown operator 'op'"), "(5) should return an error")
            "#,
        )
        .exec()
        .unwrap();

        Ok(())
    }

    #[test]
    fn test_custom_matcher() -> LuaResult<()> {
        let lua = Lua::new();

        let engine = lua.create_proxy::<Engine>()?;
        lua.globals().set("Engine", engine)?;

        lua.load(
            r#"
            local engine = Engine.new()
            engine:register_fetcher("ip", { matcher = "ip" }, function(ctx)
                return ctx.ip
            end)

            local rule = engine:compile({ip = "127.0.0.1/8"})
            assert(rule:evaluate({ip = "127.0.0.1"}) == true, "(1) should evaluate to true")
            assert(rule:evaluate({ip = "172.16.0.0"}) == false, "(2) should evaluate to false")

            local _, err = engine:register_fetcher("ip", { matcher = "abc" }, function(ctx) end)
            assert(err:find("unknown matcher type"), "(3) should return an error for unknown matcher type")
            "#,
        )
        .exec()
        .unwrap();

        Ok(())
    }

    #[cfg(feature = "validation")]
    #[test]
    fn test_validation() -> LuaResult<()> {
        let lua = Lua::new();

        let engine = lua.create_proxy::<Engine>()?;
        lua.globals().set("Engine", engine)?;

        lua.load(
            r#"
            local engine = Engine.new()
            engine:register_fetcher("ctx_fetcher", function(ctx)
                return ctx[arg]
            end)

            local ok, err = engine:validate({["ctx_fetcher(key)"] = "my_value"})
            assert(ok == true and err == nil, "(1) should compile successfully")

            ok, err = engine:validate({unknown_fetcher = "my_value"})
            assert(not ok and err:find("'unknown_fetcher' was unexpected"), "(2) should return an error for unknown fetcher")
            "#,
        )
        .exec()
        .unwrap();

        Ok(())
    }
}
