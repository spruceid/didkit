#[macro_export]
macro_rules! throws {
    ($cx:ident, $f:expr) => {
        match $f {
            Ok(v) => Ok(v),
            Err(e) => {
                let err: Error = e.into();
                $cx.throw_error(err.0)
            }
        }
    };
}

#[macro_export]
macro_rules! arg {
    ($cx:ident, $i:expr, $ty:ty) => {{
        let val = $cx.argument::<JsValue>($i)?;
        let ret: $ty = throws!($cx, neon_serde::from_value(&mut $cx, val))?;
        ret
    }};
}

#[macro_export]
macro_rules! prop {
    ($cx:ident, $obj:ident, $prop:expr, $ty:ty) => {{
        let val = $obj
            .get(&mut $cx, $prop)?
            .downcast_or_throw::<JsValue, _>(&mut $cx)?;

        let ret: $ty = throws!($cx, neon_serde::from_value(&mut $cx, val))?;

        ret
    }};
}

#[macro_export]
macro_rules! map_opt_prop {
    ($cx:ident, $obj:ident, $prop:expr, $tobj:ident, $tprop:expr) => {{
        let val = $obj.get(&mut $cx, $prop);

        if let Ok(val) = val {
            $tobj.set(&mut $cx, $tprop, val);
        }
    }};
}
