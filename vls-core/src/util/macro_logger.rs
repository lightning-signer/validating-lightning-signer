/// Return a long version of the function name.
#[macro_export]
macro_rules! function {
    () => {{
        fn _f() {}
        fn _type_name_of<T>(_: T) -> &'static str {
            core::any::type_name::<T>()
        }
        let name = _type_name_of(_f);
        &name[..name.len() - 3]
    }};
}

/// Return a shortened version of the function name.
#[macro_export]
macro_rules! short_function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            core::any::type_name::<T>()
        }
        let name = type_name_of(f);

        // Find and cut the rest of the path
        match &name[..name.len() - 3].rfind(':') {
            Some(pos) => &name[pos + 1..name.len() - 3],
            None => &name[..name.len() - 3],
        }
    }};
}

/// Return a shortened version of the function name outside the closure.
#[macro_export]
macro_rules! containing_function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            core::any::type_name::<T>()
        }
        let name = type_name_of(f);

        // Find and cut the rest of the path
        match &name[..name.len() - 3].strip_suffix("::{{closure}}") {
            Some(stripped) => match &stripped.rfind(':') {
                Some(pos) => &stripped[pos + 1..stripped.len()],
                None => &stripped,
            },
            None => &name[..name.len() - 3],
        }
    }};
}

/// Construct a string suitable for debugging from a list of arguments
#[macro_export]
macro_rules! vals_str {
    ( $( $x:expr ),* ) => {{
        let mut buffer = String::new();
            $(
                {
                    #[cfg(not(feature = "log_pretty_print"))]
                    {
                        if buffer.len() > 0 {
                            buffer.push_str(", ");
                        }
                        buffer.push_str(&format!("{}: {:?}", stringify!($x), $x)[..]);
                    }

                    #[cfg(feature = "log_pretty_print")] {
                    }
                    if buffer.len() > 0 {
                            buffer.push_str(",");
                    }
                    buffer.push_str(&format!("\n{}: {:#?}", stringify!($x), $x)[..]);
                }
            )*
            buffer
        }};
}

/// Log bytes
#[macro_export]
macro_rules! log_bytes {
    ($obj: expr) => {
        crate::util::macro_logger::DebugBytes(&$obj)
    };
}
