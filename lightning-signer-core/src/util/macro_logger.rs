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

#[macro_export]
macro_rules! log_bytes {
    ($obj: expr) => {
        crate::util::macro_logger::DebugBytes(&$obj)
    };
}
