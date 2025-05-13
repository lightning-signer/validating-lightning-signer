macro_rules! type_name {
    ($tt: expr) => {{
        fn type_name_of<T>(_: &T) -> &'static str {
            std::any::type_name::<T>()
        }
        type_name_of($tt)
    }};
}

macro_rules! type_and_value {
    ($vv: expr) => {{
        format!("{}={}", type_name!($vv), json!($vv))
    }};
}
