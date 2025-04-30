#[macro_export]
macro_rules! log_pretty {
    ($level:ident, $err:expr) => {
        #[cfg(not(feature = "log_pretty_print"))]
        $level!("{:?}", $err);
        #[cfg(feature = "log_pretty_print")]
        $level!("{:#?}", $err);
    };

    ($level:ident, $err:expr, $self:expr) => {
        #[cfg(not(feature = "log_pretty_print"))]
        $level!("{:?}: {:?}", $self.client_id, $err);
        #[cfg(feature = "log_pretty_print")]
        $level!("{:?}: {:#?}", $self.client_id, $err);
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)+) => {
        log_pretty!(error, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_request {
    ($($arg:tt)+) => {
        log_pretty!(debug, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_reply {
    ($reply_bytes:expr) => {
        if log::log_enabled!(log::Level::Debug) {
            let reply = msgs::from_vec($reply_bytes.clone()).expect("parse reply failed");
            log_pretty!(debug, reply);
        }
    };
    ($reply_bytes:expr, $self:expr) => {
        if log::log_enabled!(log::Level::Debug) {
            let reply = msgs::from_vec($reply_bytes.clone()).expect("parse reply failed");
            log_pretty!(debug, reply, $self);
        }
    };
}
