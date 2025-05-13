use anyhow::Result;
use log::info;
use serde::Serializer;
use triggered::{Listener, Trigger};

pub fn as_hex<S>(buf: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(&buf))
}

pub fn as_payment_status<S>(status: &i32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(match status {
        0 => "pending",
        1 => "succeeded",
        2 => "failed",
        _ => "unknown",
    })
}

#[derive(Clone)]
pub struct Shutter {
    pub trigger: Trigger,
    pub signal: Listener,
}

impl Shutter {
    /// There should only be one of these per process
    pub fn new() -> Self {
        let (trigger, signal) = triggered::trigger();
        let ctrlc_trigger = trigger.clone();
        ctrlc::set_handler(move || {
            info!("got termination signal");
            ctrlc_trigger.trigger();
        })
        .expect("Error setting Ctrl-C handler - do you have more than one?");

        Self { trigger, signal }
    }
}
