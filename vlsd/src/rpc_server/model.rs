use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InfoModel {
    height: u32,
    channels: u32,
    version: String,
}

impl InfoModel {
    pub fn new(height: u32, channels: u32, version: String) -> Self {
        Self { height, channels, version }
    }
}
