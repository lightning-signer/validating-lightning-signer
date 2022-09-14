pub mod client;
mod database;
mod model;
pub mod server;
mod proto {
    tonic::include_proto!("lss");
}
pub mod util;

pub use database::{Database, Error};
pub use model::Value;
