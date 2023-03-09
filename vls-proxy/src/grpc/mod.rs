pub mod adapter;
mod hsmd {
    tonic::include_proto!("hsmd");
}
pub mod incoming;
pub mod signer;
pub mod signer_loop;
