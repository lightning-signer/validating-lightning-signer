use lightning_signer_server::server;

// BEGIN NOT TESTED
fn main() -> Result<(), Box<dyn std::error::Error>> {
    server::driver::start()
}
// END NOT TESTED
