use lightning_signer::server;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    server::driver::start()
}
