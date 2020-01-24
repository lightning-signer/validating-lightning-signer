use lightning_signer::client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    client::driver::start()
}
