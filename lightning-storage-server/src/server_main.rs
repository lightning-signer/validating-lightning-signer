use lightning_storage_server::server;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    server::driver::start()
}
