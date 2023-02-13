use lightning_storage_server::server;

fn abort_on_panic() {
    let old = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        old(info);
        std::process::abort();
    }));
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    abort_on_panic();
    server::driver::start()
}
