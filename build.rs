fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .format(false)
        .out_dir("src/server")
        .compile(&["src/server/remotesigner.proto"], &["src/server"])?;
    Ok(())
}
