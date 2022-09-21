fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .format(true)
        .compile(&["proto/lss.proto"], &["proto"])?;
    Ok(())
}
