fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .format(true)
        .out_dir("src/grpc")
        .compile(&["src/grpc/hsmd.proto"], &["src/grpc"])?;
    Ok(())
}
