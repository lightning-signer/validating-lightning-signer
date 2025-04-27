fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .compile_protos(&["src/grpc/hsmd.proto"], &["src/grpc"])?;
    Ok(())
}
