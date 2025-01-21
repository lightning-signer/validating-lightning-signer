fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .protoc_arg("-I=..")
        .compile_protos(&["proto/lss.proto"], &["proto"])?;
    Ok(())
}
