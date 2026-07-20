fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tell Cargo to re-run this script if the proto files change
    println!("cargo:rerun-if-changed=proto/rpc.proto");
    println!("cargo:rerun-if-changed=proto/messages.proto");

    // Compile the Kaspa gRPC protobuf files into native Rust code
    tonic_build::configure()
        .build_server(false)
        .compile(
            &["proto/messages.proto", "proto/rpc.proto"],
            &["proto/"],
        )?;
        
    Ok(())
}