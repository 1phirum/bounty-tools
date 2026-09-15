fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Explicitly set PROTOC environment variable so tonic-build knows where to find our downloaded compiler
    std::env::set_var("PROTOC", r"C:\bug-tools\.bin\protoc\bin\protoc.exe");
    
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &["../../contracts/v1/events.proto"],
            &["../../contracts/v1"],
        )?;
    
    Ok(())
}
