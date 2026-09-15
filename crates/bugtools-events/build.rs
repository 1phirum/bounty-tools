fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Honor PROTOC/PATH; retain the repository-local Windows fallback.
    println!("cargo:rerun-if-env-changed=PROTOC");
    if std::env::var_os("PROTOC").is_none() {
        let local = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.bin/protoc/bin/protoc.exe");
        if cfg!(windows) && local.is_file() {
            std::env::set_var("PROTOC", local);
        }
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &["../../contracts/v1/events.proto"],
            &["../../contracts/v1"],
        )?;

    Ok(())
}
