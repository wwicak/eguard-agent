fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(
            &[
                "../../proto/eguard/v1/agent.proto",
                "../../proto/eguard/v1/telemetry.proto",
                "../../proto/eguard/v1/compliance.proto",
                "../../proto/eguard/v1/command.proto",
                "../../proto/eguard/v1/response.proto",
            ],
            &["../../proto"],
        )?;

    Ok(())
}
