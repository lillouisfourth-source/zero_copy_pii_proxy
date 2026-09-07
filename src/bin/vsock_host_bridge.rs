// src/bin/vsock_host_bridge.rs
//
// VSOCK Proxy Bridge: Parent EC2 Host ↔ Nitro Enclave Bidirectional Tunnel
//
// This binary bridges host-side TCP traffic to the Nitro Enclave via vSOCKET.
// It runs on the parent EC2 instance (not inside the enclave).
//
// Topology:
//   External Client
//        ↓
//   Host TCP 0.0.0.0:3000
//        ↓ (this process)
//   Nitro Enclave VSOCK://<CID>:3000
//        ↓
//   Proxy binary (inside enclave)
//        ↓
//   Upstream LLM API (encrypted TLS)
//
// Usage:
//   cargo build --release --bin vsock_host_bridge --target x86_64-unknown-linux-musl
//   ./target/x86_64-unknown-linux-musl/release/vsock_host_bridge \
//     --enclave-cid 42 \
//     --listen 0.0.0.0:3000 \
//     --vsock-port 3000

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::net::TcpStream as TokioTcpStream;
use tokio_vsock::VsockStream;

/// Configuration for the VSOCK bridge
#[derive(Clone, Debug)]
struct BridgeConfig {
    /// Nitro Enclave CID (typically 3 for first enclave, 42+ for additional)
    enclave_cid: u32,
    /// VSOCK port inside the enclave (same as data plane port, typically 3000)
    enclave_port: u32,
    /// Host listen address (e.g., 0.0.0.0:3000)
    listen_addr: SocketAddr,
}

/// Bridge a single TCP connection to VSOCK
async fn bridge_connection(
    client_stream: TokioTcpStream,
    config: Arc<BridgeConfig>,
) -> Result<(), String> {
    // Get client peer address for logging
    let peer_addr = client_stream.peer_addr().ok();

    tracing::info!(
        ?peer_addr,
        enclave_cid = config.enclave_cid,
        enclave_port = config.enclave_port,
        "Accepting client connection, bridging to enclave..."
    );

    // Connect to Nitro Enclave VSOCK
    // NOTE: On Windows/macOS, this will fail (VSOCK is Linux-only).
    // For production use, run on Amazon Linux 2 with Nitro support.
    let mut enclave_stream = VsockStream::connect(config.enclave_cid, config.enclave_port)
        .await
        .map_err(|error| {
            format!(
                "failed to connect to enclave VSOCK CID {} port {}: {error}",
                config.enclave_cid, config.enclave_port
            )
        })?;

    // Stream data bidirectionally between client and enclave
    if let Err(error) = io::copy_bidirectional(&mut client_stream, &mut enclave_stream).await {
        tracing::error!(%error, ?peer_addr, "relay connection severed");
        return Err(format!("bidirectional relay failed: {error}"));
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .fmt_fields(tracing_subscriber::fmt::format::PrettyFields::new())
        .init();

    tracing::info!("VSOCK Bridge starting...");

    // Parse command-line arguments
    let config = parse_args()?;

    tracing::info!(
        listen_addr = %config.listen_addr,
        enclave_cid = config.enclave_cid,
        enclave_port = config.enclave_port,
        "Bridge configuration loaded"
    );

    // Create async TCP listener on host
    let listener = TokioTcpListener::bind(config.listen_addr)
        .await
        .map_err(|e| format!("Failed to bind listener: {}", e))?;

    tracing::info!(
        addr = %config.listen_addr,
        "Host TCP listener started. Waiting for connections..."
    );

    let config = Arc::new(config);

    // Accept connections in a loop
    loop {
        match listener.accept().await {
            Ok((client_stream, peer_addr)) => {
                let config = config.clone();

                // Spawn a task to handle this connection
                // This allows concurrent client connections
                tokio::spawn(async move {
                    if let Err(e) = bridge_connection(client_stream, config).await {
                        tracing::error!(error = %e, %peer_addr, "Bridge connection failed");
                    } else {
                        tracing::info!(%peer_addr, "Bridge connection closed gracefully");
                    }
                });
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to accept connection");
            }
        }
    }
}

/// Parse command-line arguments
fn parse_args() -> Result<BridgeConfig, String> {
    let args: Vec<String> = std::env::args().collect();

    let mut enclave_cid: Option<u32> = None;
    let mut enclave_port: Option<u32> = None;
    let mut listen_addr: Option<SocketAddr> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--enclave-cid" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --enclave-cid".to_string());
                }
                enclave_cid = Some(args[i].parse().map_err(|_| "Failed to parse enclave-cid")?);
            }
            "--enclave-port" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --enclave-port".to_string());
                }
                enclave_port = Some(
                    args[i]
                        .parse()
                        .map_err(|_| "Failed to parse enclave-port")?,
                );
            }
            "--listen" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --listen".to_string());
                }
                listen_addr = Some(
                    args[i]
                        .parse()
                        .map_err(|_| "Failed to parse listen address")?,
                );
            }
            "--help" => {
                println!(
                    r#"VSOCK Proxy Bridge - Nitro Enclave TCP↔VSOCK Tunnel

Usage:
    vsock_host_bridge [OPTIONS]

Options:
    --enclave-cid <CID>     Nitro Enclave CID (default: 3)
    --enclave-port <PORT>   VSOCK port inside enclave (default: 3000)
    --listen <ADDR:PORT>    Host listen address (default: 0.0.0.0:3000)
    --help                  Show this help message

Example:
    vsock_host_bridge --enclave-cid 42 --listen 0.0.0.0:3000 --enclave-port 3000

Running on non-Linux platforms will result in an error.
This binary must execute on an EC2 instance with Nitro Enclave support.
"#
                );
                std::process::exit(0);
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]));
            }
        }
        i += 1;
    }

    Ok(BridgeConfig {
        enclave_cid: enclave_cid.unwrap_or(3),
        enclave_port: enclave_port.unwrap_or(3000),
        listen_addr: listen_addr.unwrap_or_else(|| {
            "0.0.0.0:3000"
                .parse()
                .expect("Failed to parse default listen address")
        }),
    })
}

/// Graceful shutdown handler (stub for production)
#[allow(dead_code)]
async fn setup_shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
    };

    ctrl_c.await;
    tracing::info!("Shutdown signal received. Closing listener...");
    // In production, use CancellationToken to gracefully close all active connections
    std::process::exit(0);
}
