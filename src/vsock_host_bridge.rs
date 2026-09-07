#![cfg(feature = "host-bridge")]

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_vsock::{VsockListener, VsockStream};

const VMADDR_CID_ANY: u32 = 0xffff_ffff;
const MAX_CONNECT_HEADERS: usize = 4096;

pub async fn run_host_vsock_relay(
    vsock_port: u32,
    target_host: &str,
    target_port: u16,
) -> Result<(), String> {
    let mut listener = VsockListener::bind(VMADDR_CID_ANY, vsock_port)
        .map_err(|error| format!("failed to bind VSOCK port {vsock_port}: {error}"))?;
    let target_host = target_host.to_string();

    loop {
        let (vsock, _) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept VSOCK connection: {error}"))?;
        let target_host = target_host.clone();
        tokio::spawn(async move {
            if target_port == 443 {
                let result = tokio::time::timeout(
                    Duration::from_secs(3),
                    relay_connect_connection(vsock, &target_host),
                )
                .await;
                if let Err(error) = match result {
                    Ok(result) => result,
                    Err(_) => Err("KMS CONNECT handshake timed out".to_string()),
                } {
                    tracing::warn!(%error, "KMS VSOCK relay connection rejected");
                }
            } else {
                let Ok(mut tcp) = TcpStream::connect((target_host.as_str(), target_port)).await
                else {
                    return;
                };
                let mut vsock = vsock;
                let _ = tokio::io::copy_bidirectional(&mut vsock, &mut tcp).await;
            }
        });
    }
}

async fn relay_connect_connection(vsock: VsockStream, fallback_host: &str) -> Result<(), String> {
    let mut buffered_vsock = BufReader::new(vsock);
    let requested_host = read_connect_target(&mut buffered_vsock).await?;
    validate_kms_host(&requested_host)?;

    let target_host = if requested_host.is_empty() {
        fallback_host.to_string()
    } else {
        requested_host
    };
    let mut tcp = TcpStream::connect((target_host.as_str(), 443))
        .await
        .map_err(|error| format!("failed to connect to KMS endpoint: {error}"))?;
    buffered_vsock
        .get_mut()
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|error| format!("failed to acknowledge CONNECT request: {error}"))?;
    tokio::io::copy_bidirectional(&mut buffered_vsock, &mut tcp)
        .await
        .map_err(|error| format!("KMS relay copy failed: {error}"))?;
    Ok(())
}

async fn read_connect_target<R>(reader: &mut BufReader<R>) -> Result<String, String>
where
    R: AsyncRead + Unpin,
{
    let mut handshake = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    let mut state = 0u8;

    loop {
        if handshake.len() == MAX_CONNECT_HEADERS {
            return Err("CONNECT headers exceed 4096 bytes".to_string());
        }
        reader
            .read_exact(&mut byte)
            .await
            .map_err(|error| format!("failed to read CONNECT headers: {error}"))?;
        handshake.push(byte[0]);
        state = match (state, byte[0]) {
            (0, b'\r') => 1,
            (1, b'\n') => 2,
            (2, b'\r') => 3,
            (3, b'\n') => break,
            (_, b'\r') => 1,
            _ => 0,
        };
    }

    let header_text = std::str::from_utf8(&handshake)
        .map_err(|_| "CONNECT headers are not valid ASCII".to_string())?;
    let request_line = header_text
        .split("\r\n")
        .next()
        .ok_or_else(|| "CONNECT request is empty".to_string())?;
    let mut fields = request_line.split_whitespace();
    let method = fields
        .next()
        .ok_or_else(|| "CONNECT method is missing".to_string())?;
    let authority = fields
        .next()
        .ok_or_else(|| "CONNECT authority is missing".to_string())?;
    let version = fields
        .next()
        .ok_or_else(|| "CONNECT HTTP version is missing".to_string())?;
    if method != "CONNECT" || version != "HTTP/1.1" || fields.next().is_some() {
        return Err("invalid CONNECT request line".to_string());
    }
    Ok(authority.to_string())
}

fn allowed_kms_host() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.windows(2)
        .find(|values| values[0] == "--allowed-kms-host")
        .map(|values| values[1].clone())
}

fn validate_kms_host(authority: &str) -> Result<(), String> {
    if allowed_kms_host().as_deref() == Some(authority) {
        return Ok(());
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Err("KMS CONNECT authority must include port 443".to_string());
    };
    if port != "443" || host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return Err("KMS CONNECT target is not an approved hostname".to_string());
    }
    let mut labels = host.split('.');
    let service = labels.next().unwrap_or_default();
    let region = labels.next().unwrap_or_default();
    if labels.next().is_some()
        || !(service == "kms" || service == "kms-fips")
        || region.is_empty()
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("KMS CONNECT target is not an approved hostname".to_string());
    }
    Ok(())
}

pub async fn start_host_daemon() {
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    tokio::spawn(async move {
        if let Err(error) =
            run_host_vsock_relay(8000, &format!("kms.{region}.amazonaws.com"), 443).await
        {
            tracing::error!(%error, "KMS host relay stopped");
        }
    });
    tokio::spawn(async {
        if let Err(error) = run_host_vsock_relay(8001, "169.254.169.254", 80).await {
            tracing::error!(%error, "IMDS host relay stopped");
        }
    });
}
