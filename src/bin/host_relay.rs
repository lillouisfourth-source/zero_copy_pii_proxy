#![cfg(feature = "host-bridge")]

#[tokio::main]
async fn main() {
    zero_copy_pii_proxy::vsock_host_bridge::start_host_daemon().await;
    std::future::pending::<()>().await;
}
