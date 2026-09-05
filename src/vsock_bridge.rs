#![cfg(feature = "nitro")]

pub async fn start_tunnel(local_port: u16, vsock_cid: u32, vsock_port: u32) {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", local_port))
        .await
        .unwrap();

    tokio::task::spawn(async move {
        loop {
            let (mut tcp, _) = listener.accept().await.unwrap();
            tokio::task::spawn(async move {
                let Ok(mut vsock) = tokio_vsock::VsockStream::connect(vsock_cid, vsock_port).await
                else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut vsock).await;
            });
        }
    });
}

pub async fn spawn_enclave_tunnels() {
    static STARTED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    STARTED
        .get_or_init(|| async {
            start_tunnel(8000, 3, 8000).await;
            start_tunnel(8001, 3, 8001).await;
        })
        .await;
}