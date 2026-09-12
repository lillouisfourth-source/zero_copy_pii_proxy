use std::io;
use std::sync::Arc;

use axum::serve::Listener;
use rcgen::generate_simple_self_signed;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

pub fn build_tls_acceptor() -> TlsAcceptor {
    let certified_key = generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("failed to generate ephemeral enclave TLS certificate");
    let certificate = rustls::pki_types::CertificateDer::from(certified_key.cert.der().to_vec());
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der()),
    );
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .expect("failed to build enclave TLS server configuration");

    TlsAcceptor::from(Arc::new(config))
}

pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub fn new(listener: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self { listener, acceptor }
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = loop {
                match self.listener.accept().await {
                    Ok(connection) => break connection,
                    Err(error) => {
                        tracing::error!(%error, "TLS listener accept failed");
                    }
                }
            };

            match self.acceptor.accept(stream).await {
                Ok(tls_stream) => return (tls_stream, address),
                Err(error) => {
                    tracing::warn!(%error, %address, "TLS handshake failed");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsListener")
            .field("listener", &self.listener)
            .finish_non_exhaustive()
    }
}
