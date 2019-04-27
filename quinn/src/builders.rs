use std::borrow::Cow;
use std::io;
use std::net::ToSocketAddrs;
use std::str;
use std::sync::Arc;

use err_derive::Error;
use proto::{ClientConfig, EndpointConfig, ServerConfig};
use rustls::{KeyLogFile, TLSError};
use slog::Logger;

use crate::endpoint::{Endpoint, EndpointDriver, EndpointRef, Incoming};
use crate::tls::{Certificate, CertificateChain, PrivateKey};
use crate::udp::UdpSocket;

/// A helper for constructing an `Endpoint`.
pub struct EndpointBuilder<'a> {
    reactor: Option<&'a tokio_reactor::Handle>,
    logger: Logger,
    server_config: Option<ServerConfig>,
    config: EndpointConfig,
    client_config: ClientConfig,
}

#[allow(missing_docs)]
impl<'a> EndpointBuilder<'a> {
    /// Start a builder with a specific initial low-level configuration.
    pub fn new(config: EndpointConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Build an endpoint bound to `addr`.
    pub fn bind<T: ToSocketAddrs>(
        self,
        addr: T,
    ) -> Result<(EndpointDriver, Endpoint, Incoming), EndpointError> {
        let socket = std::net::UdpSocket::bind(addr).map_err(EndpointError::Socket)?;
        self.with_socket(socket)
    }

    /// Build an endpoint around a pre-configured socket.
    pub fn with_socket(
        self,
        socket: std::net::UdpSocket,
    ) -> Result<(EndpointDriver, Endpoint, Incoming), EndpointError> {
        let reactor = match self.reactor {
            Some(x) => Cow::Borrowed(x),
            None => Cow::Owned(tokio_reactor::Handle::default()),
        };
        let addr = socket.local_addr().map_err(EndpointError::Socket)?;
        let socket = UdpSocket::from_std(socket, &reactor).map_err(EndpointError::Socket)?;
        let rc = EndpointRef::new(
            self.logger.clone(),
            socket,
            proto::Endpoint::new(
                self.logger,
                Arc::new(self.config),
                self.server_config.map(Arc::new),
            )?,
            addr.is_ipv6(),
        );
        Ok((
            EndpointDriver(rc.clone()),
            Endpoint {
                inner: rc.clone(),
                default_client_config: self.client_config,
            },
            Incoming::new(rc),
        ))
    }

    /// Accept incoming connections.
    pub fn listen(&mut self, config: ServerConfig) -> &mut Self {
        self.server_config = Some(config);
        self
    }

    pub fn reactor(&mut self, handle: &'a tokio_reactor::Handle) -> &mut Self {
        self.reactor = Some(handle);
        self
    }
    pub fn logger(&mut self, logger: Logger) -> &mut Self {
        self.logger = logger;
        self
    }

    /// Set the default configuration used for outgoing connections.
    ///
    /// The default can be overriden by using `Endpoint::connect_with`.
    pub fn default_client_config(&mut self, config: ClientConfig) -> &mut Self {
        self.client_config = config;
        self
    }
}

impl<'a> Default for EndpointBuilder<'a> {
    fn default() -> Self {
        Self {
            reactor: None,
            logger: Logger::root(slog::Discard, o!()),
            server_config: None,
            config: EndpointConfig::default(),
            client_config: ClientConfig::default(),
        }
    }
}

/// Errors that can occur during the construction of an `Endpoint`.
#[derive(Debug, Error)]
pub enum EndpointError {
    /// An error during setup of the underlying UDP socket.
    #[error(display = "failed to set up UDP socket: {}", _0)]
    Socket(io::Error),
    /// An error configuring TLS.
    #[error(display = "failed to set up TLS: {}", _0)]
    Tls(TLSError),
    /// Errors relating to web PKI infrastructure
    #[error(display = "webpki failed: {:?}", _0)]
    WebPki(webpki::Error),
    /// An error in the Quinn transport configuration
    #[error(display = "configuration error: {:?}", _0)]
    Config(proto::ConfigError),
}

impl From<proto::ConfigError> for EndpointError {
    fn from(x: proto::ConfigError) -> Self {
        EndpointError::Config(x)
    }
}

impl From<webpki::Error> for EndpointError {
    fn from(e: webpki::Error) -> Self {
        EndpointError::WebPki(e)
    }
}

/// Helper for constructing a `ServerConfig` to be passed to `EndpointBuilder::listen` to enable
/// incoming connections.
pub struct ServerConfigBuilder {
    config: ServerConfig,
}

impl ServerConfigBuilder {
    /// Construct a builder using `config` as the initial state.
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    /// Construct the complete `ServerConfig`.
    pub fn build(self) -> ServerConfig {
        self.config
    }

    /// Enable NSS-compatible cryptographic key logging to the `SSLKEYLOGFILE` environment variable.
    ///
    /// Useful for debugging encrypted communications with protocol analyzers such as Wireshark.
    pub fn enable_keylog(&mut self) -> &mut Self {
        Arc::make_mut(&mut self.config.crypto).key_log = Arc::new(KeyLogFile::new());
        self
    }

    /// Set the certificate chain that will be presented to clients.
    pub fn certificate(
        &mut self,
        cert_chain: CertificateChain,
        key: PrivateKey,
    ) -> Result<&mut Self, TLSError> {
        Arc::make_mut(&mut self.config.crypto).set_single_cert(cert_chain.certs, key.inner)?;
        Ok(self)
    }

    /// Set the application-layer protocols to accept, in order of descending preference.
    ///
    /// When set, clients which don't declare support for at least one of the supplied protocols will be rejected.
    ///
    /// The IANA maintains a [registry] of standard protocol IDs, but custom IDs may be used as well.
    ///
    /// [registry]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
    pub fn protocols(&mut self, protocols: &[&[u8]]) -> &mut Self {
        Arc::make_mut(&mut self.config.crypto).alpn_protocols =
            protocols.iter().map(|x| x.to_vec()).collect();
        self
    }

    /// Whether to require clients to prove they can receive packets before accepting a connection
    pub fn use_stateless_retry(&mut self, enabled: bool) -> &mut Self {
        self.config.use_stateless_retry = enabled;
        self
    }
}

impl Default for ServerConfigBuilder {
    fn default() -> Self {
        Self {
            config: ServerConfig::default(),
        }
    }
}

/// Helper for creating new outgoing connections.
pub struct ClientConfigBuilder {
    config: ClientConfig,
}

impl ClientConfigBuilder {
    /// Construct a builder using `config` as the initial state.
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Add a trusted certificate authority.
    ///
    /// For more advanced/less secure certificate verification, construct a [`ClientConfig`]
    /// manually and use rustls's `dangerous_configuration` feature to override the certificate
    /// verifier.
    pub fn add_certificate_authority(
        &mut self,
        cert: Certificate,
    ) -> Result<&mut Self, EndpointError> {
        {
            let anchor = webpki::trust_anchor_util::cert_der_as_trust_anchor(
                untrusted::Input::from(&cert.inner.0),
            )?;
            Arc::make_mut(&mut self.config.crypto)
                .root_store
                .add_server_trust_anchors(&webpki::TLSServerTrustAnchors(&[anchor]));
        }
        Ok(self)
    }

    /// Enable NSS-compatible cryptographic key logging to the `SSLKEYLOGFILE` environment variable.
    ///
    /// Useful for debugging encrypted communications with protocol analyzers such as Wireshark.
    pub fn enable_keylog(&mut self) -> &mut Self {
        Arc::make_mut(&mut self.config.crypto).key_log = Arc::new(KeyLogFile::new());
        self
    }

    /// Set the application-layer protocols to accept, in order of descending preference.
    ///
    /// When set, clients which don't declare support for at least one of the supplied protocols will be rejected.
    ///
    /// The IANA maintains a [registry] of standard protocol IDs, but custom IDs may be used as well.
    ///
    /// [registry]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
    pub fn protocols(&mut self, protocols: &[&[u8]]) -> &mut Self {
        Arc::make_mut(&mut self.config.crypto).alpn_protocols =
            protocols.iter().map(|x| x.to_vec()).collect();
        self
    }

    /// Begin connecting from `endpoint` to `addr`.
    pub fn build(self) -> ClientConfig {
        self.config
    }
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        let mut x = ClientConfig::default();
        let crypto = Arc::make_mut(&mut x.crypto);
        crypto
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        crypto.ct_logs = Some(&ct_logs::LOGS);
        Self::new(x)
    }
}
