// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{
    jsonrpc::parse_jsonrpc_request, Error, JsonRpcRequest, JsonRpcResponse, Result, ALPN_QUIC_HTTP,
};
use crate::utils;
use log::{debug, trace, warn};
use rustls::{Certificate, PrivateKey, RootCertStore};
use std::{fs, net::SocketAddr, path::Path, sync::Arc};

/// A QUIC Server Endpoint for using JSON-RPC.
///
/// Based on the QUINN library's implementation of QUIC.
///
/// As per `ClientEndpoint`, the additional fields are added for unit testing, but could potentially
/// be used by callers of the library.
pub struct ServerEndpoint {
    config: quinn::ServerConfig,
    #[allow(dead_code)]
    crypto_config: rustls::ServerConfig,
    #[allow(dead_code)]
    idle_timeout: u64,
}

impl ServerEndpoint {
    /// Create a new `ServerEndpoint` instance.
    ///
    /// The path of a certificate is required.
    ///
    /// The corresponding private key for the certificate is required.
    ///
    /// An optional idle timeout can be specified in milliseconds; otherwise a default of 18
    /// seconds will be used.
    pub fn new<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
        idle_timeout: Option<u64>,
    ) -> Result<Self> {
        trace!("Creating a new server endpoint");
        let (cert, key) = fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?)))?;
        let mut store = RootCertStore::empty();
        let (added, _) = store.add_parsable_certificates(vec![cert.clone()].as_slice());
        if added != 1 {
            return Err(Error::ServerError(
                "A valid certificate must be supplied".to_string(),
            ));
        }

        let key = PrivateKey(key);
        let cert = Certificate(cert);
        let mut crypto_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;
        crypto_config.alpn_protocols = vec![ALPN_QUIC_HTTP.to_vec()];

        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto_config.clone()));
        let (transport, timeout) = utils::new_transport_cfg(idle_timeout)?;
        config.transport = Arc::new(transport);

        trace!("Server endpoint with transport config: {config:?}");
        Ok(Self {
            config,
            crypto_config,
            idle_timeout: timeout,
        })
    }

    pub fn bind(&self, listen_socket_addr: &SocketAddr) -> Result<IncomingConn> {
        let endpoint = quinn::Endpoint::server(self.config.clone(), *listen_socket_addr)?;
        Ok(IncomingConn::new(endpoint))
    }
}

// Stream of incoming QUIC connections
pub struct IncomingConn {
    quinn_endpoint: quinn::Endpoint,
}

impl IncomingConn {
    pub(crate) fn new(quinn_endpoint: quinn::Endpoint) -> Self {
        Self { quinn_endpoint }
    }

    /// Get the next incoming peer connection.
    ///
    /// The `next` function blocks until a peer establishes a new connection.
    pub async fn get_next(&mut self) -> Result<Option<IncomingJsonRpcRequest>> {
        debug!("Wait for new incoming connection...");
        match self.quinn_endpoint.accept().await {
            Some(connecting) => match connecting.await {
                Ok(conn) => {
                    debug!("Established new connection from peer");
                    Ok(Some(IncomingJsonRpcRequest::new(conn)))
                }
                Err(err) => {
                    debug!("Error when establishing new peer connection");
                    Err(Error::ServerError(err.to_string()))
                }
            },
            None => Ok(None),
        }
    }
}

// Stream of incoming JSON-RPC request messages
pub struct IncomingJsonRpcRequest {
    quinn_connection: quinn::Connection,
}

impl IncomingJsonRpcRequest {
    pub(crate) fn new(quinn_connection: quinn::Connection) -> Self {
        Self { quinn_connection }
    }

    // Each stream initiated by the client constitutes a new request
    pub async fn get_next(&mut self) -> Result<Option<(JsonRpcRequest, JsonRpcResponseStream)>> {
        let (send, recv) = match self.quinn_connection.accept_bi().await {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                // This seems to be Quinn's mechanism for closing a connection. Not sure
                // why they treat it as an error. For our purposes we return an Ok result
                // with no request to process.
                debug!("Connection terminated");
                return Ok(None);
            }
            Err(err) => {
                warn!("Failed to read incoming request: {}", err);
                return Err(Error::ServerError(format!(
                    "Failed to accept incoming bi-stream: {err}"
                )));
            }
            Ok(bi_stream) => bi_stream,
        };

        // Read the request, which must be at most 64KiB.
        match recv.read_to_end(64 * 1024).await {
            Ok(req_bytes) => {
                debug!("Received request...");
                match parse_jsonrpc_request(req_bytes) {
                    Ok(jsonrpc_req) => {
                        debug!("Request parsed successfully");
                        Ok(Some((jsonrpc_req, JsonRpcResponseStream::new(send))))
                    }
                    Err(err_response) => {
                        let warning = err_response
                            .clone()
                            .error
                            .ok_or_else(|| {
                                Error::ServerError(
                                    "The response should be populated with an error".to_string(),
                                )
                            })?
                            .message;
                        warn!("Failed to parse request as JSON-RPC: {}", warning);
                        Err(Error::JsonRpcRequestParsingError(
                            err_response,
                            JsonRpcResponseStream::new(send),
                        ))
                    }
                }
            }
            Err(err) => {
                warn!("Failed to read request: {}", err);
                Err(Error::ServerError(format!("Failed to read request: {err}")))
            }
        }
        //}
        //}
    }
}

// Stream of outgoing JSON-RPC responses
#[derive(Debug)]
pub struct JsonRpcResponseStream {
    quinn_send_stream: quinn::SendStream,
}

impl JsonRpcResponseStream {
    pub(crate) fn new(quinn_send_stream: quinn::SendStream) -> Self {
        Self { quinn_send_stream }
    }

    // Write a JsonRpcResponse into the current connection's sending stream
    pub async fn respond(&mut self, response: &JsonRpcResponse) -> Result<()> {
        let serialised_res = serde_json::to_string(response)
            .map_err(|err| Error::ServerError(format!("Failed to serialise response: {err:?}")))?;

        self.quinn_send_stream
            .write_all(&serialised_res.into_bytes())
            .await
            .map_err(|err| {
                Error::ServerError(format!(
                    "Failed to write entire buffer to response stream: {err}"
                ))
            })
    }

    // Gracefully finish current connection's stream
    pub async fn finish(&mut self) -> Result<()> {
        self.quinn_send_stream.finish().await.map_err(|err| {
            Error::ServerError(format!(
                "Failed to shutdown the response stream gracefully: {err}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ServerEndpoint, ALPN_QUIC_HTTP};
    use assert_fs::prelude::*;
    use color_eyre::{eyre::eyre, Result};
    use std::str;

    #[test]
    fn new_should_return_configured_endpoint() -> Result<()> {
        let tmp_dir = assert_fs::TempDir::new()?;
        let cert_file = tmp_dir.child("cert.der");
        let key_file = tmp_dir.child("key.der");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        cert_file.write_binary(cert.serialize_der()?.as_slice())?;
        key_file.write_binary(cert.serialize_private_key_der().as_slice())?;

        let endpoint = ServerEndpoint::new(cert_file.path(), key_file.path(), None)?;

        assert_eq!(endpoint.idle_timeout, 18000);
        assert_eq!(
            str::from_utf8(&endpoint.crypto_config.alpn_protocols[0])?,
            str::from_utf8(ALPN_QUIC_HTTP)?
        );

        Ok(())
    }

    #[test]
    fn new_should_use_supplied_idle_timeout() -> Result<()> {
        let tmp_dir = assert_fs::TempDir::new()?;
        let cert_file = tmp_dir.child("cert.der");
        let key_file = tmp_dir.child("key.der");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        cert_file.write_binary(cert.serialize_der()?.as_slice())?;
        key_file.write_binary(cert.serialize_private_key_der().as_slice())?;

        let endpoint = ServerEndpoint::new(cert_file.path(), key_file.path(), Some(10000))?;

        assert_eq!(endpoint.idle_timeout, 10000);

        Ok(())
    }

    #[test]
    fn new_should_ensure_valid_der_cert_is_used() -> Result<()> {
        let tmp_dir = assert_fs::TempDir::new()?;
        let cert_file = tmp_dir.child("cert.der");
        let key_file = tmp_dir.child("key.der");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        cert_file.write_binary(b"this isn't really a DER certificate")?;
        key_file.write_binary(cert.serialize_private_key_der().as_slice())?;

        let result = ServerEndpoint::new(cert_file.path(), key_file.path(), Some(10000));

        // For some reason you can't call `unwrap_err` on this result, so the check needs to be
        // more verbose.
        match result {
            Ok(_) => return Err(eyre!("this test case should return an error")),
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    "ServerError: A valid certificate must be supplied"
                );
            }
        }

        Ok(())
    }
}
