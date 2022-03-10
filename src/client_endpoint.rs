// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{jsonrpc::parse_jsonrpc_response, Error, JsonRpcRequest, Result, ALPN_QUIC_HTTP};
use crate::utils;
use log::debug;
use quinn::Endpoint;
use rustls::{ClientConfig, KeyLogFile, RootCertStore};
use serde::de::DeserializeOwned;
use std::{fs, path::Path, sync::Arc, time::Instant};
use url::Url;

/// A QUIC Client Endpoint for using JSON-RPC.
///
/// Based on the QUINN library's implementation of QUIC.
///
/// The `quinn::ClientConfig` struct keeps all its state private after it's been set, which is a
/// pain for unit testing. The `rustls::ClientConfig` exposes a couple of fields you can use to
/// verify configuration has been set correctly. That's the reason the additional `crypto_config`
/// and `idle_timeout` fields have been added; however, it could be beneficial for users of
/// `ClientEndpoint` to be able to read these fields.
///
/// Strictly speaking of course, it would still be possible for `idle_timeout` in this struct and
/// the private idle timeout to be set to different values, but there's not much we can do if the
/// `quinn` developers choose to not expose the information.
pub struct ClientEndpoint {
    config: quinn::ClientConfig,
    #[allow(dead_code)]
    crypto_config: rustls::ClientConfig,
    #[allow(dead_code)]
    idle_timeout: u64,
}

impl ClientEndpoint {
    /// Create a new `ClientEndpoint` instance.
    ///
    /// The path of a certificate is required.
    ///
    /// An optional idle timeout can be specified in milliseconds; otherwise a default of 18
    /// seconds will be used.
    ///
    /// If `enable_keylog` is `true`, key logging will be output to the path specified by the
    /// `SSLKEYLOGFILE` environment variable, which is required to be set.
    pub fn new<P: AsRef<Path>>(
        cert_path: P,
        idle_timeout: Option<u64>,
        enable_keylog: bool,
    ) -> Result<Self> {
        let cert = fs::read(&cert_path)
            .map_err(|err| Error::ClientError(format!("Failed to read certificate: {}", err)))?;
        let mut store = RootCertStore::empty();
        let (added, _) = store.add_parsable_certificates(vec![cert].as_slice());
        if added != 1 {
            return Err(Error::ClientError(
                "A valid certificate must be supplied".to_string(),
            ));
        }

        let mut client_crypto = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(store)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![ALPN_QUIC_HTTP.to_vec()];
        if enable_keylog {
            match std::env::var("SSLKEYLOGFILE") {
                Ok(_) => client_crypto.key_log = Arc::new(KeyLogFile::new()),
                Err(_) => {
                    return Err(Error::ClientError(
                        "To enable key logging the SSLKEYLOGFILE environment variable must be set."
                            .to_string(),
                    ))
                }
            }
        }

        let mut config = quinn::ClientConfig::new(Arc::new(client_crypto.clone()));
        let (transport, timeout) = utils::new_transport_cfg(idle_timeout)?;
        config.transport = Arc::new(transport);
        Ok(Self {
            config,
            crypto_config: client_crypto,
            idle_timeout: timeout,
        })
    }

    pub fn bind(&self) -> Result<OutgoingConn> {
        let socket_addr = "[::]:0".parse().map_err(|err| {
            Error::ClientError(format!("Failed to parse client endpoint address: {}", err))
        })?;
        let mut endpoint = Endpoint::client(socket_addr)?;
        endpoint.set_default_client_config(self.config.clone());
        Ok(OutgoingConn::new(endpoint))
    }
}

// Outgoing QUIC connections
pub struct OutgoingConn {
    pub quinn_endpoint: quinn::Endpoint,
}

impl OutgoingConn {
    pub(crate) fn new(quinn_endpoint: quinn::Endpoint) -> Self {
        Self { quinn_endpoint }
    }

    // Connect to a remote peer to send JSON-RPC requests
    // dest_endpoint: QUIC destination endpoint URL
    // cert_host: Override hostname used for certificate verification
    pub async fn connect(
        &mut self,
        dest_endpoint: &str,
        cert_host: Option<&str>,
    ) -> Result<OutgoingJsonRpcRequest> {
        let start = Instant::now();
        let url = Url::parse(dest_endpoint).map_err(|_| {
            Error::ClientError("Failed to parse remote end point address".to_string())
        })?;
        let remote = url
            .socket_addrs(|| None)
            .map_err(|_| Error::ClientError("Invalid remote end point address".to_string()))?[0];
        let host = cert_host
            .as_ref()
            .map_or_else(|| url.host_str(), |x| Some(x))
            .ok_or_else(|| Error::ClientError("No certificate hostname specified".to_string()))?;

        let new_conn = self
            .quinn_endpoint
            .connect(remote, host)
            .map_err(|err| {
                Error::ClientError(format!(
                    "Failed when attempting to create a connection with remote QUIC endpoint: {}",
                    err
                ))
            })?
            .await
            .map_err(|err| {
                Error::ClientError(format!(
                    "Failed to establish connection with remote QUIC endpoint: {}",
                    err
                ))
            })?;

        debug!(
            "Connected with remote QUIC endpoint at {:?}",
            start.elapsed()
        );
        let quinn::NewConnection {
            connection: conn, ..
        } = { new_conn };

        Ok(OutgoingJsonRpcRequest::new(conn))
    }
}

// Stream of outgoing JSON-RPC request messages
pub struct OutgoingJsonRpcRequest {
    quinn_connection: quinn::Connection,
}

impl OutgoingJsonRpcRequest {
    pub(crate) fn new(quinn_connection: quinn::Connection) -> Self {
        Self { quinn_connection }
    }

    // Send a JSON_RPC request to the remote peer on current QUIC connection,
    // awaiting for a JSON-RPC response which result is of type T
    // method: JSON-RPC request method
    // params: JSON-RPC request params
    pub async fn send<T>(&mut self, method: &str, params: serde_json::Value) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let (mut send, recv) = self.quinn_connection.open_bi().await.map_err(|err| {
            Error::ClientError(format!("Failed to open communication stream: {}", err))
        })?;

        let jsonrpc_req = JsonRpcRequest::new(method, params);

        let serialised_req = serde_json::to_string(&jsonrpc_req).map_err(|err| {
            Error::ClientError(format!("Failed to serialise request to be sent: {}", err))
        })?;

        // Send request over QUIC, and await for JSON-RPC response
        send.write_all(serialised_req.as_bytes())
            .await
            .map_err(|err| Error::ClientError(format!("Failed to send request: {}", err)))?;

        send.finish().await.map_err(|err| {
            Error::ClientError(format!(
                "Failed to gracefully shutdown communication stream: {}",
                err
            ))
        })?;

        debug!("Request sent to remote endpoint");
        let received_bytes = recv
            .read_to_end(usize::max_value())
            .await
            .map_err(|err| Error::ClientError(format!("Response not received: {}", err)))?;

        self.quinn_connection.close(0u32.into(), b"");

        parse_jsonrpc_response(received_bytes.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ClientEndpoint, ALPN_QUIC_HTTP};
    use assert_fs::prelude::*;
    use color_eyre::{eyre::eyre, Result};
    use std::str;

    #[test]
    fn new_should_return_configured_endpoint() -> Result<()> {
        let tmp_dir = assert_fs::TempDir::new()?;
        let cert_file = tmp_dir.child("cert.der");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        cert_file.write_binary(cert.serialize_der()?.as_slice())?;

        let endpoint = ClientEndpoint::new(cert_file.path(), None, false)?;

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

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        cert_file.write_binary(cert.serialize_der()?.as_slice())?;

        let endpoint = ClientEndpoint::new(cert_file.path(), Some(10000), false)?;

        assert_eq!(endpoint.idle_timeout, 10000);

        Ok(())
    }

    #[test]
    fn new_should_ensure_env_var_is_set_when_key_logging_is_enabled() -> Result<()> {
        let tmp_dir = assert_fs::TempDir::new()?;
        let cert_file = tmp_dir.child("cert.der");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        cert_file.write_binary(cert.serialize_der()?.as_slice())?;

        let result = ClientEndpoint::new(cert_file.path(), None, true);

        // For some reason you can't call `unwrap_err` on this result, so the check needs to be
        // more verbose.
        match result {
            Ok(_) => return Err(eyre!("this test case should return an error")),
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    "ClientError: To enable key logging the SSLKEYLOGFILE environment variable \
                    must be set."
                );
            }
        }

        Ok(())
    }

    #[test]
    fn new_should_ensure_valid_der_cert_is_used() -> Result<()> {
        let tmp_dir = assert_fs::TempDir::new()?;
        let cert_file = tmp_dir.child("cert.der");
        cert_file.write_binary(b"this isn't really a DER certificate")?;

        let result = ClientEndpoint::new(cert_file.path(), None, false);

        // For some reason you can't call `unwrap_err` on this result, so the check needs to be
        // more verbose.
        match result {
            Ok(_) => return Err(eyre!("this test case should return an error")),
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    "ClientError: A valid certificate must be supplied"
                );
            }
        }

        Ok(())
    }
}
