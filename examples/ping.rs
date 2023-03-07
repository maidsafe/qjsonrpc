// copyright 2021 maidsafe.net limited.
//
// this safe network software is licensed to you under the general public license (gpl), version 3.
// unless required by applicable law or agreed to in writing, the safe network software distributed
// under the gpl licence is distributed on an "as is" basis, without warranties or conditions of any
// kind, either express or implied. please review the licences for the specific language governing
// permissions and limitations relating to use of the safe network software.

use color_eyre::{eyre::eyre, Result};
use qjsonrpc::{ClientEndpoint, Error, JsonRpcResponse, ServerEndpoint, JSONRPC_METHOD_NOT_FOUND};
use serde_json::json;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use tracing_subscriber::EnvFilter;
use url::Url;

const LISTEN: &str = "https://localhost:33001";
const METHOD_PING: &str = "ping";
const TIMEOUT_MS: u64 = 10000;

/// A small example for running a server that can accept a ping message and send an acknowledgement
/// back to the client. The client will wait to receive a response.
///
/// Also demonstrates handling server errors related to connections and requests.
///
/// The server job will establish an incoming connection and then process one request on that
/// connection. In a real server you would probably want to wrap both the connection and request
/// processing in loops; however, in this example, we want the process to exit.
///
/// A self-signed certificate and key are generated and supplied to both client and server.
#[tokio::main]
async fn main() -> Result<()> {
    configure_logging();
    let cert_base_dir = tempdir()?;
    let (cert_path, key_path) = generate_certificates(cert_base_dir.path())?;

    let qjsonrpc_endpoint = ServerEndpoint::new(cert_path.clone(), key_path, Some(TIMEOUT_MS))?;

    let server_task = async move {
        let listen_socket_addr = Url::parse(LISTEN)
            .map_err(|_| eyre!("Invalid endpoint address"))?
            .socket_addrs(|| None)
            .map_err(|_| eyre!("Invalid endpoint address"))?[0];

        let mut in_conn = qjsonrpc_endpoint
            .bind(&listen_socket_addr)
            .map_err(|err| eyre!("Failed to bind endpoint: {err}"))?;

        println!("[server] Bound to address '{}'", &listen_socket_addr);

        match in_conn.get_next().await {
            Ok(in_req) => {
                if let Some(mut in_req) = in_req {
                    println!("[server] Processing incoming connection...");
                    match in_req.get_next().await {
                        Ok(rpc_req) => {
                            if let Some((rpc_req, mut stream)) = rpc_req {
                                println!("[server] Received request: {:?}", &rpc_req);
                                let resp = match rpc_req.method.as_str() {
                                    METHOD_PING => {
                                        JsonRpcResponse::result(json!("ACK"), rpc_req.id)
                                    }
                                    _ => JsonRpcResponse::error(
                                        format!("Unknown method '{}'", &rpc_req.method),
                                        JSONRPC_METHOD_NOT_FOUND,
                                        Some(rpc_req.id),
                                    ),
                                };
                                stream.respond(&resp).await?;
                                println!("[server] Sent response: {:?}", &resp);
                                stream.finish().await?;
                                println!("[server] Connection closed");
                            };
                        }
                        Err(err) => match err {
                            Error::JsonRpcRequestParsingError(resp, mut stream) => {
                                println!(
                                    "[server] An error occurred while parsing incoming request"
                                );
                                println!("[server] Sending error response back to client");
                                stream.respond(&resp).await?;
                                stream.finish().await?;
                                println!("[server] Connection closed");
                            }
                            _ => {
                                // Any other errors related to bad connections or receipt
                                // of data, so we can't send a response back to the client.
                                println!("[server] {err}");
                            }
                        },
                    }
                }
            }
            Err(e) => {
                println!("[server] {e}");
            }
        }

        Ok(())
    };

    let client = ClientEndpoint::new(&cert_path, Some(TIMEOUT_MS), false)?;
    let client_task = async move {
        let mut out_conn = client.bind()?;

        let mut out_jsonrpc_req = out_conn.connect(LISTEN, None).await?;
        println!("[client] Connected to {LISTEN}");

        println!("[client] Sending '{METHOD_PING}' method to server...");
        let resp_result = out_jsonrpc_req
            .send::<String>(METHOD_PING, json!(null))
            .await?;
        println!("[client] Received result '{}' from server.", &resp_result);

        Ok(())
    };

    tokio::try_join!(client_task, server_task).and_then(|_| Ok(()))
}

fn generate_certificates(cert_base_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|err| eyre!("Failed to generate self-signed certificate: {err}"))?;
    let cert_path = cert_base_dir.join("cert.der");
    let key_path = cert_base_dir.join("key.der");
    let key = cert.serialize_private_key_der();
    let cert = cert
        .serialize_der()
        .map_err(|err| eyre!("Failed to serialise certificate: {err}"))?;
    std::fs::write(&cert_path, cert).map_err(|err| eyre!("Failed to write certificate: {err}"))?;
    std::fs::write(&key_path, key).map_err(|err| eyre!("Failed to write private key: {err}"))?;
    Ok((cert_path, key_path))
}

fn configure_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_names(true)
        .with_ansi(false)
        .init();
}
