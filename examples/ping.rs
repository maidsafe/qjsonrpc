// copyright 2021 maidsafe.net limited.
//
// this safe network software is licensed to you under the general public license (gpl), version 3.
// unless required by applicable law or agreed to in writing, the safe network software distributed
// under the gpl licence is distributed on an "as is" basis, without warranties or conditions of any
// kind, either express or implied. please review the licences for the specific language governing
// permissions and limitations relating to use of the safe network software.

use qjsonrpc::{ClientEndpoint, Error, JsonRpcResponse, Result, ServerEndpoint};
use serde_json::json;
use tempfile::tempdir;
use url::Url;

// hyper parameters
const LISTEN: &str = "https://localhost:33001";
const METHOD_PING: &str = "ping";
const TIMEOUT_MS: u64 = 10000;

// as per jsonrpc 2.0 spect (see: https://www.jsonrpc.org/specification)
const ERROR_METHOD_NOT_FOUND: isize = -32601;

/// Sets up a minimal client and server.
/// The client pings the server with a string
/// and the server responds with an ack
#[tokio::main]
async fn main() -> Result<()> {
    let cert_base_dir = tempdir()?;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|err| {
        Error::GeneralError(format!(
            "Failed to generate self-signed certificate: {}",
            err
        ))
    })?;
    let cert_path = &cert_base_dir.path().join("cert.der");
    let key_path = &cert_base_dir.path().join("key.der");
    let key = cert.serialize_private_key_der();
    let cert = cert
        .serialize_der()
        .map_err(|err| Error::GeneralError(format!("Failed to serialise certificate: {}", err)))?;
    std::fs::write(&cert_path, &cert)
        .map_err(|err| Error::GeneralError(format!("Failed to write certificate: {}", err)))?;
    std::fs::write(&key_path, &key)
        .map_err(|err| Error::GeneralError(format!("Failed to write private key: {}", err)))?;

    let qjsonrpc_endpoint = ServerEndpoint::new(cert_path, key_path, Some(TIMEOUT_MS))?;
    let server_task = async move {
        let listen_socket_addr = Url::parse(LISTEN)
            .map_err(|_| Error::GeneralError("Invalid endpoint address".to_string()))?
            .socket_addrs(|| None)
            .map_err(|_| Error::GeneralError("Invalid endpoint address".to_string()))?[0];

        let mut in_conn = qjsonrpc_endpoint
            .bind(&listen_socket_addr)
            .map_err(|err| Error::GeneralError(format!("Failed to bind endpoint: {}", err)))?;
        println!("[server] Bound to address '{}'", &listen_socket_addr);

        if let Some(mut in_req) = in_conn.get_next().await {
            while let Some((jsonrpc_req, mut resp_stream)) = in_req.get_next().await {
                println!("[server] Received jsonrpc request: {:?}", &jsonrpc_req);
                let resp = match jsonrpc_req.method.as_str() {
                    METHOD_PING => JsonRpcResponse::result(json!("ack"), jsonrpc_req.id),
                    _ => {
                        let msg = format!("Received unkown method '{}'", &jsonrpc_req.method);
                        JsonRpcResponse::error(msg, ERROR_METHOD_NOT_FOUND, Some(jsonrpc_req.id))
                    }
                };
                resp_stream.respond(&resp).await?;
                println!("[server] Sent jsonrpc response: {:?}", &resp);
                resp_stream.finish().await?;
                println!("[server] Connection Closed.");
            }
        }

        Ok(())
    };

    let client = ClientEndpoint::new(&cert_path, Some(TIMEOUT_MS), false)?;
    let client_task = async move {
        let mut out_conn = client.bind()?;

        let mut out_jsonrpc_req = out_conn.connect(LISTEN, None).await?;
        println!("[client] connected to {}", LISTEN);

        println!("[client] sending '{}' method to server...", METHOD_PING);
        let resp_result = out_jsonrpc_req
            .send::<String>(METHOD_PING, json!(null))
            .await?;
        println!("[client] received result '{}' from server.", &resp_result);

        Ok(())
    };

    tokio::try_join!(client_task, server_task).and_then(|_| Ok(()))
}
