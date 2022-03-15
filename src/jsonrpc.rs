// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::Error;
use rand::{self, Rng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::str;

type Result<T> = std::result::Result<T, Error>;

/// Version of JSON-RPC used in the requests
const JSONRPC_VERSION: &str = "2.0";

/// JSON-RPC error codes as defined at https://www.jsonrpc.org/specification#response_object
const JSONRPC_PARSE_ERROR: isize = -32700;
const JSONRPC_INVALID_REQUEST: isize = -32600;
pub const JSONRPC_METHOD_NOT_FOUND: isize = -32601;
pub const JSONRPC_INVALID_PARAMS: isize = -32602;
pub const JSONRPC_INTERNAL_ERROR: isize = -32603;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcRequest {
    jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
    pub id: u32,
}

impl JsonRpcRequest {
    pub fn new(method: &str, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: method.to_string(),
            params,
            id: rand::thread_rng().gen_range(0, std::u32::MAX) + 1,
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
    pub id: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct JsonRpcError {
    pub code: isize,
    pub message: String,
    pub data: String,
}

impl JsonRpcResponse {
    /// Construct a JsonRpcResponse with a result.
    ///
    /// This should be used to indicate successfully processing a request.
    pub fn result(result: serde_json::Value, id: u32) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: Some(result),
            error: None,
            id: Some(id),
        }
    }

    /// Construct a JsonRpcResponse with an error.
    ///
    /// The optional 'data' member won't be populated.
    pub fn error(message: String, code: isize, id: Option<u32>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: "".to_string(),
            }),
            id,
        }
    }

    /// Construct a JsonRpcResponse with an error.
    ///
    /// The optional 'data' member will be included in the response.
    pub fn error_with_data(message: String, data: String, code: isize, id: Option<u32>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data,
            }),
            id,
        }
    }
}

/// Parses a JSON-RPC Request object from the bytes received from the client.
///
/// A `Result` will be returned, with the `Ok` value being the `JsonRpcRequest` to be processed, or
/// the `Err` being a `JsonRpcResponse` with an error to be sent back to the client.
pub(crate) fn parse_jsonrpc_request(
    req: Vec<u8>,
) -> std::result::Result<JsonRpcRequest, JsonRpcResponse> {
    let req_payload = match String::from_utf8(req) {
        Ok(payload) => payload,
        Err(err) => {
            return Err(JsonRpcResponse::error_with_data(
                "Request payload is a malformed UTF-8 string".to_string(),
                err.to_string(),
                JSONRPC_PARSE_ERROR,
                None,
            ));
        }
    };

    let jsonrpc_req: JsonRpcRequest = match serde_json::from_str(&req_payload) {
        Ok(jsonrpc) => jsonrpc,
        Err(err) => {
            return Err(JsonRpcResponse::error_with_data(
                "Failed to deserialise request payload as a JSON-RPC message".to_string(),
                err.to_string(),
                JSONRPC_INVALID_REQUEST,
                None,
            ));
        }
    };

    Ok(jsonrpc_req)
}

// Parse bytes to construct a JsonRpcResponse expected to contain a result of type T
pub(crate) fn parse_jsonrpc_response<T>(response_bytes: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    let res_payload = std::str::from_utf8(response_bytes)
        .map_err(|err| Error::ClientError(format!("Failed to decode response data: {}", err)))?;

    match serde_json::from_str(res_payload) {
        Ok(JsonRpcResponse {
            jsonrpc,
            result: Some(r),
            ..
        }) => {
            if jsonrpc != JSONRPC_VERSION {
                Err(Error::ClientError(format!(
                    "Received response with JSON-RPC version {}. Client only supports version {}.",
                    jsonrpc, JSONRPC_VERSION
                )))
            } else {
                let result = serde_json::from_value(r).map_err(|err| {
                    Error::ClientError(format!("Failed to decode response result: {}", err))
                })?;

                Ok(result)
            }
        }
        Ok(JsonRpcResponse {
            error: Some(err), ..
        }) => {
            let mut message = err.message;
            if !err.data.is_empty() {
                message.push_str(": ");
                message.push_str(&err.data);
            }
            Err(Error::RemoteEndpointError(message))
        }
        Ok(JsonRpcResponse {
            result: None,
            error: None,
            ..
        }) => Err(Error::ClientError(
            "Received invalid JSON-RPC response with neither result or error fields populated"
                .to_string(),
        )),
        Err(err) => Err(Error::ClientError(format!(
            "Failed to parse response document: {}",
            err
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_jsonrpc_request, parse_jsonrpc_response, JsonRpcError, JSONRPC_INVALID_REQUEST,
        JSONRPC_PARSE_ERROR, JSONRPC_VERSION,
    };
    use color_eyre::{eyre::eyre, Result};
    use serde_json::json;

    #[test]
    fn parse_jsonrpc_request_should_return_json_rpc_request() -> Result<()> {
        let req = json!({
            "jsonrpc": JSONRPC_VERSION,
            "method": "test",
            "params": {
                "name": "value",
                "name2": "value2"
            },
            "id": 12345
        })
        .to_string();
        let req = req.as_bytes();
        let req = parse_jsonrpc_request(req.to_vec())
            .map_err(|err| eyre!(format!("Error: {}", err.error.unwrap().message)))?;

        assert_eq!(req.jsonrpc, JSONRPC_VERSION);
        assert_eq!(req.method, "test");
        assert_eq!(req.params["name"], "value");
        assert_eq!(req.params["name2"], "value2");
        assert_eq!(req.id, 12345);
        Ok(())
    }

    #[test]
    fn parse_jsonrpc_request_should_return_error_response_for_invalid_utf8_string() -> Result<()> {
        // Invalid byte sequence taken from the documentation:
        // https://doc.rust-lang.org/std/string/struct.String.html#method.from_utf8
        let req = vec![0_u8, 159_u8, 146_u8, 150_u8];

        let result = parse_jsonrpc_request(req);
        let error_response = result.unwrap_err();
        let error = error_response
            .error
            .ok_or_else(|| eyre!("This response should contain an error"))?;

        assert_eq!(error_response.jsonrpc, JSONRPC_VERSION);
        assert!(error_response.result.is_none());
        assert_eq!(error.code, JSONRPC_PARSE_ERROR);
        assert_eq!(error.message, "Request payload is a malformed UTF-8 string");
        assert_eq!(error.data, "invalid utf-8 sequence of 1 bytes from index 1");

        Ok(())
    }

    #[test]
    fn parse_jsonrpc_request_should_return_error_response_for_non_json_document() -> Result<()> {
        let req = "not a json document";

        let result = parse_jsonrpc_request(req.as_bytes().to_vec());

        assert!(result.is_err());
        let error_response = result.unwrap_err();
        let error = error_response
            .error
            .ok_or_else(|| eyre!("This response should contain an error"))?;

        assert_eq!(error_response.jsonrpc, JSONRPC_VERSION);
        assert!(error_response.result.is_none());
        assert_eq!(error.code, JSONRPC_INVALID_REQUEST);
        assert_eq!(
            error.message,
            "Failed to deserialise request payload as a JSON-RPC message"
        );
        assert_eq!(error.data, "expected ident at line 1 column 2");

        Ok(())
    }

    #[test]
    fn parse_jsonrpc_response_should_return_result_response() -> Result<()> {
        let resp = json!({
            "jsonrpc": JSONRPC_VERSION,
            "result": Some("ack"),
            "error": None::<JsonRpcError>,
            "id": 12345
        })
        .to_string();

        let resp = parse_jsonrpc_response::<String>(resp.as_bytes())?;

        assert_eq!(resp, "ack");

        Ok(())
    }

    #[test]
    fn parse_jsonrpc_response_should_return_error_for_wrong_jsonrpc_version() -> Result<()> {
        let resp = json!({
            "jsonrpc": "1.0",
            "result": Some("ack"),
            "error": None::<JsonRpcError>,
            "id": 12345
        })
        .to_string();

        let result = parse_jsonrpc_response::<String>(resp.as_bytes());
        assert!(result.is_err());

        assert_eq!(
            result.unwrap_err().to_string(),
            "ClientError: Received response with JSON-RPC version 1.0. Client only supports \
            version 2.0."
        );

        Ok(())
    }

    #[test]
    fn parse_jsonrpc_response_should_return_error_for_invalid_document() -> Result<()> {
        // It's invalid because the result field must be a string.
        let resp =
            r#"{ jsonrpc: "2.0", result: Some(2471293435), error: None, id: Some(2471293435) }"#;

        let result = parse_jsonrpc_response::<String>(resp.as_bytes());
        assert!(result.is_err());

        assert_eq!(
            result.unwrap_err().to_string(),
            "ClientError: Failed to parse response document: key must be a string at line 1 column 3"
        );

        Ok(())
    }

    #[test]
    fn parse_jsonrpc_response_should_return_remote_endpoint_error_for_error_response() -> Result<()>
    {
        let resp = json!({
            "jsonrpc": JSONRPC_VERSION,
            "result": None::<String>,
            "error": {
                "code": -32700,
                "message": "Request payload is a malformed UTF-8 string",
                "data": "invalid utf-8 sequence of 1 bytes from index 1"
            },
            "id": 12345
        })
        .to_string();

        let result = parse_jsonrpc_response::<String>(resp.as_bytes());
        assert!(result.is_err());

        assert_eq!(
            result.unwrap_err().to_string(),
            "RemoteEndpointError: Request payload is a malformed UTF-8 string: invalid utf-8 \
            sequence of 1 bytes from index 1"
        );

        Ok(())
    }

    #[test]
    fn parse_jsonrpc_response_should_return_client_error_for_response_with_no_result_or_error(
    ) -> Result<()> {
        let resp = json!({
            "jsonrpc": JSONRPC_VERSION,
            "result": None::<String>,
            "error": None::<JsonRpcError>,
            "id": 12345
        })
        .to_string();

        let result = parse_jsonrpc_response::<String>(resp.as_bytes());
        assert!(result.is_err());

        assert_eq!(
            result.unwrap_err().to_string(),
            "ClientError: Received invalid JSON-RPC response with neither result or error fields \
            populated"
        );

        Ok(())
    }
}
