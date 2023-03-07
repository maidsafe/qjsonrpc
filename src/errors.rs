// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{JsonRpcResponse, JsonRpcResponseStream};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ClientError: {0}")]
    ClientError(String),
    #[error("An error occurred configuring crypto options: {0}")]
    CryptoConfigError(#[from] rustls::Error),
    #[error("An error occurred parsing idle timeout for transport config: {0}")]
    IdleTimeoutParsingError(#[from] quinn_proto::VarIntBoundsExceeded),
    /// For use when there's a problem parsing a request that was sent to the server.
    ///
    /// The response object will indicate the problem and the stream can be used to send it back to
    /// the client.
    #[error("An error occurred while parsing incoming JSON-RPC request")]
    JsonRpcRequestParsingError(JsonRpcResponse, JsonRpcResponseStream),
    #[error("RemoteEndpointError: {0}")]
    RemoteEndpointError(String),
    #[error("ServerError: {0}")]
    ServerError(String),
    #[error("An error occurred configuring client to use certificates: {0}")]
    Webpki(#[from] webpki::Error),
    #[error("I/O error occurred: {0}")]
    IoError(#[from] std::io::Error),
}
