// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod client_endpoint;
mod errors;
mod jsonrpc;
mod server_endpoint;
mod utils;

use std::time::Duration;

const ALPN_QUIC_HTTP: &[u8] = b"hq-24";

/// Default idle timeout for endpoint transfer config.
///
/// Ostensibly a little inside the 20s that a lot of routers might cut off at.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(18);

pub use client_endpoint::ClientEndpoint;
pub use errors::{Error, Result};
pub use server_endpoint::{
    IncomingConn, IncomingJsonRpcRequest, JsonRpcResponseStream, ServerEndpoint,
};

pub use jsonrpc::{
    JsonRpcRequest, JsonRpcResponse, JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS,
    JSONRPC_METHOD_NOT_FOUND,
};
