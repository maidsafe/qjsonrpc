// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ClientError: {0}")]
    ClientError(String),
    #[error("ServerError: {0}")]
    ServerError(String),
    #[error("RemoteEndpointError: {0}")]
    RemoteEndpointError(String),
    #[error("GeneralError: {0}")]
    GeneralError(String),
    #[error("An error occurred configuring crypto options")]
    CryptoConfigError(#[from] rustls::Error),
    #[error("An error occurred parsing idle timeout for transport config")]
    IdleTimeoutParsingError(#[from] quinn_proto::VarIntBoundsExceeded),
    #[error("An error occurred configuring client to use certificates")]
    Webpki(#[from] webpki::Error),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::GeneralError(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
