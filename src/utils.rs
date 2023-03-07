// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::Result;
use crate::DEFAULT_IDLE_TIMEOUT;
use quinn::{IdleTimeout, VarInt};

pub fn new_transport_cfg(idle_timeout: Option<u64>) -> Result<(quinn::TransportConfig, u64)> {
    let mut transport_config = quinn::TransportConfig::default();
    let timeout = if let Some(timeout) = idle_timeout {
        transport_config.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u64(timeout)?)));
        timeout
    } else {
        let default_timeout = DEFAULT_IDLE_TIMEOUT.as_millis() as u64;
        transport_config
            .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u64(default_timeout)?)));
        default_timeout
    };
    Ok((transport_config, timeout))
}
