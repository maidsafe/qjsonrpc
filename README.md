# JSON-RPC and QUIC

| [MaidSafe website](https://maidsafe.net) | [Safe Dev Forum](https://forum.safedev.org) | [Safe Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Description

This crate provides the implementation of [JSON-RPC](https://www.jsonrpc.org/) over [QUIC](https://en.wikipedia.org/wiki/QUIC), which is required by the [Authenticator daemon communication protocol](https://github.com/maidsafe/sn_authd).

This crate exposes a minimised set of functions which are used by other crates to implement the Authenticator daemon communication protocol. On one hand the [`sn_api`](https://github.com/maidsafe/sn_api) makes use of it to be able to send JSON-RPC messages to the [`authd`](https://github.com/maidsafe/sn_authd) over QUIC, and on the other hand the `sn_authd` makes use of it to accept those requests from clients, generating and sending back a JSON-RPC response over QUIC. Please refer to the [sn_authd README](https://github.com/maidsafe/sn_authd/blob/master/README.md) to see some examples of these types of requests/responses.

## Further Help

You can discuss development-related questions on the [Safe Dev Forum](https://forum.safedev.org/).
If you are just starting to develop an application for the Safe Network, it's very advisable to visit the [Safe Network Dev Hub](https://hub.safedev.org) where you will find a lot of relevant information.

## License

This Safe Network library is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) https://opensource.org/licenses/MIT) at your option.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
