# QUIC

<!-- introduced_in=REPLACEME-->

> Stability: 1 - Experimental

TBD

## Examples

TBD

## Concepts

## API

### `quic.createEndpoint([options])`
<!-- YAML
added: REPLACEME
-->

* `options` {quic.EndpointConfig|quic.EndpointConfigOptions}
* Returns: {quic.Endpoint}

Creates and returns a new {quic.Endpoint}.

### Class: `Endpoint`

### Class: `Session`

### Class: `Stream`

### Class: `quic.EndpointConfig`
<!-- YAML
added: REPLACEME
-->

The `quic.EndpointConfig` is used to provide configuration options for a
new `quic.Endpoint` instance.

#### `new quic.EndpointConfig([options])`
<!-- YAML
added: REPLACEME
-->

* `options` {quic.EndpointConfigOptions}
  * `address` {net.SocketAddress|net.SocketAddressOptions} A local socket
    address to bind to. If not specified, defaults to IPv4 address `'127.0.0.0'`
    with IP port `0`.
  * `maxConnectionsPerHost` {bigint|integer} The maximum number of concurrent
    connections allowed per remote address. **Default**: `100`.
  * `maxConnectionsTotal` {bigint|integer} The maximum number of concurrent
    connections allowed. **Default**: `Number.MAX_SAFE_INTEGER`;
  * `maxStatelessResets` {bigint|integer} The maximum number of stateless resets
    the endpoint is permitted to send to a remote host. **Default**: `10`.
  * `qlog` {boolean} When `true`, configures the `Endpoint` to emit detailed
    QLog tracing information. **Default**: `false`.
  * `retryLimit` {bigint|integer} The maximum number of times the endpoint will
    attempt sending a `RETRY` packet to a remote host. **Default**: `10`
  * `resetTokenSecret` {ArrayBuffer|TypedArray|DataView|Buffer} A 16-byte secret
    that will be used when generating reset tokens. If not specified a random
    secret will be generated. **Default**: `undefined`.
  * `retryTokenExpiration` {bigint|integer} The length of time (in seconds) that
    a retry token is considered valid. **Default**: `10`.
  * `tokenExpiration` {bigint|integer} The length of time (in seconds) that
    a token is considered valid. **Default**: `3600`.
  * `udp` {Object} UDP-specific options
    * `ipv6Only` {boolean} When `true` and the endpoint is IPv6, disables
      "dual-mode" support and limits the `Endpoint` to only IPv6 traffic.
      **Default**: `false`.
    * `receiveBufferSize` {integer} The UDP receive buffer size. When set
      to `0`, uses the internal defaults. **Default**: `0`.
    * `sendBufferSize` {integer} The UDP send buffer size. When set
      to `0`, uses the internal defaults. **Default**: `0`.
    * `ttl` {integer} The maximum number of network hops UDP packets sent
      by this endpoint will be permitted to travel through. When set to
      `0`, uses the internal defaults. **Default**: `0`.
  * `validateAddress` {boolean} When `true`, instructs the `Endpoint` to perform
    explicit path validation. **Default**: `true`.
  * Advanced Options (most applications will not have reason to set these):
    * `addressLRUSize` {bigint|integer} The maximum number of recently validated
      remote host addresses the endpoint will retain. **Default**: `100`.
    * `ccAlgorithm` {string} One of either `'cubic'` or `'reno'`, specifiying
      the congestion control algorithm the `Endpoint` will use.
      **Default**: `'cubic'`.
    * `disableStatelessReset` {boolean} When `true`, disables the use of
      stateless reset tokens. **Default**: `false`.
    * `maxPayloadSize` {bigint|integer} The maximum size of a QUIC packet.
      **Default**: `1200`. The maximum payload size should never exceed the
      minimum MTU size of the network path.
    * `maxStreamWindowOverride` {bigint|integer} The maximum per-stream flow
      control window size. **Default**: `0`.
    * `maxWindowOverride` {bigint|integer} The maximum per-session flow control
      window size. **Default**: `0`.
    * `rxPacketLoss` {number} For debugging purposes only, the `rxPacketLoss`
      specifies a value between `0.0` and `1.0` indicating a probability of
      simulated packet loss. **Default**: `0.0`.
    * `txPacketLoss` {number} For debugging purposes only, the `txPacketLoss`
      specifies a value between `0.0` and `1.0` indicating a probability of
      simulated packet loss. **Default**: `0.0`.
    * `unacknowledgedPacketThreshold` {bigint|integer} The maximum number of
      unacknowledged packets that a Session will accumulate before sending an
      acknowledgement. Setting this to `0` uses the internal defaults.
      **Default**: `0`.

### Class: `quic.SessionConfig`
<!-- YAML
added: REPLACEME
-->

The `quic.SessionOptions` is used to provide configuration options for a
new `quic.Session` instance.

#### `new quic.SessionConfig([options])`
<!-- YAML
added: REPLACEME
-->

* `options` {quic.SessionConfigOptions}
  * `alpn` {string} The ALPN protocol identifier. **Default**: `h3`.
  * `hostname` {string} The SNI host name. **Dfault**: `undefined`.
  * `onSession` {Function}
    * `session` {quic.Session}
  * `preferredAddressStrategy` {string} one of either `'use'` or `'ignore'`.
    **Default**: `'use'`.
  * `secure` {Object} Options used to configure the secure TLS context:
    * `ca` {string|string[]|Buffer|Buffer[]} Optionally override the trusted CA
      certificates. Default is to trust the well-known CAs curated by Mozilla.
      Mozilla's CAs are completely replaced when CAs are explicitly specified
      using this option. The value can be a string or `Buffer`, or an `Array`
      of strings and/or `Buffer`s. Any string or `Buffer` can contain multiple
      PEM CAs concatenated together. The peer's certificate must be chainable to
      a CA trusted by the server for the connection to be authenticated. When
      using certificates that are not chainable to a well-known CA, the
      certificate's CA must be explicitly specified as a trusted or the
      connection will fail to authenticate.
      If the peer uses a certificate that doesn't match or chain to one of the
      default CAs, use the `ca` option to provide a CA certificate that the
      peer's certificate can match or chain to.
      For self-signed certificates, the certificate is its own CA, and must be
      provided.
      For PEM encoded certificates, supported types are "TRUSTED CERTIFICATE",
      "X509 CERTIFICATE", and "CERTIFICATE".
      See also [`tls.rootCertificates`][].
    * `cert` {string|string[]|Buffer|Buffer[]} Cert chains in PEM format. One
      cert chain should be provided per private key. Each cert chain should
      consist of the PEM formatted certificate for a provided private `key`,
      followed by the PEM formatted intermediate certificates (if any), in
      order, and not including the root CA (the root CA must be pre-known to
      the peer, see `ca`). When providing multiple cert chains, they do not have
      to be in the same order as their private keys in `key`. If the
      intermediate certificates are not provided, the peer will not be able to
      validate the certificate, and the handshake will fail.
    * `sigalgs` {string} Colon-separated list of supported signature algorithms.
      The list can contain digest algorithms (`SHA256`, `MD5` etc.), public key
      algorithms (`RSA-PSS`, `ECDSA` etc.), combination of both (e.g
      'RSA+SHA384') or TLS v1.3 scheme names (e.g. `rsa_pss_pss_sha512`).
      See [OpenSSL man pages][] for more info.
    * `ciphers` {string} Cipher suite specification, replacing the default. For
      more information, see [modifying the default cipher suite][]. Permitted
      ciphers can be obtained via [`tls.getCiphers()`][]. Cipher names must be
      uppercased in order for OpenSSL to accept them.
    * `clientCertEngine` {string} Name of an OpenSSL engine which can provide
      the client certificate.
    * `crl` {string|string[]|Buffer|Buffer[]} PEM formatted CRLs (Certificate
      Revocation Lists).
    * `dhparam` {string|Buffer} Diffie-Hellman parameters, required for
      [perfect forward secrecy][]. Use `openssl dhparam` to create the
      parameters. The key length must be greater than or equal to 1024 bits or
      else an error will be thrown. Although 1024 bits is permissible, use 2048
      bits or larger for stronger security. If omitted or invalid, the
      parameters are silently discarded and DHE ciphers will not be available.
    * `ecdhCurve` {string} A string describing a named curve or a colon
      separated list of curve NIDs or names, for example `P-521:P-384:P-256`,
      to use for ECDH key agreement. Set to `auto` to select the
      curve automatically. Use [`crypto.getCurves()`][] to obtain a list of
      available curve names. On recent releases, `openssl ecparam -list_curves`
      will also display the name and description of each available elliptic
      curve. **Default:** [`tls.DEFAULT_ECDH_CURVE`][].
    * `key` {string|string[]|Buffer|Buffer[]|Object[]} Private keys in PEM
      format.
      PEM allows the option of private keys being encrypted. Encrypted keys will
      be decrypted with `options.passphrase`. Multiple keys using different
      algorithms can be provided either as an array of unencrypted key strings
      or buffers, or an array of objects in the form
      `{pem: <string|buffer>[, passphrase: <string>]}`. The object form can only
      occur in an array. `object.passphrase` is optional. Encrypted keys will be
      decrypted with `object.passphrase` if provided, or `options.passphrase` if
      it is not.
    * `privateKey` {Object}
      * `engine` {string} Name of an OpenSSL engine to get private key from.
        Should be used together with `privateKeyIdentifier`.
      * `identifier` {string} Identifier of a private key managed by an OpenSSL
        engine. Should be used together with `privateKeyEngine`. Should not be
        set together with `key`, because both options define a private key in
        different ways.
    * `passphrase` {string} Shared passphrase used for a single private key
      and/or a PFX.
    * `pfx` {string|string[]|Buffer|Buffer[]|Object[]} PFX or PKCS12 encoded
      private key and certificate chain. `pfx` is an alternative to providing
      `key` and `cert` individually. PFX is usually encrypted, if it is,
      `passphrase` will be used to decrypt it. Multiple PFX can be provided
      either as an array of unencrypted PFX buffers, or an array of objects in
      the form `{buf: <string|buffer>[, passphrase: <string>]}`. The object form
      can only occur in an array. `object.passphrase` is optional. Encrypted PFX
      will be decrypted with `object.passphrase` if provided, or
      `options.passphrase` if it is not.
    * `secureOptions` {number} Optionally affect the OpenSSL protocol behavior,
      which is not usually necessary. This should be used carefully if at all!
      Value is a numeric bitmask of the `SSL_OP_*` options from
      [OpenSSL Options][].
    * `sessionIdContext` {string} Opaque identifier used by servers to ensure
      session state is not shared between applications. Unused by clients.
    * `ticketKeys` {Buffer} 48-bytes of cryptographically strong pseudo-random
      data. See [Session Resumption][] for more information.
    * `sessionTimeout` {number} The number of seconds after which a TLS session
      created by the server will no longer be resumable. See
      [Session Resumption][] for more information. **Default:** `300`.
    * `enableTLSTrace` {boolean} When `true`, enables detailed TLS debug
      tracing.
    * `handshakeTimeout` {integer} The maximum length of time (in milliseconds)
      the handshake is permitted to complete.
    * `minDHSize` {integer} Minimum size of the DH parameter in bits to accept a
      TLS connection. When a server offers a DH parameter with a size less
      than `minDHSize`, the TLS connection is destroyed and an error is thrown.
      **Default:** `1024`.
    * `pskCallback` {Function}
      * `socket` {tls.TLSSocket} the server [`tls.TLSSocket`][] instance for
        this connection.
      * `identity` {string} identity parameter sent from the client.
      * Returns: {Buffer|TypedArray|DataView} pre-shared key that must either be
        a buffer or `null` to stop the negotiation process. Returned PSK must be
        compatible with the selected cipher's digest.
      When negotiating TLS-PSK (pre-shared keys), this function is called
      with the identity provided by the client.
      If the return value is `null` the negotiation process will stop and an
      "unknown_psk_identity" alert message will be sent to the other party.
      If the server wishes to hide the fact that the PSK identity was not known,
      the callback must provide some random data as `psk` to make the connection
      fail with "decrypt_error" before negotiation is finished.
      PSK ciphers are disabled by default, and using TLS-PSK thus
      requires explicitly specifying a cipher suite with the `ciphers` option.
      More information can be found in the [RFC 4279][].
    * `pskIdentityHint` {string} optional hint to send to a client to help
      with selecting the identity during TLS-PSK negotiation. Will be ignored
      in TLS 1.3. Upon failing to set pskIdentityHint `'tlsClientError'` will be
      emitted with `'ERR_TLS_PSK_SET_IDENTIY_HINT_FAILED'` code.
    * `rejectUnauthorized` {boolean} If not `false` a server `Session`
      automatically reject clients with invalid certificates.
      **Default**: `true`.
    * `requestOCSP` {boolean} When `true`, instructs a client `Session` to
      request OCSP status details. **Default**: `false`.
    * `requestPeerCertificate` {boolean} When `true`, instructs a server
      `Session` to request a client peer certificate. **Default**: `false`.
    * `verifyHostnameIdentity` {boolean} When `true`, instructs the session to
      verify the host name identity. **Default**: `true`. Setting this to
      `false` is in violation of the QUIC specification.
  * `transportParams` {Object}
    * `initialMaxStreamDataBidiLocal` {bigint|integer}
    * `initialMaxStreamDataBidiRemote` {bigint|integer}
    * `initialMaxStreamDataUni` {bigint|integer}
    * `initialMaxData` {bigint|integer}
    * `initialMaxStreamsBidi` {bigint|integer}
    * `initialMaxStreamsUni` {bigint|integer}
    * `maxIdleTimeout` {bigint|integer}
    * `activeConnectionIdLimit` {bigint|integer}
    * `ackDelayExponent` {bigint|integer}
    * `maxAckDelay` {bigint|integer}
    * `maxDatagramFrameSize` {bigint|integer}
    * `disableActiveMigration` {boolean}
    * `preferredAddress` {Object}
      * `ipv4` {net.SocketAddress|net.SocketAddressOptions}
      * `ipv6` {net.SocketAddress|net.SocketAddressOptions}

## Notes

[`crypto.getCurves()`]: crypto.md#crypto_crypto_getcurves
[`tls.DEFAULT_ECDH_CURVE`]: tls.html#tls_tls_default_ecdh_curve
[`tls.getCiphers()`]: tls.html#tls_tls_getciphers
[`tls.rootCertificates`]: tls.html#tls_tls_rootcertificates
[`tls.TLSSocket`]: tls.html#tls_class_tls_tlssocket
[OpenSSL Options]: crypto.html#crypto_openssl_options
[OpenSSL man pages]: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set1_sigalgs_list.html
[RFC 4279]: https://tools.ietf.org/html/rfc4279
[Session Resumption]: tls.html#tls_session_resumption
[modifying the default cipher suite]: #tls_modifying_the_default_tls_cipher_suite
[perfect forward secrecy]: tls.html#tls_perfect_forward_secrecy
