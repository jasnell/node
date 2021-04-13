# QUIC

## Overview

## API

### Class: `net.quic.EndpointConfig`

#### `new net.quic.EndpointConfig(options)`

* `options` {Object}
  * `address` {Object|net.SocketAddress} Identifies the local IPv4 or IPv6
    address to bind to.
    * `address` {string} The network address as either an IPv4 or IPv6 string.
      **Default**: `'127.0.0.1'` if `family` is `'ipv4'`; `'::'` if `family` is
      `'ipv6'`.
    * `family` {string} One of either `'ipv4'` or 'ipv6'`.
      **Default**: `'ipv4'`.
    * `flowlabel` {number} An IPv6 flow-label used only if `family` is `'ipv6'`.
    * `port` {number} An IP port.
  * `retryTokenExpiration` {number|bigint}
  * `tokenExpiration` {number|bigint}
  * `maxWindowOverride` {number|bigint}
  * `maxStreamWindowOverride` {number|bigint}
  * `maxConnectionsPerHost` {number|bigint}
  * `maxConnectionsTotal` {number|bigint}
  * `maxStatelessResets` {number|bigint}
  * `addressLRUSize` {number|bigint}
  * `retryLimit` {number|bigint}
  * `maxPayloadSize` {number|bigint}
  * `unacknowledgedPacketThreshold` {number|bigint}
  * `qlog` {boolean}
  * `validateAddress` {boolean}
  * `disableStatelessReset` {boolean}
  * `rxPacketLoss` {number}
  * `txPacketLoss` {number}
  * `ccAlgorithm` {string} One of either `'cubic'` or `'reno'`.
  * `udp` {Object}
    * `ipv6Only` {boolean}
    * `receiveBufferSize` {number}
    * `sendBufferSize` {number}
    * `ttl` {number}
  * `resetTokenSecret` {ArrayBuffer|TypedArray|DataView|Buffer}

### Class: `net.quic.SessionConfig`

#### `new net.quic.SessionConfig(side, options)`

* `side` {String} One of `'client'` or `'server'`
* `options` {Object}
  * `alpn` {string}
  * `dcid` {string|ArrayBuffer|TypedArray|DataView|Buffer}
  * `hostname` {string}
  * `preferredAddressStrategy` {string} One of `'use'` or `'ignore'`
  * `secure` {Object}
    * `ca` {string|string[]|Buffer|Buffer[]}
    * `cert` {string|string[]|Buffer|Buffer[]}
    * `sigalgs` {string}
    * `ciphers` {string}
    * `clientCertEngine` {string}
    * `crl` {string|string[]|Buffer|Buffer[]}
    * `dhparam` {string|Buffer}
    * `ecdhCurve` {string}
    * `key` {string|string[]|Buffer|Buffer[]|Object[]}
    * `privateKey` {Object}
      * `engine` {string}
      * `identifier` {string}
    * `passphrase` {string}
    * `pfx` {string|string[]|Buffer|Buffer[]|Object[]}
    * `secureOptions`
    * `sessionIdContext` {string}
    * `ticketKeys` {Buffer}
    * `sessionTimeout` {number}
    * `enableTLSTrace` {boolean}
    * `handshakeTimeout` {number}
    * `minDHSize` {number}
    * `pskCallback` {Function}
      * `socket` {tls.TLSSocket}
      * `identity` {string}
      * Returns: {Buffer|TypedArray|DataView}
    * `rejectUnauthorized` {boolean}
    * `requestOCSP` {boolean}
    * `requestPeerCertificate` {boolean}
    * `verifyHostnameIdentity` {boolean}
  * `transportParams` {Object}
    * `initialMaxStreamDataBidiLocal` {number|bigint}
    * `initialMaxStreamDataBidiRemote` {number|bigint}
    * `initialMaxStreamDataUni` {number|bigint}
    * `initialMaxData` {number|bigint}
    * `initialMaxStreamsBidi` {number|bigint}
    * `initialMaxStreamsUni` {number|bigint}
    * `maxIdleTimeout` {number|bigint}
    * `activeConnectionIdLimit` {number|bigint}
    * `ackDelayExponent` {number|bigint}
    * `maxAckDelay` {number|bigint}
    * `maxDatagramFrameSize` {number|bigint}
    * `disableActiveMigration` {boolean}
    * `preferredAddress` {Object}
      * `ipv4` {Object|net.SocketAddress}
        * `address` {string}
        * `port` {number}
      * `ipv6` {Object|net.SocketAddress}
        * `address` {string}
        * `port` {number}
