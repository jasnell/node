'use strict';

const {
  initializeCallbacks,
} = internalBinding('quic');

const {
  symbols: {
    owner_symbol,
  },
} = require('internal/async_hooks');

// If the initializeCallbacks is undefined, the Node.js binary
// was built without QUIC support, in which case we
// don't want to export anything here.
if (initializeCallbacks === undefined)
  return;

// For the list of required callbacks, see the QUIC_JS_CALLBACKS
// macro in src/quic/quic.h

function onEndpointClose(context, status) {}

function onEndpointDone() {
  this[owner_symbol].destroy();
}

function onEndpointError() {}

function onSessionNew() {}

function onSessionCert() {}

function onSessionClientHello() {}

function onSessionClose() {}

function onSessionDatagram() {}

function onSessionHandshake() {}

function onSessionKeylog() {}

function onSessionPathValidation() {}

function onSessionUsePreferredAddress() {}

function onSessionQlog() {}

function onSessionOcspRequest() {}

function onSessionOcspResponse() {}

function onSessionTicket() {}

function onSessionVersionNegotiation() {}

function onStreamClose() {}

function onStreamError() {}

function onStreamReady() {}

function onStreamReset() {}

function onStreamHeaders() {}

function onStreamBlocked() {}

module.exports = {
  initializeBinding() {
    initializeCallbacks({
      onEndpointClose,
      onEndpointDone,
      onEndpointError,
      onSessionNew,
      onSessionCert,
      onSessionClientHello,
      onSessionClose,
      onSessionDatagram,
      onSessionHandshake,
      onSessionKeylog,
      onSessionPathValidation,
      onSessionUsePreferredAddress,
      onSessionQlog,
      onSessionOcspRequest,
      onSessionOcspResponse,
      onSessionTicket,
      onSessionVersionNegotiation,
      onStreamClose,
      onStreamError,
      onStreamReady,
      onStreamReset,
      onStreamHeaders,
      onStreamBlocked,
    });
  }
};
