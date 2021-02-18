'use strict';

const {
  ArrayIsArray,
  ArrayPrototypeFilter,
  ArrayPrototypeForEach,
  ArrayPrototypeJoin,
  ArrayPrototypePush,
  StringPrototypeIndexOf,
  StringPrototypeSlice,
  StringPrototypeSplit,
  StringPrototypeStartsWith,
  ObjectCreate,
} = primordials;

const {
  validateObject,
  validateString,
} = require('internal/validators');

const {
  codes: {
    ERR_CRYPTO_CUSTOM_ENGINE_NOT_SUPPORTED,
    ERR_INVALID_ARG_VALUE,
    ERR_INVALID_ARG_TYPE,
  },
} = require('internal/errors');

const {
  crypto: {
    TLS1_2_VERSION,
    TLS1_3_VERSION,
  }
} = internalBinding('constants');

// Example:
// C=US\nST=CA\nL=SF\nO=Joyent\nOU=Node.js\nCN=ca1\nemailAddress=ry@clouds.org
function parseCertString(s) {
  const out = ObjectCreate(null);
  ArrayPrototypeForEach(StringPrototypeSplit(s, '\n'), (part) => {
    const sepIndex = StringPrototypeIndexOf(part, '=');
    if (sepIndex > 0) {
      const key = StringPrototypeSlice(part, 0, sepIndex);
      const value = StringPrototypeSlice(part, sepIndex + 1);
      if (key in out) {
        if (!ArrayIsArray(out[key])) {
          out[key] = [out[key]];
        }
        ArrayPrototypePush(out[key], value);
      } else {
        out[key] = value;
      }
    }
  });
  return out;
}

function getDefaultEcdhCurve() {
  // We do it this way because DEFAULT_ECDH_CURVE can be
  // changed by users, so we need to grab the current
  // value, but we want the evaluation to be lazy.
  return require('tls').DEFAULT_ECDH_CURVE || 'auto';
}

function getDefaultCiphers() {
  // We do it this way because DEFAULT_CIPHERS can be
  // changed by users, so we need to grab the current
  // value, but we want the evaluation to be lazy.
  return require('tls').DEFAULT_CIPHERS;
}

function addCACerts(context, certs) {
  ArrayPrototypeForEach(certs, (cert) => {
    validateKeyOrCertOption('ca', cert);
    context.addCACert(cert);
  });
}

function setCerts(context, certs) {
  ArrayPrototypeForEach(certs, (cert) => {
    validateKeyOrCertOption('cert', cert);
    context.setCert(cert);
  });
}

function validateKeyOrCertOption(name, value) {
  if (typeof value !== 'string' && !isArrayBufferView(value)) {
    throw new ERR_INVALID_ARG_TYPE(
      `options.${name}`,
      [
        'string',
        'Buffer',
        'TypedArray',
        'DataView'
      ],
      value
    );
  }
}

function setKey(context, key, passphrase) {
  validateKeyOrCertOption('key', key);
  if (passphrase != null)
    validateString(passphrase, 'options.passphrase');
  context.setKey(key, passphrase);
}

function processCiphers(ciphers) {
  ciphers = StringPrototypeSplit(ciphers || getDefaultCiphers(), ':');

  const cipherList =
    ArrayPrototypeJoin(
      ArrayPrototypeFilter(
        ciphers,
        (cipher) => {
          return cipher.length > 0 &&
            !StringPrototypeStartsWith(cipher, 'TLS_');
        }), ':');

  const cipherSuites =
    ArrayPrototypeJoin(
      ArrayPrototypeFilter(
        ciphers,
        (cipher) => {
          return cipher.length > 0 &&
            StringPrototypeStartsWith(cipher, 'TLS_');
        }), ':');

  // Specifying empty cipher suites for both TLS1.2 and TLS1.3 is invalid, its
  // not possible to handshake with no suites.
  if (cipherSuites === '' && cipherList === '')
    throw new ERR_INVALID_ARG_VALUE('options.ciphers', ciphers);

  return { cipherList, cipherSuites };
}

function configSecureContext(context, options = {}, name = 'options') {
  validateObject(options, name);

  const {
    ca,
    cert,
    ciphers = getDefaultCiphers(),
    clientCertEngine,
    crl,
    dhparam,
    ecdhCurve = getDefaultEcdhCurve(),
    key,
    passphrase,
    pfx,
    privateKeyIdentifier,
    privateKeyEngine,
    sessionIdContext,
    sessionTimeout,
    sigalgs,
    ticketKeys,
  } = options;

  // Add CA before the cert to be able to load cert's issuer in C++ code.
  // NOTE(@jasnell): ca, cert, and key are permitted to be falsy, so do not
  // change the checks to !== undefined checks.
  if (ca)
    addCACerts(context, ArrayIsArray(ca) ? ca : [ca]);
  else
    context.addRootCerts();

  if (cert)
    setCerts(context, ArrayIsArray(cert) ? cert : [cert]);

  // Set the key after the cert.
  // `ssl_set_pkey` returns `0` when the key does not match the cert, but
  // `ssl_set_cert` returns `1` and nullifies the key in the SSL structure
  // which leads to the crash later on.
  if (key) {
    if (ArrayIsArray(key)) {
      for (const val of key) {
        // eslint-disable-next-line eqeqeq
        const pem = (val != undefined && val.pem !== undefined ? val.pem : val);
        setKey(context, pem, val.passphrase || passphrase);
      }
    } else {
      setKey(context, key, passphrase);
    }
  }

  if (sigalgs !== undefined) {
    validateString(sigalgs, 'options.sigalgs');

    if (sigalgs === '')
      throw new ERR_INVALID_ARG_VALUE('options.sigalgs', sigalgs);

    context.setSigalgs(sigalgs);
  }

  if (privateKeyIdentifier !== undefined) {
    if (privateKeyEngine === undefined) {
      // Engine is required when privateKeyIdentifier is present
      throw new ERR_INVALID_ARG_VALUE('options.privateKeyEngine',
                                      privateKeyEngine);
    }
    if (key) {
      // Both data key and engine key can't be set at the same time
      throw new ERR_INVALID_ARG_VALUE('options.privateKeyIdentifier',
                                      privateKeyIdentifier);
    }

    if (typeof privateKeyIdentifier === 'string' &&
        typeof privateKeyEngine === 'string') {
      if (context.setEngineKey)
        context.setEngineKey(privateKeyIdentifier, privateKeyEngine);
      else
        throw new ERR_CRYPTO_CUSTOM_ENGINE_NOT_SUPPORTED();
    } else if (typeof privateKeyIdentifier !== 'string') {
      throw new ERR_INVALID_ARG_TYPE('options.privateKeyIdentifier',
                                      ['string', 'undefined'],
                                      privateKeyIdentifier);
    } else {
      throw new ERR_INVALID_ARG_TYPE('options.privateKeyEngine',
                                      ['string', 'undefined'],
                                      privateKeyEngine);
    }
  }

  if (ciphers != null)
    validateString(ciphers, 'options.ciphers');

  // Work around an OpenSSL API quirk. cipherList is for TLSv1.2 and below,
  // cipherSuites is for TLSv1.3 (and presumably any later versions). TLSv1.3
  // cipher suites all have a standard name format beginning with TLS_, so split
  // the ciphers and pass them to the appropriate API.
  const { cipherList, cipherSuites } = processCiphers(ciphers);

  context.setCipherSuites(cipherSuites);
  context.setCiphers(cipherList);

  if (cipherSuites === '' &&
      context.getMaxProto() > TLS1_2_VERSION &&
      context.getMinProto() < TLS1_3_VERSION) {
    c.context.setMaxProto(TLS1_2_VERSION);
  }

  if (cipherList === '' &&
      context.getMinProto() < TLS1_3_VERSION &&
      context.getMaxProto() > TLS1_2_VERSION) {
    context.setMinProto(TLS1_3_VERSION);
  }

  validateString(ecdhCurve, 'options.ecdhCurve');
  context.setECDHCurve(ecdhCurve);

  if (dhparam !== undefined) {
    validateKeyOrCertOption('dhparam', dhparam);
    const warning = context.setDHParam(dhparam);
    if (warning)
      process.emitWarning(warning, 'SecurityWarning');
  }

  if (crl !== undefined) {
    if (ArrayIsArray(crl)) {
      for (const val of crl) {
        validateKeyOrCertOption('crl', val);
        context.addCRL(val);
      }
    } else {
      validateKeyOrCertOption('crl', crl);
      context.addCRL(crl);
    }
  }

  if (sessionIdContext !== undefined) {
    validateString(sessionIdContext, 'options.sessionIdContext');
    context.setSessionIdContext(sessionIdContext);
  }

  if (pfx !== undefined) {
    if (ArrayIsArray(pfx)) {
      ArrayPrototypeForEach(pfx, (val) => {
        const raw = val.buf ? val.buf : val;
        const pass = val.passphrase || passphrase;
        if (pass !== undefined) {
          context.loadPKCS12(toBuf(raw), toBuf(pass));
        } else {
          context.loadPKCS12(toBuf(raw));
        }
      });
    } else if (passphrase) {
      context.loadPKCS12(toBuf(pfx), toBuf(passphrase));
    } else {
      context.loadPKCS12(toBuf(pfx));
    }
  }

  if (clientCertEngine !== undefined) {
    if (typeof c.context.setClientCertEngine !== 'function')
      throw new ERR_CRYPTO_CUSTOM_ENGINE_NOT_SUPPORTED();
    if (typeof clientCertEngine !== 'string') {
      throw new ERR_INVALID_ARG_TYPE('options.clientCertEngine',
                                      ['string', 'null', 'undefined'],
                                      clientCertEngine);
    }
    context.setClientCertEngine(clientCertEngine);
  }

  if (ticketKeys !== undefined) {
    if (!isArrayBufferView(ticketKeys)) {
      throw new ERR_INVALID_ARG_TYPE(
        'options.ticketKeys',
        [
          'Buffer',
          'TypedArray',
          'DataView'
        ],
        ticketKeys);
    }
    if (ticketKeys.byteLength !== 48) {
      throw new ERR_INVALID_ARG_VALUE(
        'options.ticketKeys',
        ticketKeys.byteLenth,
        'must be exactly 48 bytes');
    }
    context.setTicketKeys(ticketKeys);
  }

  if (sessionTimeout !== undefined) {
    validateInt32(sessionTimeout, 'options.sessionTimeout');
    context.setSessionTimeout(sessionTimeout);
  }
}

module.exports = {
  configSecureContext,
  parseCertString,
};
