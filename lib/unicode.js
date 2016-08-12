'use strict';

const has_icu = process.binding('config').hasIntl;
const Buffer = require('buffer').Buffer;
const kDefaultOptions = {};

if (has_icu) {
  const icu = process.binding('icu');

  const conversions = {
    'ascii': {
      'binary': (source) => {
        return source;
      },
      'utf8': (source) => {
        return source;
      },
      'ucs2': (source) => {
        return icu.convertToUcs2('us-ascii', source);
      }
    },
    'binary': {
      'ascii': (source) => {
        return icu.convert('us-ascii', 'iso8859-1', source);
      },
      'utf8': (source) => {
        return icu.convert('utf-8', 'iso8859-1', source);
      },
      'ucs2': (source) => {
        return icu.convertToUcs2('iso8859-1', source);
      }
    },
    'utf8': {
      'ascii': (source) => {
        return icu.convert('us-ascii', 'utf-8', source);
      },
      'binary': (source) => {
        return icu.convert('iso-8859-1', 'utf-8', source);
      },
      'ucs2': icu.convertToUcs2FromUtf8,
    },
    'ucs2': {
      'ascii': (source) => {
        if (source.length % 2 !== 0)
          throw new TypeError('Invalid UCS2 Buffer');
        return icu.convertFromUcs2('us-ascii', source);
      },
      'binary': (source) => {
        if (source.length % 2 !== 0)
          throw new TypeError('Invalid UCS2 Buffer');
        return icu.convertFromUcs2('iso-8859-1', source);
      },
      'utf8': (source) => {
        if (source.length % 2 !== 0)
          throw new TypeError('Invalid UCS2 Buffer');
        return icu.convertToUtf8FromUcs2(source);
      }
    }
  };

  exports.transcode = function transcode(source, from_enc, to_enc, options) {
    if (!source) return;
    if (!(source.buffer instanceof ArrayBuffer))
      throw new TypeError('"source" argument must be a Buffer');
    if (source.length === 0) return Buffer.alloc(0);

    from_enc = normalizeEncoding(from_enc);
    to_enc = normalizeEncoding(to_enc);

    if (from_enc === to_enc)
      return source;

    options = options || kDefaultOptions;
    const cnv_from = conversions[from_enc];

    if (cnv_from) {
      const cnv_to = cnv_from[to_enc];
      if (cnv_to)
        return cnv_to(source, options.lenient);
    }
    throw new Error(`Unsupported conversion: ${from_enc} to ${to_enc}`);
  };

  function normalizeEncoding(enc) {
    if (!enc) return 'utf8';
    enc = String(enc).toLowerCase();
    switch (enc) {
      case 'utf-8':
        return 'utf8';
      case 'us-ascii':
        return 'ascii';
      case 'iso-8859-1':
      case 'latin-1':
      case 'latin1':
      case 'binary':
        return 'binary';
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
      case 'utf16-le':
        return 'ucs2';
      default:
        return enc;
    }
  }

  exports.codePointAt = function(buf, pos, encoding) {
    if (pos < 0 || pos >= buf.length)
      return;
    pos >>>= 0;

    encoding = normalizeEncoding(encoding || 'utf8');

    if (encoding === 'binary' || encoding === 'ascii')
      return buf[pos];
    if (encoding !== 'utf8' && encoding !== 'ucs2')
      throw new TypeError(`Unsupported Encoding: ${encoding}`);

    return icu.getCodePointAt(buf, encoding === 'utf8', pos);
  };

  exports.charAt = function(buf, pos, encoding) {
    if (pos < 0 || pos >= buf.length)
      return;

    pos >>>= 0;
    encoding = normalizeEncoding(encoding || 'utf8');

    if (encoding === 'binary' || encoding === 'ascii')
      return String.fromCharCode(buf[pos]);
    if (encoding !== 'utf8' && encoding !== 'ucs2')
      throw new TypeError(`Unsupported Encoding: ${encoding}`);

    return icu.getCharAt(buf, encoding === 'utf8', pos);
  };

} else {
  exports.transcode =
  exports.codePointAt =
  exports.charAt =
    function noICU() {
      throw new Error('This Node.js binary was built without ICU support.');
    };
}


function utf8IsLeadByte(c) {
  return (c & 0xc0) != 0x80;
}

function utf8CountTrailBytes(c) {
  return ((c >= 0xc0) + (c >= 0xe0) + (c >= 0xf0));
}

function utf8ForwardN(buf, start, n) {
  // Assumes that buf[start] is already aligned on a lead byte
  const len = buf.length;
  n >>>= 0;
  var i = start;
  if (i >= len) throw new RangeError('index out of range');
  for (; n > 0; n--)
    i += 1 + utf8CountTrailBytes(buf[i]);
  return i;
}

// Performs a UTF-8 aware slice without error checking. start and end
// represent character offsets, not byte offsets.
exports.utf8Slice = function utf8Slice(buf, start, end) {
  if (!buf) return;
  if (!(buf.buffer instanceof ArrayBuffer))
    throw new TypeError('First argument must be a Buffer');
  if (typeof end === 'undefined') end = buf.length;
  start >>= 0;
  end >>= 0;
  start = Math.max(0, start);
  if (start === end) return buf;
  if (start > end)
    throw new RangeError(
      'The "start" offset must be less than or equal to the "end" offset');
  var startOffset = utf8ForwardN(buf, 0, start); // this is the starting offset
  var endOffset = utf8ForwardN(buf, startOffset, end - start); // ending offset
  return buf.slice(startOffset, endOffset);
};

// Counts the number of UTF-8 encoded characters in the Buffer without
// error checking. start and end are byte offsets within which to count.
// Essentially, this works by counting the UTF-8 lead bytes that just happen
// to fall within a specific buffer offset range. It's not a perfectly
// accurate method of counting length but it should be efficient.
exports.utf8Length = function utf8Length(buf, start, end) {
  if (!buf) return;
  if (!(buf.buffer instanceof ArrayBuffer))
    throw new TypeError('First argument must be a Buffer');
  if (typeof end === 'undefined') end = buf.length;
  start >>= 0;
  end >>= 0;
  start = Math.max(0, start);
  if (start === end) return 0;
  if (start > end)
    throw new RangeError(
      'The "start" offset must be less than or equal to the "end" offset');
  var count = 0;
  const len = Math.min(end, buf.length);
  while (start < len) {
    if (utf8IsLeadByte(buf[start]))
      count++;
    start = utf8ForwardN(buf, start, 1);
  }
  return count;
};
