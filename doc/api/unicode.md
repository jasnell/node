# icu

    Stability: 1 - Experimental

The `unicode` module provides an interface to Unicode and Internationalization
functionality provided by the ICU4C library.

```js
const unicode = require('unicode');
```

## unicode.transcode(buf, from_enc, to_enc)

* `buf` {Buffer} A `Buffer` instance
* `from_enc` {string} The current encoding
* `to_enc` {string} The target encoding

Re-encodes the given `Buffer` from one character encoding to another. Returns
a new `Buffer` instance.

## unicode.codePointAt(buf, pos, encoding)

* `buf` {Buffer} A `Buffer` instance
* `pos` {integer} The offset position
* `encoding` The character encoding of the `Buffer` data. Default = `'utf8'`

Returns the Unicode codepoint located at the given offset in the `Buffer`. Works
even if the offset falls in the middle of a multibyte UTF-8 or UTF-16 character.

## unicode.charAt(buf, pos, encoding)

* `buf` {Buffer} A `Buffer` instance
* `pos` {integer} The offset position
* `encoding` The character encoding of the `Buffer` data. Default = `'utf8'`

Returns the character located at the given offset in the `Buffer`. Works even
if the offset falls in the middle of a multibyte UTF-8 or UTF-16 character.

## unicode.utf8Slice(buf, start, end)

* `buf` {Buffer} A `Buffer` instance
* `start` {integer} The starting character offset
* `end` {integer} The ending character offset

Performs a UTF-8 aware slice of the Buffer instance. The `start` and `end`
arguments define character offsets rather than byte offsets. Ensures that the
slice occurs at proper UTF-8 unit boundaries.

## unicode.utf8Length(buf, start, end)

* `buf` {Buffer} A `Buffer` instance
* `start` {integer} The starting byte offset
* `end` {integer} The ending byte offset

Returns the number of UTF-8 encoded codepoints in the `Buffer` instance.
