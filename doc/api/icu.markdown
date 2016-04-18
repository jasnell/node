# icu

    Stability: 1 - Experimental

The `icu` module provides an interface to Unicode and Internationalization
functionality provided by the ICU4C library.

```js
const icu = require('icu');
```

## icu.detectEncoding(buffer)

* `buf` {Buffer} A `Buffer` instance

Applies heuristics to detect the character encoding of the `Buffer` contents.
Returns `undefined` if the encoding cannot be determined.

Returns a string.

## icu.detectEncodingString(str)

* `str` (string)

Applies heuristics to detect the character encoding of the given string.

Returns a string.

## icu.detectEncodings(buffer)

* `buf` {Buffer} A `Buffer instance`

Applies heuristics to detect the possible character encodings of the `Buffer` 
contents.

Returns an object whose keys identify the possible character encodings and
whose values are an integer value that reflects the confidence.

## icu.detectEncodingsString(str)

* `str` {string}

Applies heuristics to detect the possible character encodings of the given 
string.

Returns an object whose keys identify the possible character encodings and
whose values are an integer value that reflects the confidence.

## icu.reencode(buf, from_enc, to_enc)

* `buf` {Buffer} A `Buffer` instance
* `from_enc` {string} The current encoding
* `to_enc` {string} The target encoding

Re-encodes the given `Buffer` from one character encoding to another. Returns
a new `Buffer` instance.

## icu.codePointAt(buf, pos, encoding)

* `buf` {Buffer} A `Buffer` instance
* `pos` {integer} The offset position
* `encoding` The character encoding of the `Buffer` data. Default = `'utf8'`

Returns the Unicode codepoint located at the given offset in the `Buffer`. Works
even if the offset falls in the middle of a multibyte UTF-8 or UTF-16 character.

## icu.charAt(buf, pos, encoding)

* `buf` {Buffer} A `Buffer` instance
* `pos` {integer} The offset position
* `encoding` The character encoding of the `Buffer` data. Default = `'utf8'`

Returns the character located at the given offset in the `Buffer`. Works even
if the offset falls in the middle of a multibyte UTF-8 or UTF-16 character.

## icu.utf8Slice(buf, start, end)

* `buf` {Buffer} A `Buffer` instance
* `start` {integer} The starting character offset
* `end` {integer} The ending character offset

Performs a UTF-8 aware slice of the Buffer instance. The `start` and `end`
arguments define character offsets rather than byte offsets. Ensures that the
slice occurs at proper UTF-8 unit boundaries.

## icu.utf8Length(buf, start, end)

* `buf` {Buffer} A `Buffer` instance
* `start` {integer} The starting byte offset
* `end` {integer} The ending byte offset

Returns the number of UTF-8 encoded codepoints in the `Buffer` instance.
