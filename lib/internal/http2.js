'use strict';

const assert = require('assert');
const binding = process.binding('http2');
const constants = process.binding('constants').http2;
const EventEmitter = require('events');
const stream = require('stream');
const Readable = stream.Readable;
const Writable = stream.Writable;
const PassThrough = stream.PassThrough;
const Http2Session = binding.Http2Session;
const Http2Header = binding.Http2Header;
const Http2DataProvider = binding.Http2DataProvider;

const kType = Symbol('type');
const kSession = Symbol('session');
const kStream = Symbol('stream');
const kStreamID = Symbol('streamid');
const kOutgoingData = Symbol('outgoingData');
const kSocket = Symbol('socket');
const kHeaders = Symbol('headers');
const kTrailers = Symbol('trailers');
const kHeadersSent = Symbol('headersSent');
const kProvider = Symbol('provider');
const kChunks = Symbol('chunks');
const kFinished = Symbol('finished');
const kPaused = Symbol('paused');
const kResume = Symbol('resume');
const kBeginResponse = Symbol('begin-response');
const kEndStream = Symbol('end-stream');
const kStreams = Symbol('streams');
const kRequest = Symbol('request');
const kResponse = Symbol('response');
const kHasTrailers = Symbol('has-trailers');

const kStatusHeader = ':status';
const kMethodHeader = ':method';
const kAuthorityHeader = ':authority';
const kPathHeader = ':path';
const kSchemeHeader = ':scheme';

function HeaderStorage() {};
HeaderStorage.prototype = Object.create(null);

function assertValidSession(session) {
  if (session.type === Http2Session.INVALID)
    throw new Error('Session is no longer valid');
}

function objectToHeaders(obj) {
  const ret = [];
  if (!obj || typeof obj !== 'object' || Array.isArray(obj))
    return ret;
  const keys = Object.keys(obj);
  for (const key of keys) {
    const value = obj[key];
    if (value) {
      if (Array.isArray(value)) {
        for (var n = 0, l = value.length; n < l; n++)
          ret.push(new Http2Header(key.toLowerCase(), value[n]));
      } else {
        ret.push(new Http2Header(key.toLowerCase(), value));
      }
    }
  }
  return ret;
}

class Session extends EventEmitter {
  constructor(type, socket) {
    super();
    type |= 0;
    if (type !== Http2Session.SERVER && type !== Http2Session.CLIENT)
      throw new TypeError('Invalid Session Type');
    this[kType] = type;
    this[kSocket] = socket;
    const session = this[kSession] = new Http2Session(type);
    const streams = this[kStreams] = new Map();

    session[Http2Session.kOnSend] = (data) => {
      socket.write(data);
    };

    // Called at the beginning of a new block of headers.
    // stream is the Http2Stream object representing the
    // internal nghttp2 stream.
    // TODO: what about trailers
    session[Http2Session.kOnBeginHeaders] = (stream, cat) => {
      switch (cat) {
        case constants.NGHTTP2_HCAT_REQUEST:
          streams.set(stream.id, stream);
          if (type === Http2Session.CLIENT) {
            // Receiving request headers on the client is a protocol
            // error. Refuse the stream with NGHTTP2_PROTOCOL_ERROR
            session.rstStream(stream, constants.NGHTTP2_PROTOCOL_ERROR);
            return;
          } else {
            // A request has begun. Allocate storage for the headers
            stream[kHeaders] = new HeaderStorage();
            stream[kTrailers] = new HeaderStorage();
          }
          break;
        case constants.NGHTTP2_HCAT_RESPONSE:
          streams.set(stream.id, stream);
          if (type === Http2Session.SERVER) {
            // Receiving response headers on the server is a protocol
            // error. Refuse the stream with NGHTTP2_PROTOCOL_ERROR
            session.rstStream(steram, constants.NGHTTP2_PROTOCOL_ERROR);
            return;
          } else {
            // A response has begun, Allocate storage for the headers
            stream[kHeaders] = new HeaderStorage();
            stream[kTrailers] = new HeaderStorage();
          }
          break;
        case constants.NGHTTP2_HCAT_PUSH_RESPONSE:
          // TODO: Support push promises
          break;
        case constants.NGHTTP2_HCAT_HEADERS:
          // TODO: Trailers and other headers
          break;
      }
    }

    // Called when a header name value pair has been processed. Will
    // be called once for each header in a frame. The stream argument
    // is the Http2Stream object.
    session[Http2Session.kOnHeader] = (stream, name, value) => {
        const headers = (this[kHeadersSent]) ? stream[kTrailers] :
                                               stream[kHeaders];
        // Only store the header if space has been allocated for it.
        if (headers) {
          var existing = headers[name];
          if (!existing) {
            headers[name] = value;
            return;
          } else if (Array.isArray(existing)) {
          } else {
            headers[name] = existing = [existing];
          }
          existing.push(value);
        }
    };

    // Called when a header frame has been completely processed by nghttp2.
    // If this is a server session, it's time to dispatch the request event,
    // If this is a client session, then it's to dispatch the response event.
    session[Http2Session.kOnHeaders] = (stream) => {
      // if this is a server, emit a request
      // if this ia a client, emit a response
      switch (type) {
        // TODO: what about multiple header blocks in a single request.
        // Handle this appropriately
        case Http2Session.SERVER:
          if (!stream[kHeadersSent]) {
            stream[kHeadersSent] = true;
            stream[kRequest] = new Http2Request(this, stream);
            stream[kResponse] = new Http2Response(this, stream);
            process.nextTick(() => {
              this.emit('request', stream[kRequest], stream[kResponse]);
            });
          } else {
            // trailers are done... 
            stream[kRequest][kFinished] = true;
            stream[kRequest].end();
          }
          break;
        case Http2Session.CLIENT:
          // TODO: emit the response 
          break;
      }
    };

    // Called when a stream has been closed.
    // Currently there's not much to do here.
    session[Http2Session.kOnStreamClose] = (stream) => {
      streams.delete(stream.id);
    };

    // Called when a chunk of data has been read from a data frame.
    // For any single data frame, this may be called multiple times.
    // The data needs to be buffered until the end of the data frame.
    // Then, once the data frame is complete, any included padding
    // needs to be removed. Currently, this is not dealing with the
    // padding appropriately.
    session[Http2Session.kOnDataChunk] = (id, flags, chunk) => {
      const stream = streams.get(id);
      assert(stream);
      stream[kRequest].write(chunk);
    };

    // Called when a data frame has been completely processed. If the frame
    // includes padding, then the padding needs to be trimmed from the received
    // data before proceeding. Currently this is not handling the padding.
    // If the data EOF or end-stream flags are set, then the inbound stream
    // is closed.
    session[Http2Session.kOnData] = (stream, flags, length, padlen) => {
      // TODO: handle padding
      if (flags & constants.NGHTTP2_DATA_FLAG_EOF ||
          flags & constants.NGHTTP2_FLAG_END_STREAM) {
        stream[kRequest][kFinished] = true;
        stream[kRequest].end();
      }
    };

    session[Http2Session.kOnFrameSend] = (id, type, flags) => {
      process.nextTick(() => this.emit('frame-sent', id, type, flags));
    };

    // Currently non-op
    session[Http2Session.kOnGoaway] = (code, lastStreamID, opaqueData) => {};
    session[Http2Session.kOnRstStream] = (stream, code) => {};
    session[Http2Session.kOnPriority] = (stream) => {};
  }

  /**
   * Return the session type. 0 = server, 1 = client, -1 = invalid (destroyed)
   **/
  get type() {
    return this[kType];
  }

  /**
   * Destroy the session. This destroys the underlying nghttp2_session also,
   * freeing any of the allocated resources. Once called, the Session object
   * is no longer usable.
   **/
  destroy() {
    this[kSession].destroy();
    this[kType] = -1;
  }

  /**
   * Terminates the session by sending a GOAWAY.
   * TODO: provide a proper termination code
   **/
  terminate() {
    assertValidSession(this);
    this[kSession].terminate();
  }

  /**
   * Transmits the appropriate connection header for the session.
   * TODO: support for client connection header
   **/
  sendConnectionHeader() {
    const err = this[kSession].sendServerConnectionHeader();
    if (err) {
      throw err;
    }
  }

  /**
   * When a chunk of data is received by the Socket, the receiveData
   * method passes that data on to the underlying nghttp2_session. The
   * data argument must be a Buffer.
   **/
  receiveData(data) {
    const err = this[kSession].receiveData(data);
    if (err) {
      throw err;
    }
  }

  /**
   * Prompts the nghttp2_session to serialize and send (via callbacks) any
   * http/2 frames currently in it's outgoing queue.
   **/
  sendData() {
    const err = this[kSession].sendData();
    if (err) {
      throw err;
    }
  }

  /**
   * Sets the priority weight of the given stream
   * TODO: implement this
   */
  changeStreamPriority(stream, parent, weight, exclusive) {}

  /**
   * For flow control purposes, tell the nghttp2_session that size amount
   * of data has been consumed.
   **/
  consume(stream, size) {
    assertValidSession(this);
    stream |= 0;
    size |= 0;
    const err = this[kSession].consume(stream, size);
    if (err) {
      process.nextTick(() => this.emit('error', err));
      return;
    }
  }

  /**
   * For flow control purposes, tell the nghttp2_session that size amount
   * of data has been consumed.
   **/
  consumeSession(size) {
    assertValidSession(this);
    size |= 0;
    const err = this[kSession].consume(stream, size);
    if (err) {
      process.nextTick(() => this.emit('error', err));
      return;
    }
  }

  /**
   * For flow control purposes, tell the nghttp2_session that size amount
   * of data has been consumed.
   **/
  consumeStream(stream, size) {
    assertValidSession(this);
    stream |= 0;
    size |= 0;
    const err = this[kSession].consume(stream, size);
    if (err) {
      process.nextTick(() => this.emit('error', err));
      return;
    }
  }

  get socket() {
    return this[kSocket];
  }

  get effectiveLocalWindowSize() {
    assertValidSession(this);
    return this[kSession].getEffectiveLocalWindowSize();
  }
  
  get effectiveRecvDataLength() {
    assertValidSession(this);
    return this[kSession].getEffectiveRecvDataLength();
  }

  get lastProcStreamID() {
    assertValidSession(this);
    return this[kSession].getLastProcStreamID();
  }

  get nextStreamID() {
    assertValidSession(this);
    return this[kSession].getNextStreamID();
  }

  set nextStreamID(id) {
    assertValidSession(this);
    id |= 0;
    const ret = this[kSession].setNextStreamID(id);
    if (ret)
      throw ret;
  }

  get outboundQueueSize() {
    assertValidSession(this);
    return this[kSession].getOutboundQueueSize();
  }

  get remoteWindowSize() {
    assertValidSession(this);
    return this[kSession].getRemoteWindowSize();
  }

  set localWindowSize(size) {
    assertValidSession(this);
    size |= 0;
    const ret = this[kSession].setLocalWindowSize(size);
    if (ret)
      throw ret;
  }

  getRemoteSetting(id) {
    assertValidSession(this);
    id |= 0;
    return this[kSession].getRemoteSetting(id);
  }

  createIdleStream(stream, parent, weight, exclusive) {}
}

// ----------------------------------------------------------------------- //

exports.kSession = kSession;

/**
 * The connection listener for the Socket. Called whenever the socket detects
 * that a new connection has been established.
 **/
exports.connectionListener = function connectionListener(socket) {

  // For every connection, there is exactly one Session that must be
  // maintained for the lifetime of the socket.
  const session = socket[kSession] =  new Session(Http2Session.SERVER, socket);

  socket[kOutgoingData] = 0;

  function updateOutgoingData(delta) {
    // `outgoingData` is an approximate amount of bytes queued through all
    // inactive responses. If more data than the high watermark is queued - we
    // need to pause TCP socket/HTTP parser, and wait until the data will be
    // sent to the client.
    outgoingData += delta;
    if (socket._paused && outgoingData < socket._writableState.highWaterMark)
      return socketOnDrain();
  }

  // Set up the timeout listener
  if (this.timeout)
    socket.setTimeout(this.timeout);
  socket.on('timeout', () => {
    if (!this.emit('timeout', socket))
      socket.destroy();
  });

  // Destroy the session if the socket is destroyed
  const destroySocket = socket.destroy;
  socket.destroy = function() {
    session.destroy();
    destroySocket.apply(socket);
  };

  // Terminate the session if socket.end() is called
  const endSocket = socket.end;
  socket.end = function(data, encoding) {
    // needs to write the data, then terminate the session,
    // *then* end the socket
    socket.write(data, encoding, () => {
      session.terminate();
      // end the socket somehow
    });
  };

  socket.on('error', socketOnError);
  socket.on('close', socketOnClose);
  socket.on('end', socketOnEnd);
  socket.on('data', socketOnData);
  socket.on('resume', socketOnResume);
  socket.on('pause', socketOnPause);
  socket.on('drain', socketOnDrain);

  // 'this' is the http/2 Server object
  session.on('request', (request, response) => {
    this.emit('request', request, response);
  });

  // Now that the socket is setup, send the HTTP/2 server handshake
  session.sendConnectionHeader();
};

function socketOnError(error) {
  const session = this[kSession];
}

function socketOnClose() {
  const session = this[kSession];
}

function socketOnEnd() {
  const session = this[kSession];
}

function socketOnData(data) {
  const session = this[kSession];
  const err = session.receiveData(data);
  if (err) {
    throw err;
  }
  session.sendData();
}

function socketOnResume() {
  if (this._paused) {
    this.pause();
    return;
  }

  if (this._handle && !this._handle.reading) {
    this._handle.reading = true;
    this._handle.readStart();
  }
}

function socketOnPause() {
  if (this._handle && this._handle.reading) {
    this._handle.reading = false;
    this._handle.readStop();
  }
}

function socketOnDrain() {
  const needPause = this[kOutgoingData] > this._writableState.highWaterMark;
  if (this._paused && !needPause) {
    this._paused = false;
    this.resume();
  }
}

// --------------------------------------------------------------------- //

class Http2Response extends Writable {
  constructor(_session, stream) {
    super({});
    const session = _session[kSession];
    this[kFinished] = false;
    this[kSession] = session;
    this[kStream] = stream;
    this[kSocket] = _session.socket;
    this[kHeaders] = new HeaderStorage();
    this[kTrailers] = new HeaderStorage();
    this[kHeadersSent] = false;
    this[kChunks] = [];

    // The Http2DataProvider objects wraps a nghttp2_data_provider internally
    // that supplies outbound data to the stream. The Http2Response object is
    // a Writable stream that stores the chunks of written data into a simple
    // this[kchunks] array (currently). The Http2DataProvider object simply
    // harvests the chunks from that array. TODO: Make this more efficient,
    // perhaps by using a PassThrough stream.
    this[kProvider] = new Http2DataProvider(stream);
    // This callback is invoked from node_http2.cc while the outgoing data
    // frame is being processed. The buffer argument is a pre-allocated, fixed
    // sized buffer to read the data into. flags is an object that supports
    // two properties used to indicate if the data has concluded or not.
    // The callback must return the actual number of bytes written up to but
    // not exceeding buffer.length
    this[kProvider][Http2Session.kOnData] = (buffer, flags) => {
      const chunks = this[kChunks];
      if (chunks.length === 0) {
        if (!this[kFinished]) {
          // The end() method has not yet been called but there's
          // currently no data in the queue, defer the data frame
          // until additional data is written.
          this[kPaused] = true;
          return constants.NGHTTP2_ERR_DEFERRED;
        } else {
          // There is no more data in the queue and end() has
          // been called. Set the flags. Note: this will cause
          // an extra empty data frame to be sent. See below.
          this[kEndStream](flags);
          return 0;
        }
      } else {
        if (this[kFinished]) {
          // Finish has been called so there will
          // not be any more data queued. Set the
          // flags to avoid another data frame write.
          // Assuming that finish has been called before
          // all of the data could be harvested, this ensures
          // that we do not have to send an extra empty data
          // frame to signal the end of the data. However,
          // it's not always possible to know this in advance.
          this[kEndStream](flags);
        }
        // Consume as much of the currently buffered 
        // data as possible per data frame up to buffer.length
        return copyBuffers(buffer, chunks);
      }
    };

    // If this Writable is connected to a pipe, resume any deferred data
    // frames and initiate the response if it hasn't been initiated already.
    this.on('pipe', () => {
      this[kResume]();
      this[kBeginResponse]();
    });
    
    this.statusCode = 200;
  }

  get socket() {
    return this[kSocket];
  }

  get finished() {
    return this[kFinished];
  }

  get headersSent() {
    return this[kHeadersSent];
  }

  get statusCode() {
    return this[kHeaders][kStatusHeader] | 0;
  }

  set statusCode(code) {
    code |= 0;
    if (code < 100 || code > 999)
      throw new RangeError(`Invalid status code: ${code}`);
    this[kHeaders][kStatusHeader] = +code;
  }

  setHeader(name, value) {
    name = String(name).toLowerCase().trim();
    // Delete the current value if it's null
    if (value === undefined || value === null) {
      delete this[kHeaders][name];
      return this;
    }
    // Cannot add headers that start with the :-prefix
    if (name[0] === ':')
      throw new TypeError('Cannot add HTTP/2 pseudo-headers');
    if (Array.isArray(value)) {
      this[kHeaders][name] = value.map((i) => String(i));
    } else {
      this[kHeaders][name] = String(value);
    }
    return this;
  }

  setTrailer(name, value) {
    name = String(name).toLowerCase().trim();
    // Delete the current value if it's null
    if (value === undefined || value === null) {
      delete this[kTrailers][name];
      this[kHasTrailers] = Object.keys(this[kTrailers]).length > 0;
      return this;
    }
    this[kHasTrailers] = true;
    // Cannot add headers that start with the :-prefix
    if (name[0] === ':')
      throw new TypeError('Cannot add HTTP/2 pseudo-headers');
    if (Array.isArray(value)) {
      this[kTrailers][name] = value.map((i) => String(i));
    } else {
      this[kTrailers][name] = String(value);
    }
    return this;
  }

  addTrailers(headers) {
    var keys = Object.keys(headers);
    for (var key of keys)
      this.setTrailer(key, headers[key]);
    return this;
  }

  getHeader(name) {
    return this[kHeaders][name];
  }

  removeHeader(name) {
    delete this[kHeaders][name];
    return this;
  }

  setTimeout(msec, callback) {
    if (callback)
      this.on('timeout', callback);
    this.socket.setTimeout(msecs);
    return this;
  }

  writeContinue() {
    this[kSession].continue(this[kStream]);
  }

  writeHead(statusCode, headers) {
    this.statucCode = statusCode;
    const keys = Object.keys(headers);
    for (var key of keys)
      this.setHeader(key, headers[key]);
    return this;
  }

  _write(chunk, encoding, callback) {
    if (typeof chunk === 'string')
      chunk = Buffer.from(chunk, encoding);
    if (chunk.length > 0)
      this[kChunks].push(chunk);
    callback();
    this[kResume]();
    this[kBeginResponse]();
    this[kSession].sendData(this[kStream]);
  }

  end(data, encoding, callback) {
    if (typeof encoding === 'function') {
      callback = encoding;
      encoding = undefined;
    }
    if (data) {
      this.write(data, encoding);
      super.end(callback);
    }
    this[kFinished] = true;
    this[kResume]();
    this[kBeginResponse]();
  }

  [kBeginResponse]() {
    if (!this[kHeadersSent]) {
      this[kHeadersSent] = true;
      this[kSession].respond(this[kStream],
                             objectToHeaders(this[kHeaders]),
                             this[kProvider]);
    }
  }

  [kResume]() {
    if (this[kPaused]) {
      this[kPaused] = false;
      this[kSession].resume(this[kStream]);
      this[kSession].sendData(this[kStream]);
    }
  }

  [kEndStream](flags) {
    flags[Http2Session.kFlagEndData] = true;
    if (this[kHasTrailers]) {
      flags[Http2Session.kFlagNoEndStream] = true;
      this[kSession].sendTrailers(this[kStream],
                                  objectToHeaders(this[kTrailers]));
    } else {
      flags[Http2Session.kFlagEndStream] = true;
    }
  }
}

class Http2Request extends PassThrough {
  constructor(session, stream) {
    super({});
    this[kSession] = session[kSession];
    this[kStream] = stream;
    this[kSocket] = session.socket;
    this[kChunks] = [];
  }

  get headers() {
    return this[kStream][kHeaders];
  }

  get httpVersion() {
    return '2.0';
  }

  get socket() {
    return this[kSocket];
  }

  get trailers() {
    return null; //TODO: return the trailers
  }

  get method() {
    return this.headers[kMethodHeader];
  }

  get url() {
    return this.headers[kPathHeader];
  }

  get scheme() {
    return this.headers[kSchemeHeader];
  }

  get authority() {
    return this.headers[kAuthorityHeader];
  }

  get path() {
    return this.headers[kPathHeader];
  }

  setTimeout(msec, callback) {
    if (callback)
      this.on('timeout', callback);
    this.socket.setTimeout(msecs);
    return this;
  }
}

function copyBuffers(buffer, chunks, offset) {
  if (chunks.length === 0) return 0;
  var current = chunks[0];
  offset |= 0;
  if (current.length <= buffer.length - offset) {
    var copied = current.copy(buffer, offset, 0);
    chunks.shift();
    if (chunks.length > 0)
      copied += copyBuffers(buffer, chunks, offset + copied);
    return copied;
  } else {
    const len = buffer.length - offset;
    current.copy(buffer, offset, 0, len);
    chunks[0] = current.slice(len);
    return len;
  }
}
