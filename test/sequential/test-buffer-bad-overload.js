'use strict';
require('../common');
const assert = require('assert');

assert.doesNotThrow(function() {
  Buffer.unsafe(10);
});

assert.throws(function() {
  new Buffer(10, 'hex');
});

assert.doesNotThrow(function() {
  new Buffer('deadbeaf', 'hex');
});
