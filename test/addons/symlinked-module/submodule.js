'use strict';
const common = require('../../common');
const path = require('path');
const assert = require('assert');

var destDir = path.resolve(common.tmpDir);
var mod = require(path.join(destDir, 'second', 'binding.node'));
assert(mod != null);
assert(mod.hello() == 'world');
