/* eslint no-irregular-whitespace: 0 */
'use strict';
// Refs: https://github.com/nodejs/node/pull/5950

// This test illustrates the problem that symlinked modules are unable
// to find their peer dependencies. This was fixed in #5950 but that is
// reverted because that particular way of fixing it causes too much
// breakage (breakage that was not caught by either CI or CITGM on multiple
// runs.

const common = require('../common');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const exec = require('child_process').exec;

if (common.isWindows) {
  // On Windows, creating symlinks requires admin privileges.
  // We'll only try to run symlink test if we have enough privileges.
  exec('whoami /priv', function(err, o) {
    if (err || o.indexOf('SeCreateSymbolicLinkPrivilege') == -1) {
      console.log('Skipped: insufficient privileges');
      return;
    } else {
      test();
    }
  });
} else {
  test();
}

function test() {
  common.refreshTmpDir();

  const tmpDir = common.tmpDir;

  // Creates the following structure
  // {tmpDir}
  // ├── app
  // │   ├── index.js
  // │   └── node_modules
  // │       ├── moduleA -> {tmpDir}/moduleA
  // │       └── moduleB
  // │           ├── index.js
  // │           └── package.json
  // └── moduleA
  //     ├── index.js
  //     └── package.json

  const moduleA = path.join(tmpDir, 'moduleA');
  const app = path.join(tmpDir, 'app');
  const moduleB = path.join(app, 'node_modules', 'moduleB');
  const moduleA_link = path.join(app, 'node_modules', 'moduleA');

  fs.mkdirSync(moduleA);
  fs.writeFileSync(path.join(moduleA, 'package.json'),
                   JSON.stringify({name: 'moduleA', main: 'index.js'}), 'utf8');
  fs.writeFileSync(path.join(moduleA, 'index.js'),
                   'module.exports = require(\'moduleB\');');

  fs.mkdirSync(app);
  fs.writeFileSync(path.join(app, 'index.js'),
                   '\'use strict\'; require(\'moduleA\');');
  fs.mkdirSync(path.join(app, 'node_modules'));

  fs.mkdirSync(moduleB);
  fs.writeFileSync(path.join(moduleB, 'package.json'),
                   JSON.stringify({name: 'moduleB', main: 'index.js'}), 'utf8');
  fs.writeFileSync(path.join(moduleB, 'index.js'),
                   'module.exports = 1;');

  fs.symlinkSync(moduleA, moduleA_link);

  // This should not throw, but it does
  assert.doesNotThrow(() => {
    console.log(require(path.join(app, 'index')));
  });
}
