/* eslint no-irregular-whitespace: 0 */
'use strict';

const common = require('../common');
const assert = require('assert');
const path = require('path');
const fs = require('fs');
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
  // {tmpDir}
  // ├── index.js
  // └── node_modules
  //     ├── moduleA
  //     │   ├── index.js
  //     │   └── node_modules
  //     │       └── moduleB -> {tmpDir}/node_modules/moduleB
  //     └── moduleB
  //         ├── index.js
  //         └── node_modules
  //             └── moduleA -> {tmpDir}/node_modules/moduleA

  common.refreshTmpDir();
  const tmpDir = common.tmpDir;

  const node_modules = path.join(tmpDir, 'node_modules');
  const moduleA = path.join(node_modules, 'moduleA');
  const moduleB = path.join(node_modules, 'moduleB');
  const moduleA_link = path.join(moduleB, 'node_modules', 'moduleA');
  const moduleB_link = path.join(moduleA, 'node_modules', 'moduleB');

  fs.writeFileSync(path.join(tmpDir, 'index.js'),
                   'module.exports = require(\'moduleA\');', 'utf8');
  fs.mkdirSync(node_modules);
  fs.mkdirSync(moduleA);
  fs.mkdirSync(moduleB);
  fs.writeFileSync(path.join(moduleA, 'index.js'),
                   'module.exports = {b: require(\'moduleB\')};', 'utf8');
  fs.writeFileSync(path.join(moduleB, 'index.js'),
                   'module.exports = {a: require(\'moduleA\')};', 'utf8');
  fs.mkdirSync(path.join(moduleA, 'node_modules'));
  fs.mkdirSync(path.join(moduleB, 'node_modules'));
  fs.symlinkSync(moduleA, moduleA_link);
  fs.symlinkSync(moduleB, moduleB_link);

  // Ensure that the symlinks are not followed forever...
  const obj = require(path.join(tmpDir, 'index'));
  assert.ok(obj);
  assert.ok(obj.b);
  assert.ok(obj.b.a);
  assert.ok(!obj.b.a.b);
}
