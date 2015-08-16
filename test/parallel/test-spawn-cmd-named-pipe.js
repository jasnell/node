'use strict';

// This test is intended for Windows only
if (process.platform != 'win32') {
  console.log('Skipping Windows-only test');
  return;
}

var common = require('../common');
var assert = require('assert');

function parent() {
  var net = require('net');
  var spawn = require('child_process').spawn;

  var stdinPipeName = '\\\\.\\pipe\\test.' + process.pid + '.stdin';
  var stdoutPipeName = '\\\\.\\pipe\\test.' + process.pid + '.stdout';

  var stdinPipeServer = net.createServer(function(c) {
    console.log('stdinPipeServer connected');
    c.on('end', function() {
      console.log('stdinPipeServer disconnected');
    });
    c.end('hello');
  });
  stdinPipeServer.listen(stdinPipeName);

  var output = [];
  var gotResponse = false;

  var stdoutPipeServer = net.createServer(function(c) {
    console.log('stdoutPipeServer connected');
    c.on('data', function(x) {
      console.log('got data:', x.toString());
      output.push(x);
    });
    c.on('end', function() {
      console.log('stdoutPipeServer disconnected');
      gotResponse = (output.join('') == 'hello');
    });
  });
  stdoutPipeServer.listen(stdoutPipeName);

  var comspec = process.env['comspec'];
  if (!comspec || comspec.length == 0) {
    console.log('Failed to get COMSPEC');
    process.exit(1);
  }

  var args = ['/c', process.execPath, __filename, 'child',
              '<', stdinPipeName, '>', stdoutPipeName];

  var child = spawn(comspec, args);

  child.on('exit', function(exitCode) {
    stdinPipeServer.close();
    stdoutPipeServer.close();
    assert(exitCode == 0);
    assert(gotResponse);
    console.log('ok');
  });
}

function child() {
  process.stdin.pipe(process.stdout);
}

if (!process.argv[2]) {
  parent();
} else {
  child();
}
