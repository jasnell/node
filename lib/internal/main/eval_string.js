'use strict';

// User passed `-e` or `--eval` arguments to Node without `-i` or
// `--interactive`.

const {
  globalThis,
} = primordials;

const {
  prepareMainThreadExecution,
  markBootstrapComplete,
} = require('internal/process/pre_execution');
const { evalEntryPointString } = require('internal/process/execution');
const { addBuiltinLibsToObject } = require('internal/modules/helpers');
const { getOptionValue } = require('internal/options');

prepareMainThreadExecution();
addBuiltinLibsToObject(globalThis, '<eval>');
markBootstrapComplete();

evalEntryPointString(getOptionValue('--eval'), getOptionValue('--print'));
