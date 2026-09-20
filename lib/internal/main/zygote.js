'use strict';

// Prototype fork server. The zygote has no entry script: it runs the
// --require preloads, waits until the event loop is idle, then serves forever.
// Only forked children ever return from binding.serve(); each one turns itself
// into the program a client asked for.

const {
  ArrayPrototypeFilter,
  ArrayPrototypeSlice,
  Float64Array,
  ObjectDefineProperty,
  ObjectKeys,
  RegExpPrototypeExec,
  StringPrototypeIndexOf,
  StringPrototypeSlice,
  StringPrototypeStartsWith,
  globalThis,
} = primordials;

const {
  prepareMainThreadExecution,
  markBootstrapComplete,
} = require('internal/process/pre_execution');
const { getOptionValue } = require('internal/options');
const { emitExperimentalWarning } = require('internal/util');

prepareMainThreadExecution(false);
markBootstrapComplete();
emitExperimentalWarning('--experimental-zygote');

const socketPath = getOptionValue('--experimental-zygote');

// Request modes, see src/node_zygote.cc. With kModeScript argv[0] is the main
// module; otherwise it is the code passed to -e (kModeEval) or -p (kModePrint).
const kModeScript = 0;
const kModePrint = 2;

// 'beforeExit' fires once the loop has drained, i.e. once the preloads have
// settled and no request is pending on the threadpool.
process.once('beforeExit', serve);

function serve() {
  const binding = internalBinding('zygote');
  const {
    0: pid, 1: cwd, 2: argv, 3: env, 4: mode,
  } = binding.serve(socketPath);
  becomeClientProgram(binding, pid, cwd, argv, env, mode);
}

function defineReadOnlyProcessProperty(name, value) {
  ObjectDefineProperty(process, name, {
    __proto__: null,
    value,
    writable: false,
    enumerable: true,
    configurable: true,
  });
}

function becomeClientProgram(binding, pid, cwd, argv, env, mode) {
  // fds 0-2 now belong to the client. Drop the streams cached for the
  // zygote's own stdio so that they are re-created, with the right type
  // (TTY, pipe, file), on first use.
  internalBinding('process_methods').resetStdioForTesting();
  const globalConsole = require('internal/console/global');
  const { initializeGlobalConsole } = require('internal/console/constructor');
  initializeGlobalConsole(globalConsole);

  defineReadOnlyProcessProperty('pid', pid);

  for (const key of ObjectKeys(process.env)) {
    delete process.env[key];
  }
  for (const entry of env) {
    const eq = StringPrototypeIndexOf(entry, '=');
    if (eq > 0) {
      process.env[StringPrototypeSlice(entry, 0, eq)] =
        StringPrototypeSlice(entry, eq + 1);
    }
  }
  process.chdir(cwd);

  reseedRandomness(binding);

  // Subprocesses spawned with process.execArgv must not become zygotes or
  // re-run the preloads.
  process.execArgv = ArrayPrototypeFilter(process.execArgv, (arg) =>
    !StringPrototypeStartsWith(arg, '--experimental-zygote') &&
    !StringPrototypeStartsWith(arg, '--require') &&
    !StringPrototypeStartsWith(arg, '-r'));

  if (mode === kModeScript) {
    const mainEntry = require('path').resolve(argv[0]);
    process.argv =
      [process.execPath, mainEntry, ...ArrayPrototypeSlice(argv, 1)];
    // Necessary to reset RegExp statics before user code runs.
    RegExpPrototypeExec(/^/, '');
    require('internal/modules/cjs/loader').Module.runMain(mainEntry);
    return;
  }

  // Same as internal/main/eval_string: `node -e <code> [args...]` has no
  // script in process.argv.
  const code = argv[0];
  const print = mode === kModePrint;
  process.argv = [process.execPath, ...ArrayPrototypeSlice(argv, 1)];
  defineReadOnlyProcessProperty('_eval', code);
  if (print) {
    defineReadOnlyProcessProperty('_print_eval', true);
  }
  const { addBuiltinLibsToObject } = require('internal/modules/helpers');
  addBuiltinLibsToObject(globalThis, '<eval>');
  require('internal/process/execution').evalEntryPointString(code, print);
}

function reseedRandomness(binding) {
  // Every child inherits the zygote's Math.random() state. V8 has no API to
  // reseed it, so replace it with a batch-refilled CSPRNG-backed version.
  // TODO: this does not cover internal callers holding primordials' MathRandom.
  const cache = new Float64Array(128);
  let available = 0;
  globalThis.Math.random = function random() {
    if (available === 0) {
      binding.fillRandom(cache);
      available = cache.length;
    }
    return cache[--available];
  };

  // crypto.randomInt() and crypto.randomUUID() serve pre-filled buffers.
  const { BuiltinModule } = require('internal/bootstrap/realm');
  if (BuiltinModule.map.get('internal/crypto/random')?.loaded) {
    require('internal/crypto/random').resetRandomCachesForFork();
  }
}
