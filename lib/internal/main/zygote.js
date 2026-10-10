'use strict';

// Prototype fork server. The zygote has no entry script: it runs the
// --require and --import preloads, waits until the event loop is idle, then
// serves forever.
// Only forked children ever return from binding.serve(); each one turns itself
// into the program a client asked for.

const {
  ArrayPrototypeJoin,
  ArrayPrototypePush,
  ArrayPrototypePushApply,
  ArrayPrototypeSlice,
  ArrayPrototypeSplice,
  Float64Array,
  ObjectDefineProperty,
  ObjectKeys,
  RegExpPrototypeExec,
  RegExpPrototypeSymbolReplace,
  SafeSet,
  SetPrototypeHas,
  StringPrototypeIndexOf,
  StringPrototypeSlice,
  globalThis,
} = primordials;

const {
  prepareMainThreadExecution,
  markBootstrapComplete,
} = require('internal/process/pre_execution');
const { getOptionValue } = require('internal/options');
const { emitExperimentalWarning, getCWDURL } = require('internal/util');

prepareMainThreadExecution(false);
markBootstrapComplete();
emitExperimentalWarning('--experimental-zygote');

// A Unix domain socket path, or `host:port` for TCP.
const address = getOptionValue('--experimental-zygote');

// Request modes, see src/node_zygote.cc. With kModeScript argv[0] is the main
// module; otherwise it is the code passed to -e (kModeEval) or -p (kModePrint).
const kModeScript = 0;
const kModePrint = 2;
// Same as kInvalidRequestExitCode in src/node_zygote.cc.
const kInvalidRequestExitCode = 125;

// --import preloads run once, here, like --require ones. These are the URLs
// they resolved to, for useZygoteImports().
const importURLs = [];
if (getOptionValue('--import').length > 0) {
  const { runEntryPointWithESMLoader } = require('internal/modules/run_main');
  // Imports the preloads, then calls back.
  runEntryPointWithESMLoader((cascadedLoader) => {
    const parentURL = getCWDURL().href;
    for (const specifier of getOptionValue('--import')) {
      const request = { __proto__: null, specifier, attributes: { __proto__: null } };
      ArrayPrototypePush(importURLs, cascadedLoader.resolveSync(parentURL, request).url);
    }
  });
}

// 'beforeExit' fires once the loop has drained, i.e. once the preloads have
// settled and no request is pending on the threadpool.
process.once('beforeExit', serve);

function serve() {
  const binding = internalBinding('zygote');
  warnAboutInheritedResources(binding);
  // For TCP, serve() takes NODE_ZYGOTE_TOKEN out of the environment itself.
  const {
    0: pid, 1: cwd, 2: argv, 3: env, 4: mode,
  } = binding.serve(address);
  // Start the program in its own turn of the event loop rather than nested in
  // this 'beforeExit' listener, as if it had been run directly.
  const { setImmediate } = require('timers');
  setImmediate(becomeClientProgram, binding, pid, cwd, argv, env, mode);
}

// A program runs the --import preloads as part of starting up, resolved from
// its working directory, which is the client's. Give it the URLs they
// resolved to in the zygote instead: its ESM loader then finds the modules
// that the zygote evaluated, and does not run them again.
function useZygoteImports() {
  if (importURLs.length === 0) return;
  // The options are cached, and this is the array that the loader reads.
  const imports = getOptionValue('--import');
  ArrayPrototypeSplice(imports, 0, imports.length);
  ArrayPrototypePushApply(imports, importURLs);
}

// Whatever the preloads left open, unref'd, every program inherits. That is
// sometimes intended (a timer that flushes metrics), but a listening socket,
// for one, would accept connections in every program.
function warnAboutInheritedResources(binding) {
  const resources = binding.getInheritedHandles();
  const { timerListMap } = require('internal/timers');
  if (ObjectKeys(timerListMap).length > 0) ArrayPrototypePush(resources, 'Timeout');
  if (resources.length === 0 || !getOptionValue('--warnings')) return;
  // Synchronously, like process.emitWarning() output: serve() never returns
  // in the zygote, so a warning emitted on a later tick would never appear.
  process._rawDebug(
    `(node:${process.pid}) Warning: Every program run by this zygote inherits what the ` +
    `preloads left open: ${ArrayPrototypeJoin(resources, ', ')}. Close what programs must not share.`);
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
  const zygoteStdio = internalBinding('process_methods').resetStdioForTesting();
  // Preloads may still hold those streams. Most use fds 0-2 directly, which
  // already are the client's. For a TTY, libuv reopened the terminal as
  // another descriptor: replace that with the client's, so that the stream
  // reaches the client and the program cannot use the zygote's terminal.
  for (const stream of zygoteStdio) {
    const fd = stream?.fd;
    const handleFd = stream?._handle?.fd;
    if (fd >= 0 && fd <= 2 && handleFd > 2) binding.replaceFd(fd, handleFd);
  }
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
  try {
    process.chdir(cwd);
  } catch (err) {
    // The client's working directory went away after the client read it.
    process._rawDebug(`node: cannot change to ${cwd}: ${err.message}`);
    process.reallyExit(kInvalidRequestExitCode);
  }
  // Node.js read these environment variables while it started the zygote.
  // Read them again from the client's environment.
  require('internal/modules/cjs/loader').Module._initPaths();  // NODE_PATH, HOME
  require('internal/util/debuglog').initializeDebugEnv(process.env.NODE_DEBUG);

  reseedRandomness(binding);
  useZygoteImports();

  process.execArgv = stripZygoteOptions(process.execArgv);

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

// Options that only make sense for the zygote itself. Subprocesses spawned
// with process.execArgv must not become zygotes or re-run the preloads (whose
// relative paths were resolved against the zygote's cwd, not the client's).
const kZygoteOnlyOptions = new SafeSet([
  '--experimental-zygote',
  '--require',
  '-r',
]);

// Returns `execArgv` without kZygoteOnlyOptions and their values.
function stripZygoteOptions(execArgv) {
  const result = [];
  for (let i = 0; i < execArgv.length; i++) {
    const arg = execArgv[i];
    // Normalize the name the way OptionsParser::Parse() does: only options
    // starting with `--` accept `--name=value`, and `_` is the same as `-`.
    const equalsIndex = arg[1] === '-' ? StringPrototypeIndexOf(arg, '=') : -1;
    const name = equalsIndex === -1 ?
      arg : StringPrototypeSlice(arg, 0, equalsIndex);
    const normalized = `${StringPrototypeSlice(name, 0, 2)}${
      RegExpPrototypeSymbolReplace(/_/g, StringPrototypeSlice(name, 2), '-')}`;
    if (!SetPrototypeHas(kZygoteOnlyOptions, normalized)) {
      ArrayPrototypePush(result, arg);
      continue;
    }
    // Without `=`, the value is the next argument. OptionsParser::Parse()
    // rejects values that start with `-`, so the next argument is always the
    // value and never another option.
    if (equalsIndex === -1) i++;
  }
  return result;
}

function reseedRandomness(binding) {
  // Every child inherits the zygote's Math.random() state. V8 has no API to
  // reseed it, so replace it with a batch-refilled CSPRNG-backed version.
  // Known gaps, accepted and documented for --experimental-zygote: references
  // to the original Math.random saved before this point (by preloads, or by
  // internals through the MathRandom primordial) and Math.random() in contexts
  // created later (vm, ShadowRealm), which V8 seeds from the isolate's random
  // number generator, still produce the same sequence in every child.
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
