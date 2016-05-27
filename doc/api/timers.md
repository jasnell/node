# Timers

    Stability: 3 - Locked

The `timer` module exposes a global API for scheduling functions to
be called at some future period of time. Because the timer functions are
globals, there is no need to call `require('timers')` to use the API.

The timer functions within Node.js implement a similar API as the timers API
provided by Web Browsers but use a different internal implementation that is
built around [the Node.js Event Loop][].

## Class: Immediate

This object is created internally and is returned from [`setImmediate`][]. It
can be passed to [`clearImmediate`] in order to cancel the scheduled actions.

## Class: Timeout

This object is created internally and is returned from [`setTimeout`][] and
[`setInterval`][]. It can be passed to [`clearTimeout`][] or [`clearInterval`][]
respectively in order to cancel the scheduled actions.

By default, when a timer is scheduled using either [`setTimeout`] or
[`setInterval`][], the Node.js event loop will continue running as long as the
timer is active. Each of the `Timeout` objects returned by these functions
export both `timer.ref()` and `timer.unref()` functions that can be used to
control this default behavior.

### ref()

When called, requests that the Node.js event loop *not* exit so long as the
timer is active. Calling `timer.ref()` multiple times will have no effect.

Returns a reference to the `Timeout`.

### unref()

When called, allows the Node.js event loop to exit if the timer is the only
item left in the Node.js event loop. Calling `timer.unref()` multiple times
will have no effect.

In the case of [`setTimeout`][], `timer.unref()` creates a separate timer that
will wake the Node.js event loop. Creating too many of these can adversely
impact the performance of the event.

Returns a reference to the `Timeout`.

## Scheduling Timers

A timer in Node.js is an internal construct that calls a given function after
a certain period of time. When a timer's function is called is a factor of
which method was used to create the timer and what other work the Node.js
event loop is doing.

### setImmediate(callback[, arg][, ...])

* `callback` {Function} The function to call when the timer elapses.
* `[, arg][, ...]` Optional arguments to pass when the `callback` is called.

Schedules the "immediate" execution of `callback` after I/O events'
callbacks and before timers created using [`setTimeout`][] and [`setInterval`][]
are triggered. Returns an `immediateObject` for possible use with
[`clearImmediate`][].

Callbacks for "immediate timers" are queued in the order in which they were
created. The entire callback queue is processed every event loop iteration. If
an immediate timer is queued from inside an executing callback, that timer will
not be triggered until the next event loop iteration.

If `callback` is not a function, an [`Error`][] will be thrown.

### setInterval(callback, delay[, arg][, ...])

* `callback` {Function} The function to call when the timer elapses.
* `delay` {number} The number of milliseconds to wait before calling the
  `callback`.
* `[, arg][, ...]` Optional arguments to pass when the `callback` is called.

Schedules repeated execution of `callback` every `delay` milliseconds.
Returns a `intervalObject` for possible use with [`clearInterval`][].

When `delay` is larger than `2147483647` or less than `1`, the `delay` will be
set to `1`.

If `callback` is not a function, an [`Error`][] will be thrown.

### setTimeout(callback, delay[, arg][, ...])

* `callback` {Function} The function to call when the timer elapses.
* `delay` {number} The number of milliseconds to wait before calling the
  `callback`.
* `[, arg][, ...]` Optional arguments to pass when the `callback` is called.

Schedules execution of a one-time `callback` after `delay` milliseconds.
Returns a `timeoutObject` for possible use with [`clearTimeout`][].

The `callback` will likely not be invoked in precisely `delay` milliseconds.
Node.js makes no guarantees about the exact timing of when callbacks will fire,
nor of their ordering. The callback will be called as close as possible to the
time specified.

When `delay` is larger than `2147483647` or less than `1`, the `delay` will be
set to `1`.

If `callback` is not a function, an [`Error`][] will be thrown.

## Cancelling Timers

The [`setImmediate`][], [`setInterval`][], and [`setTimeout`][] methods each
return objects that represent the scheduled timers. These can be used to cancel
the timer and prevent it from triggering.

### clearImmediate(immediateObject)

* `immediateObject` {Immediate} An immediate timer object as returned by
  [`setImmediate`][].

Cancels an "immediate timer".

### clearInterval(intervalObject)

* `intervalObject` {Timeout} An interval timer object as returned by
  [`setInterval`][].

Cancels an "interval timer".

### clearTimeout(timeoutObject)

* `timeoutObject` {Timeout} A timeout timer object as returned by
  [`setTimeout`][].

Cancels a "timeout timer".


[the Node.js Event Loop]: https://github.com/nodejs/node/blob/master/doc/topics/the-event-loop-timers-and-nexttick.md
[`Error`][]: errors.html
[`clearImmediate`]: timers.html#timers_clearimmediate_immediateobject
[`clearInterval`]: timers.html#timers_clearinterval_intervalobject
[`clearTimeout`]: timers.html#timers_cleartimeout_timeoutobject
[`setImmediate`]: timers.html#timers_setimmediate_callback_arg
[`setInterval`]: timers.html#timers_setinterval_callback_delay_arg
[`setTimeout`]: timers.html#timers_settimeout_callback_delay_arg
