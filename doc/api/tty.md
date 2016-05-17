# TTY

    Stability: 2 - Stable

The `tty` module houses the `tty.ReadStream` and `tty.WriteStream` classes. In
most cases, you will not need to use this module directly.

When Node.js detects that it is being run inside a TTY context, then 
`process.stdin` will be a `tty.ReadStream` instance and `process.stdout` will be
a `tty.WriteStream` instance. The preferred way to check if Node.js is being run
in a TTY context is to check `process.stdout.isTTY`:

```
$ node -p -e "Boolean(process.stdout.isTTY)"
true
$ node -p -e "Boolean(process.stdout.isTTY)" | cat
false
```

## Class: ReadStream

A `net.Socket` subclass that represents the readable portion of a tty. In normal
circumstances, `process.stdin` will be the only `tty.ReadStream` instance in any
Node.js program (only when `isatty(0)` is true).

### rs.isRaw

A `Boolean` that is initialized to `false`. It represents the current "raw" 
state of the `tty.ReadStream` instance.

### rs.setRawMode(mode)

`mode` should be `true` or `false`. This sets the properties of the
`tty.ReadStream` to act either as a raw device or default. `isRaw` will be set
to the resulting mode.

## Class: WriteStream

A `net.Socket` subclass that represents the writable portion of a tty. In normal
circumstances, `process.stdout` will be the only `tty.WriteStream` instance
ever created (and only when `isatty(1)` is true).

### Constructor: new fs.WriteStream(fd[, options])

* `fd` {Number} The numeric file descriptor for this TTY instance.
* `options` {Object}
  * `blocking` {boolean} `true` if writes to the TTY should be blocking,
    `false` otherwise. Defaults to `true`.

Creates a new `tty.WriteStream`. By default, writes to the TTY will be blocking.
Use `new fs.WriteStream(fd, {blocking: false})` to create the `fs.WriteStream`
using non-blocking writes by default.

### Event: 'resize'

`function () {}`

Emitted by `refreshSize()` when either of the `columns` or `rows` properties
has changed.

```js
process.stdout.on('resize', () => {
  console.log('screen size has changed!');
  console.log(`${process.stdout.columns}x${process.stdout.rows}`);
});
```

### ws.columns

A `Number` that gives the number of columns the TTY currently has. This property
gets updated on `'resize'` events.

### ws.rows

A `Number` that gives the number of rows the TTY currently has. This property
gets updated on `'resize'` events.

### ws.setNonBlocking([bool])

* `bool` {boolean} `true` to set the TTY to non-blocking writes, `false`
  otherwise. Defaults to `true`.

Returns a reference to the `tty.WriteStream` so calls can be chained.

```js
const myNonBlockingTTY = new tty.WriteStream(myFd).setNonBlocking();
```

## tty.isatty(fd)

Returns `true` or `false` depending on if the `fd` is associated with a
terminal.

[tty.ReadStream#setRawMode]: #tty_rs_setrawmode_mode
