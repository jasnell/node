'use strict';

const common = require('../common');
const { defer } = require('node:util');
const { strictEqual } = require('node:assert');

let n = 0;
{
  // Test that the function is called in the correct order.

  // TODO(@jasnell): The _ really should not trigger the no-unused-vars
  // es-lint rule but it does.
  using _ = defer(common.mustCall(() => {  // eslint-disable-line no-unused-vars
    strictEqual(n, 1);
  }));

  using toBeCanceled = defer(common.mustNotCall());
  toBeCanceled.cancel();

  n++;
}
