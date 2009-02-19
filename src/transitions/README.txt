This directory contains transition scripts for major changes to
monkeysphere infrastructure.

They are expected to be run immediately after upgrading to the named
version or later.

For example: you upgrade to from version 0.8 to version 0.15, and the
directory contains 0.6, 0.12 and 0.15, you should run 0.12 followed by
0.15.

The scripts are supposed to be cleverly-written enough that you can
run them repeatedly, and they should only make their intended changes
once.  If they do not behave that way, this is a bug.  Please report
it!

  https://labs.riseup.net/code/projects/monkeysphere/
