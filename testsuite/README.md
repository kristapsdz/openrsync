# Test suites for openrsync.

All tests are for the kyua framework.

run-orig/ contains slightly changed tests from GNU rsync.  See the
README.md in there.

src/ contains a new test suite.  See the README.md in there.

## src/ instructions

Edit conf.sh to your liking.

Run like this:

`./generate-kyua && kyua test`

You can also run the individual test cases like this:
`./test5_symlink-kills-dir.test`

Requirements:
- pkg misc/cstream is required for some modes of testing.
- perl5 for some one-liners

Makefile has some useful functions you might want to check out.

