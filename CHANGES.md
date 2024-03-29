# extsmail 2.8 (2023-03-22)

* Fix bug where a child's stderr could be only partly read.

* Fix bug where stderr could be closed twice.


# extsmail 2.7 (2022-10-19)

* Introduce a test suite for (unusual) child process failure modes.

* Ensure that all of a child processes's stderr output is read, even if another
  failure (e.g. the child prematurely closing stdin) occurs beforehand. This
  makes debugging failing child processes easier.

* Treat child processes killed by a signal as unsuccessful.

* Introduce a timeout for child processes that, after seemingly processing
  a file correctly (e.g. consuming all input, closing the relevant file
  descriptors), then stall before exiting.


# extsmail 2.6 (2022-08-04)

* On Linux, ensure that a pselect() timeout leads to trying to (re)send
  messages.


# extsmail 2.5 (2021-08-08)

* Heavily simplify queue processing. As well as making the code easier to
  understand, extsmail is now more aggressive in trying to send messages.
  Failure to send a message now causes the next iteration through the queue to
  start from a random position, ensuring that extsmail can't become
  stuck on a (temporarily or persistently) unsendable message, no matter the
  iteration order of the underlying spool directory.


# extsmail 2.4 (2020-01-31)

* Fix a bug whereby a failure in executing a child process could cause an
  individual mail to be sent more than once and/or an unbounded number of
  child processes to persist indefinitely.


# extsmail 2.3 (2019-10-14)

* Have autoconf decide whether to use lex/yacc or flex/bison.

* Add pledge support for extsmail and extsmaild on OS's that support it.

* If a child process fails, but doesn't print anything to stderr, then
  format the result more nicely.

* Build correctly on Linux distributions that identify as GNU rather than
  Linux.

* extsmaild -v now prints extsmail's version number.


# extsmail 2.2 (2018-11-30)

* Suggest using "-t" with sendmail in examples (some sendmail clones require
  this switch).

* Use "-z,now" when linking.

* Fix two minor compiler warnings.


# extsmail 2.1 (2017-11-25)

* Build fix for more recent C compilers.


# extsmail 2.0 (2014-11-12)

* Reload configuration file when SIGHUP is received.

* Added -t option to check a configuration file without running extsmaild.

* Be more careful to free all file handles.


# extsmail 1.9 (2014-06-20)

* Fix bug which could temporarily cause undue CPU to be consumed when a
  large file send was cut off in the middle. This didn't prevent mail being
  sent correctly in the end, but was ugly.


# extsmail 1.8 (2014-05-29)

* Fix bug which caused extsmaild to consume larger amounts of CPU than
  strictly necessary (a normal user should now be able to run extsmaild for
  several days before exceeding 1 second of CPU usage).

* Fix reporting of sent mail on Linux (which previously sent mail correctly,
  but incorrectly reported failure even when the send was successful).

* Various fixes to make OS packager's lives easier.

* Significant code reorganisation to improve readability.


# extsmail 1.7 (2014-03-12)

* Several minor bug fixes spotted by static analysis tools (including
  memory leaks).

* More robust handling of corrupt message files.


# extsmail 1.6 (2012-11-17)

* Time out stalled sendmail processes. If a sendmail process hasn't read or
  written any data for 60 seconds, it is killed and later retried. This
  stops a stalled sendmail from perpetually blocking extsmail. Although
  rare, this could happen e.g. when an interface went down while an SSH
  session was open.


# extsmail 1.5 (2012-07-09)

* Ensure that all messages which can be sent are sent. Some messages may
  temporarily be unsendable (e.g. because of size) and shouldn't hold up
  others.

* Use exponential backoff when retrying. Quite often, a send failure is just
  a brief blip, so retry quickly, and as retries fail, increase the length
  of time until the next retry.

* Add user-configurable notifications for successful / unsuccessful sends.
  Allows users to easily be notified (e.g. via xosd) if mail has been sent
  and, if not, how long it has been since everything was sent.

* Various portability improvements.

* Improvements to batch mode to bring it in line with daemon mode.


# extsmail 1.4 (2011-06-18)

* Minor bug fixes.

* Documentation fixes.


# extsmail 1.3 (2010-05-30)

* OS X compile fixes.

* Fix overly-restrictive configuration permissions check.

* Recover gracefully from some errors that were previously fatal.


# extsmail 1.2 (2009-09-24)

* Fix build error when using bison.

* Minor documentation fixes.


# extsmail 1.1 (2009-04-29)

* Fix two frees of possibly uninitialised pointers.


# extsmail 1.0 (2009-01-05)

* extsmaild's modes are now specified via the "-m <mode name>" switch. In
  particular the behaviour of the "-d" switch is now obtained with
  "-m daemon".

* More intelligent detection of whether a previous instance of extsmaild is
  running or not.

* Systematically use syslog.

* Fix possible race condition between extsmail and extsmaild.

* Correctly handle SIGPIPE.


# extsmail 0.3 (2008-12-11)

* Make Linux support on a par with BSD (using inotify).

* Minor error handling / reporting changes.


# extsmail 0.2 (2008-11-20)

* Adds 'timeout' feature to externals.

* Fixes bug where exec'd externals first parameter was not correctly set.


# extsmail 0.1 (2008-11-11)

* First public release.
