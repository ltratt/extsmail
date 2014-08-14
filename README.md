# extsmail

extsmail enables the robust sending of e-mail to external commands. In effect
extsmail masquerades as the standard UNIX sendmail program, reading messages,
and later trying to send them by user-defined commands. A typical use of extsmail
is to allow users who regularly move between different networks and / or find
themselves regularly offline, to ensure that their e-mail is sent reliably via
ssh to external servers.

More information about extsmail can be found at its webpage:

  http://tratt.net/laurie/src/extsmail/

![Travis build status](https://api.travis-ci.org/oliv3/extsmail.svg)

### Status
[![Build Status](https://travis-ci.org/oliv3/extsmail.png)](https://travis-ci.org/oliv3/extsmail)
