## keybase
### keybase.io command line client

This is an attempt at rewriting the keybase.io command line client in Go.

Currently supported:

* logging in
* look up a user
* fetch a user's public key

The `api/` subpackage contains an interface to the keybase.io API;
it will have a better record of supported features during development.

### Usage

    keybase [-u user] [-out filename] command [arguments]

The `-u` flag tells `keybase` what username to log in as; this is only
used for authenticated commands.

#### Unauthenticated commands

These commands do not require logging in.

* lookup: lookup takes a list of one or more users, and prints
  information about them to standard out. It will print out most
  available information, but it won't print out their public key to
  declutter standard output.
* fetch: fetch takes a username and attempts to download the public
  key for the user. The file is saved in the file specified by -out,
  or "<username>.pub". If the output file is "-", the key is printed
  to standard output.

#### Authenticated commands

These commands require logging in: your username should be specified
with "-u", and `keybase` will read your password from the terminal.

* testlogin: this command takes no arguments and just attempts to
  login. This is primarily useful as a test command to ensure logins
  work.

### License

This program is currently not very useful, but it (and the current API
implementation) are open sourced under the ISC license. See the
LICENSE file in either the project root or in the `api` package for
the full text.
