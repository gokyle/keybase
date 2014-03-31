## keybase
### keybase.io command line client

This is an attempt at rewriting the keybase.io command line client in Go.

Currently supported:

* logging in

The `api/` subpackage contains an interface to the keybase.io API;
it will have a better record of supported features during development.
