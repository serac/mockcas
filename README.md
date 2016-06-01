# MockCAS - Mock CAS Server for Testing
This is a simple little CAS server that was born out of a need for a
highly configurable CAS server to support load testing. Emphasis is on
simplicity, flexibility, and performance. The following SSO protocols
are supported:

1. CAS 1.0
2. CAS 2.0
3. SAML 1.1

The server implements a stupid simple routine for serving protocol
responses from files on disk under `$DATA_DIR`:

for authenticated user `$USER` on supported protocol `$PROTOCOL`, serve
the file `$DATA_DIR/$PROTOCOL/$USER`. It is the responsibility of
deployers to generate appropriate protocol data in the files, which
provides maximum flexibility for setting up test data sets at the
expense of some up-front effort generating the test data.

The [sampledata](https://github.com/serac/mockcas/tree/master/sampledata)
directory demonstrates the required layout of the `$DATA_DIR` directory.
The files therein may be used as starting points for creating a test
data set for your needs. It's only necessary to create files under the
protocols you intend to support for testing.

## Limitations
The design goal of simplicity, both in implementation and configuration,
incurs some notable limitations.

1. No support for TLS
2. Password authentication exclusively with single, static password
3. No proxy support
4. No single logout support

## Requirements
The only software requirement is Python 3.2 or later. It's recommend to
run the server on a secure private network due to the lack of TLS
support.

## Usage
    usage: server.py [-h] [--address ADDRESS] [--port PORT] secret data_dir

    Start the mock CAS server

    positional arguments:
      secret             static secret used to authenticate users
      data_dir           path to data directory

    optional arguments:
      -h, --help         show this help message and exit
      --address ADDRESS  server bind address, 0.0.0.0 by default
      --port PORT        server listen port, 8080 by default

