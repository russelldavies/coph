coph: CUPS Over Plain HTTP
==========================

coph is a small HTTP daemon that listens for requests and prints them via
CUPS.

Inspired by the `12 Factor <http://12factor.net>`_ approach of treating
backing services as attached resources, the printer becomes a URL and printing
always works, without mechanical failures *coph, coph*.

Building
--------

Because cgo is compiling CUPS libraries into the go executable you'll need
the CUPS header files and libraries. They might already be on your machine in
which case the following should suffice:

.. code-block:: bash

    $ make static
    OR
    $ make dynamic

However, this will most likely fail, especially for building a static
executable as cgo has problems including glibc. So unless your system is
running musl, you'll want to build using Docker. There is an included
Dockerfile which creates a musl based container and then builds the executable.
To use it, run the build script which will take care of creating the Docker
image and running the build process:

.. code-block:: bash

    $ ./build.sh
    OR
    $ ./build.sh dynamic

On some architectures like ARM, you can also just install musl and make use of
the compiler wrapper:

.. code-block:: bash

    $ CC=/usr/bin/musl-gcc go build --ldflags '-s -linkmode external -extldflags "-static"' coph.go


Usage
-----

Run with the help flag to see a list of options:

.. code-block:: bash

    $ ./coph --help

At the bare minimum you'll need to specify a username and password for HTTP
basic authentication and your CUPS server username and password.

.. code-block:: bash

    $ ./coph --username admin --password password --cups-username foo --cups-password bar

Then send it a HTTP POST request with the printer name and print data payload:

.. code-block:: bash

    $ curl --insecure -X POST https://foo:bar@localhost:6310 --form printer_name=Printer --form file=@file.txt

Note that coph uses TLS so your client must connect using the 'https' scheme.
Every time coph starts, it generates a self-signed certificate.

If you make an authenticated GET request, you'll see printing stats.
