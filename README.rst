coph: CUPS Over Plain HTTP
==========================

coph is a small HTTP daemon that listens for requests and prints them via
CUPS.

Inspired by the `12 Factor <http://12factor.net>`_ approach of treating
backing services as attached resources, the printer becomes a URL and printing
always works, without mechanical failures *coph, coph*.

Installation
------------

The the Makefile to either get a static or dyanmic binary:

.. code-block:: bash

    $ make static
    OR
    $ make dynamic


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

    $ curl --insecure -X POST https://localhost:6310 --form printer_name=Printer --form file=@file.txt

Note that coph uses TLS so your client must connect using the 'https' scheme.
Every time coph starts, it generates a self-signed certificate.
