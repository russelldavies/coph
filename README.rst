coph: CUPS Over Plain HTTP
==========================

coph is a small HTTP daemon that listens for requests and prints them via CUPS.

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
    $ ./coph --username admin --password password

Then send it a HTTP POST request with the printer name and print data payload:

.. code-block:: bash

    $ curl -X POST localhost:8080 --form printer_name=Printer --form data=@payload.dat
