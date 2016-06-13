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

    $ make
    $ ./coph


Running
-------

Run with the help flag:

.. code-block:: bash

    $ ./coph --help
