===========================================
Suelta -- A pure-Python SASL client library
===========================================

Suelta is a SASL library, providing you with authentication and in some
cases security layers.

It supports a wide range of typical SASL mechanisms, including the
Mandatory-To-Implement (MTI) mechanisms for all known protocols.

----------------
Getting the Code
----------------

This project is a Python3 compatible fork of Dave Cridland's (dwd_) original
Suelta project.

* Get the original at http://github.com/dwd/Suelta
* The code documented here is available at http://github.com/legastero/Suelta

-------------
API Reference
-------------
.. toctree::
    api/sasl
    api/mechanisms
    api/saslprep
    api/exceptions
    api/util

---------------
Working Example
---------------

Here is a basic, quick and dirty demonstration for using Suelta with IMAP.
The overall pattern for use remains the same regardless of the using
protocol:

* Get the list of available mechanisms
* Choose a mechanism
* Read data from the server.
* Run that data through the mechanism's :meth:`process() <suelta.sasl.Mechanism.process>` method.
* Send the result back to server.
* Repeat until a success/failure signal is received.


.. literalinclude:: ../../example.py

-------
License
-------

.. include:: ../../LICENSE

.. topic:: Playing Nicely

    .. include:: ../../PLAYING-NICELY


.. _dwd: http://github.com/dwd
