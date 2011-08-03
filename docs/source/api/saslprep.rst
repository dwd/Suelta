===============
suelta.saslprep
===============

SASL uses the SASLPrep_ profile of stringprep_ to ensure that
comparisons of internationalized usernames and passwords make sense.

.. important::
    
    The :func:`saslprep <suelta.saslprep.saslprep>` function requires
    its initial text input to be UTF-8.

.. autofunction:: suelta.saslprep.saslprep

.. _saslprep: http://tools.ietf.org/html/rfc4013
.. _stringprep: http://tools.ietf.org/html/rfc3454
