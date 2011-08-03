===========
suelta.sasl
===========

.. .. module:: suelta.sasl

The :mod:`suelta.sasl` module contains the basic framework for both
managing and choosing SASL mechanisms. As part of this, there are two
global repositories for sharing SASL related data across authentication
attempts during the same session. 

The Stash
---------
The first is the stash which is stored in :data:`SESSION
<suelta.sasl.SESSION>`. The stash stores values requested from the user by
SASL mechanisms. The stash can also be persisted to disk if a file name is
specified using :func:`set_stash_file <suelta.sasl.set_stash_file>`.

.. topic:: Why do we use a stash? 

    It makes authentication simpler for end users by
    not requiring them to re-answer security questions.

.. autodata:: suelta.sasl.SESSION

.. autofunction:: suelta.sasl.set_stash_file

The Mechanism Registry
----------------------
The second global repository is the mechanism registry, which maps mechanism
names to both the underlying implementation classes and security scores.
The security scores allow Suelta to automatically pick the most secure
mechanism out of a group of options.

.. autodata:: suelta.sasl.MECHANISMS

.. autodata:: suelta.sasl.MECH_SEC_SCORES

Adding new mechanism implmentations to the registry is done using
:func:`register_mechanism <suelta.sasl.register_mechanism>`. Since
most mechanisms are able to work with a variety of hashing algorithms,
specifying the name of a mechanism when registering is done in parts.
The first part defines the base name which identifies the mechanism
implementation. The second part of the name is based on the hashing
algorithm used, thus there are as many full mechanism names registered for
a single implementation as there are available hashing algorithms.

Hashing algorithms are ordered by security, and the final mechanism
entry's security scores are boosted slightly to preserve that ordering.

Some mechanisms do not depend on hashing algorithms, and for these
the parameter ``use_hashes=False`` may be used to create just a 
single entry.

.. autofunction:: suelta.sasl.register_mechanism

Security Queries
----------------
Many factors affect the overall security provided by SASL, including
the mechanism chosen and whether or not the underlying communications
channel is encrypted. Some combinations of features can potentially
reduce security, and before such combinations are used Suelta prompts
for confirmation.

These confirmations, or queries, are encodings of the feature combination
in question, such as ``-ENCRYPTION, SCRAM`` to indicate that the ``SCRAM``
mechanism is being used without underlying channel encryption. These
queries should be mapped to end user friendly and localized messages that
can be presented to the user for confirmation.

However, you may wish to short circuit that process by always approving
or denying security queries. Denying queries is done automatically if
no ``sec_query`` callback is provided when creating the :class:`SASL
<suelta.sasl.SASL>` object. Approving queries can be done using
:func:`sec_query_allow <suelta.sasl.sec_query_allow>`, or any method that
accepts two parameters and returns ``True``.

.. autofunction:: suelta.sasl.sec_query_allow

Queries and Explanations
~~~~~~~~~~~~~~~~~~~~~~~~
Here are the queries used by mechanisms in the version 1.0 of Suelta, along
with the implications of approving the query.

``CLEAR-PASSWORD``
    Can I save this password in the clear?

``CRAM-MD5``
    CRAM-MD5 is not very strong, and can be broken. Should I continue
    anyway? It is fairly safe to do so.

``-ENCRYPTION, SCRAM``
    I have no encryption, however I am using SCRAM. An attacker listening
    to the wire could see what you're doing, but would find it difficult to
    get your password. Should I continue?

``-ENCRYPTION, DIGEST-MD5``
    I have no encryption, however I am using DIGEST-MD5. An attacker
    listening to the wire could see what you're doing, but would find it
    difficult to get your password. Should I continue?

``-ENCRYPTION, PLAIN``
    I need to use plaintext authentication, but I have no encryption layer.
    This is bad, as it is easy to obtain your password, and impossible to
    prevent. Do you REALLY want me to continue?

``+ENCRYPTION, PLAIN``
    I have encryption, but I need to use plaintext authentication. If the
    server has been hacked, I will give the attacker your password. This is
    unlikely, but should I continue?


The SASL Class
--------------

.. autoclass:: suelta.sasl.SASL()
    :members:

    .. automethod:: suelta.sasl.SASL.__init__

SASL Callback Functions
~~~~~~~~~~~~~~~~~~~~~~~

.. function:: sec_query(mech, query)

    Approve or deny combinations of features which could negatively
    affect security.

    :param mech: The chosen SASL mechanism
    :param query: An encoding of the combination of enabled and
                  disabled features which may affect security.

    :rtype: boolean

    An example of a query is ``-ENCRYPTION+SCRAM``, indicating that
    there is no encryption but SCRAM is being used.


.. function:: request_values(mech, values)

    Return a dictionary of user data requested by the mechanism, such
    as passwords.

    :param mech: The chosen SASL mechanism
    :param dict values: A dictionary of values requested by the
                        mechanism, such as passwords.

    :rtype: dict

.. function:: tls_active()

    Indicate if TLS has been negotiated before authenticating.

    :rtype: boolean


Base Mechanism Class
--------------------

The base mechanism class provides the necessary interfaces for mechanisms
to interact with the stash, and to request information from the user.

Once a mechanism has been created, the main interaction with it is
the :meth:`process <suelta.sasl.Mechanism.process>` method. Data is
read from the server, in whatever protocol specific manner as needed,
and then passed to :meth:`process <suelta.sasl.Mechanism.process>`.
The results are then sent back to the server, in the fashion required
by the using protocol (typically this means converting to ``base64``).

And that's it! Continue looping and processing data from the server
until the protocol's signal for authentication success or failure is
received.

.. autoclass:: suelta.sasl.Mechanism
    :members:

    .. automethod:: suelta.sasl.Mechanism.__init__
