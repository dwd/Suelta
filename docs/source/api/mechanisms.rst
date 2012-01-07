=================
suelta.mechanisms
=================

Suelta comes with all of the Mandatory-To-Implement (MTI)
mechanisms required by current protocols (as of 2011). These
include :class:`ANONYMOUS <suelta.mechanisms.anonymous.ANONYMOUS>`,
:class:`PLAIN <suelta.mechanisms.plain.PLAIN>`, :class:`CRAM-MD5
<suelta.mechanisms.cram_md5.CRAM_MD5>`, :class:`DIGEST-MD5
<suelta.mechanisms.digest_md5.DIGEST_MD5>`, and :class:`SCRAM-HMAC
<suelta.mechanisms.scram_hmac.SCRAM_HMAC>`.

ANONYMOUS
---------
.. automodule:: suelta.mechanisms.anonymous
    :members:

PLAIN
-----
.. automodule:: suelta.mechanisms.plain
    :members:

CRAM-MD5
--------
.. automodule:: suelta.mechanisms.cram_md5
    :members:

DIGEST-MD5
----------
.. automodule:: suelta.mechanisms.digest_md5
    :members:

SCRAM-HMAC
----------
.. automodule:: suelta.mechanisms.scram_hmac
    :members:

X-MESSENGER-OAUTH2
------------------
The ``X-MESSENGER-OAUTH2`` mechanism is used for XMPP authentication
by the Windows Live Messenger.

.. automodule:: suelta.mechanisms.messenger_oauth2
    :members:
