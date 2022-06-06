Error message and missing <error/> child
-----------------------------------------

Some of SPAM messages are sent as stanzas which are invalid if we compare them with XMPP specification, ie. ``<message/>`` stanza with ``type`` attribute set to ``error`` are sent without child element ``<error/>`` which is required for all packets of type ``error``. This filter detects this kind of messages and marks them as SPAM.

This filter is identified by following id ``message-error-ensure-error-child``.