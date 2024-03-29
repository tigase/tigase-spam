Groupchat messages sent to bare JID
--------------------------------------

In some cases SPAM messages are being sent as groupchat messages (messages with ``type`` attribute set to ``groupchat``). With this type of messages we cannot use filtering based on number of message sent with same body as in case of MUC messages we must accept a lot of messages with same body, because there may be many users which are participants of same MUC room and should receive same message.

To address this issue we decided to drop all groupchat messages which are sent to our server XMPP users with ``to`` attribute set to bare jid, as real MUC component is aware of user resources which joined particular room and will send messages only to this particular resource by addressing message with full jid. This filter is identified by following id ``muc-message-ensure-to-full-jid``.