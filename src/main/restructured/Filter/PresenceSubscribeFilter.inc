Presence subscription filter
--------------------------------

When there is a presence-based SPAM being sent using XMPP server in most cases there is a lot of ``presence`` of type ``subscribe`` being sent from the single JID. This behavior is annoying and has negative impact on the XMPP server as according to the XMPP specification each ``presence`` of type ``subscribe`` sent from JID which is not in the users roster causes adding this JID to the user’s roster until user declines subscription request.

Detection is based on counting subscription request being sent from the same bare JID within a period of time.

Below is list of possible settings which may be modified to adjust this filter behaviour.

Number of allowed subscription requests per minute
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Be default filter allows 5 subscription requests to be sent from the single JID per minute. If some client will send more than 5 subscription requests it will be marked as a spammer.

**Setting filter to allow 7 subscription requests per minute.**

.. code:: dsl

   'sess-man' () {
       'spam-filter' () {
           'presence-subcribe' () {
               'limit-per-minute' = 7
           }
       }
   }