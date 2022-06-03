Development
=============

You can easily add a new methods of detection if a packet is a spam or not. Simplest way is to implement a new filter.

Implementation of a new filter
------------------------------------

Each class used as a filter by ``SpamProcessor`` needs to implement ``SpamFilter`` interface.

There are 3 important methods which need to be implemented by in ``SpamFilter`` interface:

-  ``String getId()`` - returns id of a filter

-  ``double getSpamProbability()`` - returns probability of sender being a spammer after detection of a single message which is blocked *(from 0.0 to 1.0 where 1.0 means that it is a spammer)*

-  ``boolean filter(Packet packet, XMPPResourceConnection session)`` - method checking if a stanza is a spam (return ``false`` to stop stanza from being delivered)

Simple filter with id ``dummy-detector`` which would look for messages with text ``dummy``, block them and then mark sender as a spammer after 5 messages would look like this:

**Example filter.**

.. code:: java

   package test;
   import tigase.spam.SpamFilter;

   @Bean(name = "dummy-detector", parent = SpamProcessor.class, active = true)
   class DummyDetector implements SpamFilter {

       @Override
       public String getId() {
           return "dummy-detector";
       }

       @Override
       public double getSpamProbability() {
           return 0.2;
       }

       @Override
       protected boolean filterPacket(Packet packet, XMPPResourceConnection session) {
           if (packet.getElemName() == "message") {
               Element bodyEl = packet.getElement().getChild("body");
               if (bodyEl != null) {
                   String body = bodyEl.getCData();
                   if (body != null) {
                       return !body.contains("dummy");
                   }
               }
           }
           return true;
       }
   }

.. Note::

   If you expect packet to be processed multiple times (ie. by filter of a sender and filer of a received), then you should take that into account when you estimate value returned by ``getSpamProbability()``.

.. Tip::

   We have added ``@Bean`` annotation to automatically enable this filter in the ``SpamProcessor`` in the Tigase XMPP Server and to be able to easily configure it without specifying full name of a class.