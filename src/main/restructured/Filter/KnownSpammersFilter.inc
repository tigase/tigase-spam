Known spammers
-----------------

To deal with spam it is required to filter every messages to verify if it is spam or not. Usually spammers are using same accounts to send bigger number of messages. This filter takes it as an advantage of this to reduce time required for filtering spam messages as when any other filter marks message as spam this filter will be notified and will mark senders jid as a spammer. This will result in a ban for any packet exchange with this user for configured `ban time <#ban-time>`__.

If user will send a burst of spam messages then he will be banned for configured ban time for every spam message, ie. if user would send 20 messages and ban time will be set to 15 minutes then users will be banned for 300 minutes (5 hours).

This filter is identified by following id ``known-spammers``.

**Ban time**

Time in minutes for which user marked as spammer will not be able to exchange packets with any other users. By default this value is set to 15 minutes and if you would like to increase it to 30 minutes just add following line to ``etc/init.properties`` file:

.. code:: text

   'sess-man' () {
       'spam-filter' () {
           'known-spammers' () {
               ban-time = 30
           }
       }
   }

Cache time
^^^^^^^^^^^

Time in minutes for which user will be remembered as a spammer. It will be able to exchange messages with other users (after ban time passes), but if the situation repeats within this time and our algorithm will be sure that user is a spammer - it may disable local user account.

.. code:: text

   'sess-man' () {
       'spam-filter' () {
           'known-spammers' () {
               cache-time = 10080
           }
       }
   }

Disabling account
^^^^^^^^^^^^^^^^^^^^^^

If filter, depending on other filter reports, will establish that user is for sure a spammer it may not only ban user for some time, but it may disable that user account. This is done by default, if you wish to disable account deactivation add following line to ``etc/init.properties`` file:

.. code:: text

   'sess-man' () {
       'spam-filter' () {
           'known-spammers' () {
               disable-account = false
           }
       }
   }

Print list of detected spammers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is possible to request filter to print full list of known spammer which are currently banned every minute. To do so, you need to set ``print-spammers`` property to ``true``.

.. code:: text

   'sess-man' () {
       'spam-filter' () {
           'known-spammers' () {
               print-spammers = true
           }
       }
   }

Frequency of printing list of spammers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, list of detected spammers is printed to logs every day. If you wish you can adjust this value to 1 hour, then add following entry to ``etc/init.properties`` file:

.. code:: text

   'sess-man' () {
       'spam-filter' () {
           'known-spammers' () {
               print-spammers-frequency = 60
           }
       }
   }