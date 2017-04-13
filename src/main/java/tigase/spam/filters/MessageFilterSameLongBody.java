/*
 * MessageFilterSameLongBody.java
 *
 * Tigase Jabber/XMPP Server
 * Copyright (C) 2004-2017 "Tigase, Inc." <office@tigase.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. Look for COPYING file in the top folder.
 * If not, see http://www.gnu.org/licenses/.
 */
package tigase.spam.filters;

import tigase.server.Message;
import tigase.server.Packet;
import tigase.stats.StatisticsList;
import tigase.util.Algorithms;
import tigase.xmpp.StanzaType;
import tigase.xmpp.XMPPResourceConnection;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by andrzej on 08.04.2017.
 */
public class MessageFilterSameLongBody extends AbstractSpamFilter {

	private static final Logger log = Logger.getLogger(MessageFilterSameLongBody.class.getCanonicalName());

	private static final Charset CHARSET_UTF8 = Charset.forName("utf-8");

	private static final String ID = "message-same-long-body";

	private final ConcurrentHashMap<String,Integer> counter = new ConcurrentHashMap<>();

	private int longMessageSize = 100;

	private int messageCounterSizeLimit = 10000;

	private int messageNumberLimit = 20;

	private final AtomicBoolean cleanerRunning = new AtomicBoolean(false);

	@Override
	public String getId() {
		return ID;
	}

	@Override
	public void init(Map<String, Object> props) {
		longMessageSize = (Integer) props.getOrDefault("size", 100);
		messageCounterSizeLimit = (Integer) props.getOrDefault("counter-size-limit", 10000);
		messageNumberLimit = (Integer) props.getOrDefault("number-limit", 20);
	}

	@Override
	protected boolean filterPacket(Packet packet, XMPPResourceConnection session) {
		if (packet.getElemName() != Message.ELEM_NAME || packet.getType() == StanzaType.groupchat) {
			return true;
		}

		try {
			String body = packet.getElemCDataStaticStr(Message.MESSAGE_BODY_PATH);
			if (body == null || body.length() <= longMessageSize) {
				return true;
			}

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String hash = Algorithms.bytesToHex(md.digest(body.getBytes(CHARSET_UTF8)));

			Integer count = counter.compute(hash, (k, v) -> {
				if (v == null) {
					return 1;
				} else {
					return v + 1;
				}
			});

			if (counter.size() > messageCounterSizeLimit) {
				if (cleanerRunning.compareAndSet(false, true)) {
					new CleanerTask().start();
				}
			}

			if (count > messageNumberLimit) {
				if (log.isLoggable(Level.FINEST) && count < (messageNumberLimit + 10)) {
					log.log(Level.FINEST, "Message is assumed to be spam. Already seen {0} message with body: {1}",
							new Object[]{count, body});
				}
				return false;
			}
		} catch (NoSuchAlgorithmException ex) {
			log.log(Level.WARNING, "Algorithm SHA-256 in not available!", ex);
		}
		return true;
	}

	@Override
	public void getStatistics(String name, StatisticsList list) {
		super.getStatistics(name, list);
		if (list.checkLevel(Level.FINE)) {
			list.add(name, getId() + "/Cache size", counter.size(), Level.FINE);
		}
	}

	private class CleanerTask extends Thread {

		public CleanerTask() {
			super(ID + "-cleaner-task");
		}

		@Override
		public void run() {
			try {
				counter.entrySet()
						.stream()
						.filter(e -> e.getValue() < messageNumberLimit)
						.forEach(e -> counter.remove(e.getKey(), e.getValue()));
			} catch (Throwable ex) {
				log.log(Level.WARNING, "Exception during cleanup of suspected SPAM message counter table", ex);
			}
			cleanerRunning.set(false);
		}
	}
}
