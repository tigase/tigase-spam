/*
 * Tigase Spam Filter - SPAM filters for Tigase XMPP Server
 * Copyright (C) 2017 Tigase, Inc. (office@tigase.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3 of the License.
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

import tigase.kernel.beans.Bean;
import tigase.kernel.beans.config.ConfigField;
import tigase.server.Message;
import tigase.server.Packet;
import tigase.spam.SpamProcessor;
import tigase.stats.StatisticsList;
import tigase.util.Algorithms;
import tigase.xmpp.ElementMatcher;
import tigase.xmpp.StanzaType;
import tigase.xmpp.XMPPResourceConnection;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by andrzej on 08.04.2017.
 */
@Bean(name = MessageFilterSameLongBody.ID, parent = SpamProcessor.class, active = true)
public class MessageFilterSameLongBody
		extends AbstractSpamFilter {

	protected static final String ID = "message-same-long-body";
	private static final Logger log = Logger.getLogger(MessageFilterSameLongBody.class.getCanonicalName());
	private static final Charset CHARSET_UTF8 = Charset.forName("utf-8");
	private final AtomicBoolean cleanerRunning = new AtomicBoolean(false);
	private final ConcurrentHashMap<String, Integer> counter = new ConcurrentHashMap<>();
	@ConfigField(desc = "Check message with body bigger that this limit", alias = "body-size")
	private int longMessageSize = 100;
	@ConfigField(desc = "Limit size of message counter cache", alias = "counter-size-limit")
	private int messageCounterSizeLimit = 10000;
	@ConfigField(desc = "Limit number of message with same body", alias = "number-limit")
	private int messageNumberLimit = 20;
	@ConfigField(desc = "Skip checking OTR for spam", alias = "skip-otr-check")
	private boolean skipOtrCheck = true;
	@ConfigField(desc = "Rules for skipping checking body for spam", alias = "skip-check-rules")
	private ElementMatcher[] skipMatchers = new ElementMatcher[]{
			new ElementMatcher(new String[]{Message.ELEM_NAME, "fallback"}, "urn:xmpp:fallback:0", true),
			new ElementMatcher(new String[]{Message.ELEM_NAME, "encrypted"}, "eu.siacs.conversations.axolotl", true),
			new ElementMatcher(new String[]{Message.ELEM_NAME, "openpgp"}, "urn:xmpp:openpgp:0", true),
			new ElementMatcher(new String[] {Message.ELEM_NAME, "encrypted"}, "urn:xmpp:omemo:1", true)
	};

	@Override
	public String getId() {
		return ID;
	}

	@Override
	public double getSpamProbability() {
		return 0.4;
	}

	@Override
	public void getStatistics(String name, StatisticsList list) {
		super.getStatistics(name, list);
		if (list.checkLevel(Level.FINE)) {
			list.add(name, getId() + "/Cache size", counter.size(), Level.FINE);
		}
	}

	protected boolean shouldSkipBodyCheck(Packet packet) {
		for (ElementMatcher matcher : skipMatchers) {
			if (matcher.matches(packet)) {
				return true;
			}
		}

		return false;
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

			if (shouldSkipBodyCheck(packet)) {
				return true;
			}

			if (skipOtrCheck) {
				if (body.startsWith("?OTR?v23?")) {
					return true;
				}
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

	private class CleanerTask
			extends Thread {

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
