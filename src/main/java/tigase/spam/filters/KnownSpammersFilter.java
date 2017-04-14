/*
 * KnownSpammersFilter.java
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

import tigase.server.Packet;
import tigase.spam.ResultsAwareSpamFilter;
import tigase.stats.StatisticsList;
import tigase.xmpp.BareJID;
import tigase.xmpp.JID;
import tigase.xmpp.XMPPResourceConnection;

import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Created by andrzej on 13.04.2017.
 */
public class KnownSpammersFilter extends AbstractSpamFilter implements ResultsAwareSpamFilter {

	private static final Logger log = Logger.getLogger(KnownSpammersFilter.class.getCanonicalName());

	protected static final String ID = "known-spammers";

	private ConcurrentHashMap<BareJID, Long> spammers = new ConcurrentHashMap<>();

	private long banTime = 15;
	private boolean printSpammers = false;

	private final Timer timer = new Timer("known-spammers", true);

	@Override
	public void init(Map<String, Object> props) {
		banTime = (Long) props.getOrDefault("ban-time", 15L);
		printSpammers = (Boolean) props.getOrDefault("print-spammers", false);
		timer.schedule(new TimerTask() {
			@Override
			public void run() {
				KnownSpammersFilter.this.cleanUp();
			}
		}, 60 * 1000, 60 * 1000);
	}

	@Override
	public void identifiedSpam(Packet packet, XMPPResourceConnection session) {
		JID from = packet.getStanzaFrom();
		if (from == null && session != null) {
			from = session.getjid();
		}
		if (from == null) {
			return;
		}
		spammers.compute(from.getBareJID(), this::computeBanTimeout);
		try {
			if (session != null && session.isAuthorized() && session.isUserId(from.getBareJID())) {
				if (log.isLoggable(Level.FINE)) {
					log.log(Level.FINE, "Local user {0} was detected as a spammer, closing session for this user...",
							new Object[]{from});
				}
				session.putSessionData("error-key", "policy-violation");
				session.logout();
			}
		} catch (Exception ex) {
			log.log(Level.FINE, "Could not logout user " + from, ex);
		}
	}

	@Override
	public String getId() {
		return ID;
	}

	@Override
	protected boolean filterPacket(Packet packet, XMPPResourceConnection session) {
		JID from = packet.getStanzaFrom();
		if (from == null) {
			return true;
		}
		return !spammers.containsKey(from.getBareJID());
	}

	private Long computeBanTimeout(BareJID jid, Long currValue) {
		if (currValue == null) {
			currValue = System.currentTimeMillis();
		}

		return currValue + (banTime * 60 * 1000);
	}

	private void cleanUp() {
		if (!spammers.isEmpty()) {
			if (log.isLoggable(Level.FINEST) || printSpammers) {
				log.log(printSpammers ? Level.INFO : Level.FINEST, "Detected {0} spammers: {1}",
						new Object[]{spammers.size(), spammers.keySet().stream().sorted(BareJID::compareTo).collect(
								Collectors.toList())});
			}
			spammers.entrySet()
					.stream()
					.filter(e -> e.getValue() < System.currentTimeMillis())
					.map(e -> e.getKey())
					.forEach(this.spammers::remove);
		}
	}

	@Override
	public void getStatistics(String name, StatisticsList list) {
		super.getStatistics(name, list);
		if (list.checkLevel(Level.FINE)) {
			list.add(name, getId() + "/Known spammers", spammers.size(), Level.FINE);
		}
	}
}
