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

import tigase.db.TigaseDBException;
import tigase.server.Packet;
import tigase.spam.ResultsAwareSpamFilter;
import tigase.spam.SpamFilter;
import tigase.stats.StatisticsList;
import tigase.xmpp.BareJID;
import tigase.xmpp.JID;
import tigase.xmpp.XMPPResourceConnection;

import java.util.*;
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

	private ConcurrentHashMap<BareJID, Spammer> spammers = new ConcurrentHashMap<>();

	private long cacheTime = 7 * 24 * 60;
	private long banTime = 15;
	private boolean printSpammers = false;
	private long printSpammersFrequency = 24 * 60;
	private boolean disableAccount = true;
	private double disableAccountProbability = 1.0;
	private long disabledAccounts = 0;
	private long localSpammers = 0;
	private long remoteSpammers = 0;

	private final Timer timer = new Timer("known-spammers", true);

	@Override
	public void init(Map<String, Object> props) {
		banTime = (Long) props.getOrDefault("ban-time", 15L);
		cacheTime = (Long) props.getOrDefault("cache-time", 7 * 24 * 60L);
		printSpammers = (Boolean) props.getOrDefault("print-spammers", false);
		printSpammersFrequency = (Long) props.getOrDefault("print-spammers-frequency", 24 * 60L);
		disableAccount = (Boolean) props.getOrDefault("disable-account", true);
		timer.schedule(new TimerTask() {
			@Override
			public void run() {
				KnownSpammersFilter.this.cleanUp();
			}
		}, 60 * 1000, 60 * 1000);
		timer.schedule(new TimerTask() {
			@Override
			public void run() {
				KnownSpammersFilter.this.printSpammers();
			}
		}, printSpammersFrequency * 60 * 1000, printSpammersFrequency * 60 * 1000);
	}

	@Override
	public void identifiedSpam(Packet packet, XMPPResourceConnection session, SpamFilter filter) {
		JID from = packet.getStanzaFrom();
		if (from == null && session != null) {
			from = session.getjid();
		}
		if (from == null) {
			return;
		}
		Spammer spammer = spammers.computeIfAbsent(from.getBareJID(), this::createSpammer);
		spammer.spamDetected(filter);
		try {
			if (session != null && session.isAuthorized() && session.isUserId(from.getBareJID())) {
				spammer.localUser();
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
		if (session != null && disableAccount && spammer.hasProbabilityReached(disableAccountProbability)) {
			try {
				if (log.isLoggable(Level.FINE)) {
					log.log(Level.FINE, "Disabling account {0} as it is most likely a spammer, probability > {1}",
							new Object[]{from, disableAccountProbability});
				}
				session.getAuthRepository().setUserDisabled(from.getBareJID(), true);
				disabledAccounts++;
			} catch (TigaseDBException ex) {
				log.log(Level.WARNING, "Failed to disable spammer account " + from + " due to repository exception", ex);
			}
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
		Spammer spammer = spammers.get(from.getBareJID());
		return spammer == null || spammer.hasTimeoutPassed(banTime * 60 * 1000);
	}
	
	private Spammer createSpammer(BareJID spammerJid) {
		return new Spammer(spammerJid);
	}

	private void cleanUp() {
		if (!spammers.isEmpty()) {
			spammers.entrySet()
					.stream()
					.filter(e -> e.getValue().hasProbabilityReached(disableAccountProbability))
					.map(e -> e.getKey())
					.forEach(this.spammers::remove);
			spammers.entrySet()
					.stream()
					.filter(e -> e.getValue().hasTimeoutPassed(cacheTime * 60 * 1000))
					.map(e -> e.getKey())
					.forEach(this.spammers::remove);
		}
	}
	
	private void printSpammers() {
		if (log.isLoggable(Level.FINEST) || printSpammers) {
			Map<Boolean, List<Spammer>> grouped = spammers.values()
					.stream()
					.collect(Collectors.groupingBy(spammer -> spammer.isLocalUser(), Collectors.toList()));

			List<Spammer> list = grouped.getOrDefault(true, Collections.emptyList());
			localSpammers = list.size();
			printSpammersGroup(printSpammers ? Level.INFO : Level.FINEST, true, list);
			list = grouped.getOrDefault(false, Collections.emptyList());
			remoteSpammers = list.size();
			printSpammersGroup(printSpammers ? Level.INFO : Level.FINEST, false, list);
		}
	}

	private void printSpammersGroup(Level level, boolean local, List<Spammer> spammers) {
		
		String name = local ? "local" : "remote";
		Map<String, List<Spammer>> spammersByDomain = spammers.stream()
				.collect(Collectors.groupingBy(spammer -> spammer.getJID().getDomain(), Collectors.toList()));
		List<String> sortedDomains = spammersByDomain.keySet().stream().sorted().collect(Collectors.toList());
		log.log(level, "Detected {0} {3} spammers for {1} domains {2}",
				new Object[]{spammers.size(), spammersByDomain.size(), sortedDomains, name});
		sortedDomains.forEach(domain -> {
			log.log(level, "For {3} domain {0} detected {1} spammers: {2}",
					new Object[]{domain, spammersByDomain.get(domain).size(),
								 spammersByDomain.get(domain).stream().sorted().map(spammer -> spammer.toString()).collect(Collectors.joining(", ")), name});
		});
	}

	@Override
	public void getStatistics(String name, StatisticsList list) {
		super.getStatistics(name, list);
		if (list.checkLevel(Level.FINE)) {
			list.add(name, getId() + "/Known spammers", spammers.size(), Level.FINE);
			list.add(name, getId() + "/Known local spammers", localSpammers, Level.FINE);
			list.add(name, getId() + "/Known remote spammers", remoteSpammers, Level.FINE);
			list.add(name, getId() + "/Disabled accounts", disabledAccounts, Level.FINE);
		}
	}

	public class Spammer implements Comparable<Spammer> {

		private final BareJID jid;
		private long lastSpamTimestamp = System.currentTimeMillis();
		private long counter = 0;
		private double probability = 0;
		private boolean localUser;

		public Spammer(BareJID jid) {
			this.jid = jid;
		}

		public BareJID getJID() {
			return jid;
		}

		public void spamDetected(SpamFilter reporter) {
			lastSpamTimestamp = System.currentTimeMillis();
			counter++;
			probability += reporter.getSpamProbability();
		}

		public boolean hasTimeoutPassed(long timeout) {
			return (System.currentTimeMillis() - lastSpamTimestamp) > timeout;
		}

		public boolean hasProbabilityReached(double value) {
			return probability >= value;
		}

		public void localUser() {
			localUser = true;
		}

		public boolean isLocalUser() {
			return localUser;
		}

		@Override
		public int compareTo(Spammer o) {
			return jid.compareTo(o.jid);
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append(jid.toString())
					.append("[last_at: ")
					.append(lastSpamTimestamp)
					.append(", count: ")
					.append(counter)
					.append(", probability: ")
					.append(probability)
					.append(", banned: ")
					.append(!hasTimeoutPassed(banTime * 60 * 1000))
					.append("]");
			return sb.toString();
		}
	}
}
