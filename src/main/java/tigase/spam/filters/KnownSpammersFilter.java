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

import tigase.db.AuthRepository;
import tigase.db.TigaseDBException;
import tigase.kernel.beans.Bean;
import tigase.kernel.beans.Initializable;
import tigase.kernel.beans.Inject;
import tigase.kernel.beans.config.ConfigField;
import tigase.kernel.beans.config.ConfigurationChangedAware;
import tigase.server.Packet;
import tigase.spam.ResultsAwareSpamFilter;
import tigase.spam.SpamFilter;
import tigase.spam.SpamProcessor;
import tigase.stats.StatisticsList;
import tigase.vhosts.VHostManagerIfc;
import tigase.xmpp.XMPPResourceConnection;
import tigase.xmpp.jid.BareJID;
import tigase.xmpp.jid.JID;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static tigase.spam.filters.KnownSpammersFilter.ID;

/**
 * Created by andrzej on 13.04.2017.
 */
@Bean(name = ID, parent = SpamProcessor.class, active = true)
public class KnownSpammersFilter
		extends AbstractSpamFilter
		implements ResultsAwareSpamFilter, ConfigurationChangedAware, Initializable {

	protected static final String ID = "known-spammers";
	private static final Logger log = Logger.getLogger(KnownSpammersFilter.class.getCanonicalName());
	@ConfigField(desc = "Ban time", alias = "ban-time")
	private long banTime = 15;
	@ConfigField(desc = "Cache time", alias = "cache-time")
	private long cacheTime = 7 * 24 * 60;
	private TimerTask cleanUpTimerTask;
	private boolean disableAccount = true;
	private double disableAccountProbability = 1.0;
	private long disabledAccounts = 0;
	private long localSpammers = 0;
	@ConfigField(desc = "Print spammers", alias = "print-spammers")
	private boolean printSpammers = false;
	@ConfigField(desc = "Print spammers frequency", alias = "print-spammers-frequency")
	private long printSpammersFrequency = 24 * 60;
	@ConfigField(desc = "Reported spammer probability")
	private double reportedSpammerProbability = 0.1;
	private TimerTask printSpammersTimerTask;
	private long remoteSpammers = 0;
	private ConcurrentHashMap<BareJID, Spammer> spammers = new ConcurrentHashMap<>();
	private Timer timer;
	@Inject
	private VHostManagerIfc vHostManager;

	@Override
	public boolean reportedSpammer(BareJID jid) {
		Spammer spammer = spammers.computeIfAbsent(jid, this::createSpammer);
		if (vHostManager.isLocalDomain(jid.getDomain())) {
			spammer.localUser();
		}
		spammer.spamDetected(reportedSpammerProbability);
		return spammer.hasProbabilityReached(disableAccountProbability);
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
		if (filter != this) {
			spammer.spamDetected(filter);
		}
		try {
			if (session != null && session.isAuthorized() && session.isUserId(from.getBareJID())) {
				spammer.localUser();
				if (log.isLoggable(Level.FINE)) {
					log.log(Level.FINE, "Local user {0} was detected as a spammer, closing session for this user...",
							new Object[]{from});
				}
				session.putSessionData("error-key", "policy-violation");
				session.logout();

				if (spammer.hasProbabilityReached(disableAccountProbability)) {
					try {
						if (log.isLoggable(Level.FINE)) {
							log.log(Level.FINE,
									"Disabling account {0} as it is most likely a spammer, probability > {1}",
									new Object[]{from, disableAccountProbability});
						}
						session.getAuthRepository()
								.setAccountStatus(from.getBareJID(), AuthRepository.AccountStatus.disabled);
						disabledAccounts++;
					} catch (TigaseDBException ex) {
						log.log(Level.WARNING,
								"Failed to disable spammer account " + from + " due to repository exception", ex);
					}
				}
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
	public double getSpamProbability() {
		return 0;
	}

	@Override
	public void beanConfigurationChanged(Collection<String> collection) {
		if (cleanUpTimerTask != null) {
			cleanUpTimerTask.cancel();
			timer.purge();
		}
		if (printSpammersTimerTask != null) {
			printSpammersTimerTask.cancel();
			timer.purge();
		}
		if (timer != null) {
			cleanUpTimerTask = new TimerTask() {
				@Override
				public void run() {
					KnownSpammersFilter.this.cleanUp();
				}
			};
			timer.schedule(cleanUpTimerTask, 60 * 1000, 60 * 1000);
			printSpammersTimerTask = new TimerTask() {
				@Override
				public void run() {
					KnownSpammersFilter.this.printSpammers();
				}
			};
			timer.schedule(printSpammersTimerTask, printSpammersFrequency * 60 * 1000,
						   printSpammersFrequency * 60 * 1000);
		}
	}

	@Override
	public void initialize() {
		timer = new Timer("known-spammers", true);
		beanConfigurationChanged(Collections.emptyList());
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
					new Object[]{domain, spammersByDomain.get(domain).size(), spammersByDomain.get(domain)
							.stream()
							.sorted()
							.map(spammer -> spammer.toString()).collect(Collectors.joining(", ")), name});
		});
	}

	public class Spammer
			implements Comparable<Spammer> {

		private final BareJID jid;
		private long counter = 0;
		private long lastSpamTimestamp = System.currentTimeMillis();
		private boolean localUser;
		private double probability = 0;

		public Spammer(BareJID jid) {
			this.jid = jid;
		}

		public BareJID getJID() {
			return jid;
		}

		public void spamDetected(SpamFilter reporter) {
			this.spamDetected(reporter.getSpamProbability());
		}

		public void spamDetected(double probability) {
			lastSpamTimestamp = System.currentTimeMillis();
			counter++;
			this.probability += probability;
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
