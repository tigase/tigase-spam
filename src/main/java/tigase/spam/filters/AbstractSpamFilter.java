/*
 * AbstractSpamFilter.java
 *
 * Tigase Jabber/XMPP Server - SPAM Filter
 * Copyright (C) 2004-2017 "Tigase, Inc." <office@tigase.com>
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

import tigase.server.Packet;
import tigase.spam.SpamFilter;
import tigase.stats.StatisticsList;
import tigase.xmpp.XMPPResourceConnection;

import java.util.logging.Level;

/**
 * Created by andrzej on 13.04.2017.
 */
public abstract class AbstractSpamFilter
		implements SpamFilter {

	private long avgProcessingTime = 0L;
	private long filteredMessages = 0L;
	private long spamMessages = 0L;
	private long totalProcessingTime = 0L;

	@Override
	public boolean filter(Packet packet, XMPPResourceConnection session) {
		long start = System.currentTimeMillis();
		filteredMessages++;

		boolean result = filterPacket(packet, session);

		long time = System.currentTimeMillis() - start;
		avgProcessingTime = (avgProcessingTime + time) / 2L;
		totalProcessingTime += time;

		if (!result) {
			spamMessages++;
		}

		return result;
	}

	@Override
	public void getStatistics(String name, StatisticsList list) {
		if (list.checkLevel(Level.FINE)) {
			list.add(name, getId() + "/Filtered packets", filteredMessages, Level.FINE);
			list.add(name, getId() + "/Spam messages", spamMessages, Level.FINE);
			list.add(name, getId() + "/Average processing time", avgProcessingTime, Level.FINE);
			list.add(name, getId() + "/Total processing time", totalProcessingTime, Level.FINE);
		}
	}

	protected abstract boolean filterPacket(Packet packet, XMPPResourceConnection session);
}
