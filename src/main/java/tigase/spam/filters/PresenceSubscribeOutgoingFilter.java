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
import tigase.server.Packet;
import tigase.spam.SpamProcessor;
import tigase.xmpp.NoConnectionIdException;
import tigase.xmpp.StanzaType;
import tigase.xmpp.XMPPResourceConnection;

import java.util.LinkedList;
import java.util.List;

/**
 * This class just filters outgoing presence-subscribe requests. For better SPAM filtering please use
 * PresenceSubscribeFilter.
 */
@Bean(name = PresenceSubscribeOutgoingFilter.ID, parent = SpamProcessor.class, active = false)
public class PresenceSubscribeOutgoingFilter extends AbstractSpamFilter {

	protected static final String ID = "presence-subscribe-outgoing";

	@ConfigField(desc = "Number of allowed subscription requests per minute")
	private int numberOfAllowedRequestsPerMinute = 5;

	@Override
	public String getId() {
		return ID;
	}

	@Override
	public double getSpamProbability() {
		return 0.4;
	}

	@Override
	protected boolean filterPacket(Packet packet, XMPPResourceConnection session) {
		if (packet.getType() == StanzaType.subscribe && packet.getPacketFrom() != null && session.isAuthorized()) {
			try {
				if (packet.getPacketFrom().equals(session.getConnectionId())) {
					Counter counter = (Counter) session.computeCommonSessionDataIfAbsent(ID, x -> new Counter());
					return counter.check(numberOfAllowedRequestsPerMinute);
				}
			} catch (NoConnectionIdException e) {
				// this should not happen
			}
		}
		return true;
	}

	public static class Counter {

		protected List<Long> timestamps = new LinkedList<>();

		public synchronized boolean check(int limit) {
			timestamps.add(System.currentTimeMillis());
			cleanUp();
			if (timestamps.size() > limit) {
				while (timestamps.size() > limit) {
					timestamps.remove(0);
				}
				return false;
			}
			return true;
		}

		public synchronized boolean cleanUp() {
			while ((!timestamps.isEmpty()) && (System.currentTimeMillis() - timestamps.get(0)) > (60 * 1000)) {
				timestamps.remove(0);
			}
			return timestamps.isEmpty();
		}

	}
}
