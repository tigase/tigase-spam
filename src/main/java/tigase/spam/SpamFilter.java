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
package tigase.spam;

import tigase.server.Packet;
import tigase.stats.StatisticsList;
import tigase.xmpp.XMPPResourceConnection;

/**
 * Interface which needs to be implemented by all filters used by <code>SpamProcessor</code> to detect spam.
 *
 * Created by andrzej on 08.04.2017.
 */
public interface SpamFilter {

	/**
	 * Method processes packet and checks if it is a SPAM or not
	 *
	 * @return false if message should be dropped as it it a SPAM
	 */
	boolean filter(Packet packet, XMPPResourceConnection session);

	/**
	 * Method returns ID of a filter
	 */
	String getId();

	/**
	 * Method should fill the <code>list</code> parameter value with statistics about processed stanzas.
	 * Default implementation should be used if there are no meaningful values to return.
	 */
	default void getStatistics(String name, StatisticsList list) {

	}

	/**
	 * Method returns probability of detection of a spammer.
	 * If value is closer to 1 this means that it is more likely that sender of stanza marked by this filter as a spam is a spammer and should be blocked.
	 * This value is used by <code>ResultsAwareSpamFilter</code> implementation to decide if sender of a stanza should be blocked (ie. using number of blocked messages within a period of time and spammer detection probability returned by this method.
	 *
	 * @return values between 0 and 1
	 */
	default double getSpamProbability() {
		return 1;
	}
}
