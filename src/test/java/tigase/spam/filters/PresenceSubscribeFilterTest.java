/*
 * PresenceSubscribeFilterTest.java
 *
 * Tigase Jabber/XMPP Server - SPAM Filter
 * Copyright (C) 2004-2018 "Tigase, Inc." <office@tigase.com>
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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import tigase.server.Packet;
import tigase.server.Presence;
import tigase.util.stringprep.TigaseStringprepException;
import tigase.xml.Element;
import tigase.xmpp.NotAuthorizedException;
import tigase.xmpp.StanzaType;
import tigase.xmpp.XMPPResourceConnection;
import tigase.xmpp.impl.ProcessorTestCase;
import tigase.xmpp.jid.BareJID;
import tigase.xmpp.jid.JID;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class PresenceSubscribeFilterTest extends ProcessorTestCase {

	private PresenceSubscribeFilter filter;

	@Before
	public void initializeFilter() {
		filter = getKernel().getInstance(PresenceSubscribeFilter.class);
	}

	@After
	public void releaseFilter() {
		filter = null;
	}

	@Override
	public void setupKernel() {
		super.setupKernel();
		getKernel().registerBean(PresenceSubscribeFilter.class).setActive(true).exec();
	}

	@Test
	public void testLocalSpammer()
			throws TigaseStringprepException, NotAuthorizedException {
		JID spammerJid = JID.jidInstance("spammer1@example.com");
		XMPPResourceConnection session = this.getSession(spammerJid, spammerJid);

		for (int i=0; i<10; i++) {
			JID targetJid = JID.jidInstance(UUID.randomUUID().toString(), "example.com");
			Packet packet = createSubscriptionRequest(spammerJid, targetJid);
			assertEquals("test no: " + i, i<5, filter.filterPacket(packet, session));
		}

		filter.cleanUp();

		JID targetJid = JID.jidInstance(UUID.randomUUID().toString(), "example.com");
		Packet packet = createSubscriptionRequest(spammerJid, targetJid);
		assertEquals("test no: 11",false, filter.filterPacket(packet, session));

		cleanUpCounters();
		assertEquals("test 1 after reset",true, filter.filterPacket(packet, session));
	}

	@Test
	public void testRemoteSpammer() throws TigaseStringprepException, NotAuthorizedException {
		JID spammerJid = JID.jidInstance("spammer1@example-ext");

		for (int i=0; i<10; i++) {
			JID targetJid = JID.jidInstance(UUID.randomUUID().toString(), "example.com");
			XMPPResourceConnection session = this.getSession(targetJid, targetJid);
			Packet packet = createSubscriptionRequest(spammerJid, targetJid);
			assertEquals("test no: " + i, i<5, filter.filterPacket(packet, session));
		}

		filter.cleanUp();

		JID targetJid = JID.jidInstance(UUID.randomUUID().toString(), "example.com");
		XMPPResourceConnection session = this.getSession(targetJid, targetJid);
		Packet packet = createSubscriptionRequest(spammerJid, targetJid);
		assertEquals("test no: 11",false, filter.filterPacket(packet, session));

		cleanUpCounters();
		assertEquals("test 1 after reset",true, filter.filterPacket(packet, session));
	}

	private void cleanUpCounters() {
		try {
			Field f = PresenceSubscribeFilter.class
					.getDeclaredField("counters");
			f.setAccessible(true);
			Map<BareJID, PresenceSubscribeFilter.Counter> counters = (Map<BareJID, PresenceSubscribeFilter.Counter>) f
					.get(filter);
			counters.clear();
		} catch (Throwable ex) {}
	}

	private Presence createSubscriptionRequest(JID from, JID to) {
		Presence presence = new Presence(
				new Element("presence", new String[]{"type"}, new String[]{StanzaType.subscribe.name()}), from, to);
		presence.setPacketFrom(from);
		return presence;
	}

}
