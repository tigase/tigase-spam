/*
 * MessageErrorFilterEnsureErrorChild.java
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

import tigase.kernel.beans.Bean;
import tigase.server.Message;
import tigase.server.Packet;
import tigase.spam.SpamProcessor;
import tigase.xmpp.StanzaType;
import tigase.xmpp.XMPPResourceConnection;

import static tigase.spam.filters.MessageErrorFilterEnsureErrorChild.ID;

/**
 * Created by andrzej on 13.04.2017.
 */
@Bean(name = ID, parent = SpamProcessor.class, active = true)
public class MessageErrorFilterEnsureErrorChild extends AbstractSpamFilter {

	protected static final String ID = "message-error-ensure-error-child";

	@Override
	protected boolean filterPacket(Packet packet, XMPPResourceConnection session) {
		if (packet.getElemName() != Message.ELEM_NAME || packet.getType() != StanzaType.error) {
			return true;
		}

		if (packet.getElement().findChild(el -> el.getName() == "error") != null) {
			return true;
		}

		return false;
	}

	@Override
	public String getId() {
		return ID;
	}
}
