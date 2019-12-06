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
import tigase.server.Message;
import tigase.server.Packet;
import tigase.spam.SpamProcessor;
import tigase.xmpp.NotAuthorizedException;
import tigase.xmpp.StanzaType;
import tigase.xmpp.XMPPResourceConnection;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by andrzej on 08.04.2017.
 */
@Bean(name = MucMessageFilterEnsureToFullJid.ID, parent = SpamProcessor.class, active = true)
public class MucMessageFilterEnsureToFullJid
		extends AbstractSpamFilter {

	protected static final String ID = "muc-message-ensure-to-full-jid";
	private static final Logger log = Logger.getLogger(MucMessageFilterEnsureToFullJid.class.getCanonicalName());

	@Override
	public String getId() {
		return ID;
	}

	@Override
	protected boolean filterPacket(Packet packet, XMPPResourceConnection session) {
		if (packet.getElemName() != Message.ELEM_NAME || packet.getType() != StanzaType.groupchat) {
			return true;
		}

		try {
			if (session != null && session.isAuthorized()) {
				if (session.isUserId(packet.getStanzaTo().getBareJID())) {
					if (packet.getStanzaTo().getResource() == null) {
						return false;
					}
					return true;
				}
			} else {
				// Need to allow this kind of messages as I cannot confirm that they are messages which are incoming
				// to the user. And even if they are incoming to the user and user is offline (disconnected) they
				// will be dropped.
				//
				// `false` caused issues with disconnection and redelivery of packets not acked by stream management.
				return true;
			}
		} catch (NotAuthorizedException ex) {
			log.log(Level.FINEST, "Could not compare packet " + packet +
					" destination with session bare jid as session is not authorized yet", ex);
			return true;
		}
		return true;
	}

}
