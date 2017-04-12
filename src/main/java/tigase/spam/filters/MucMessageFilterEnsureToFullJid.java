package tigase.spam.filters;

import tigase.server.Message;
import tigase.server.Packet;
import tigase.spam.SpamFilter;
import tigase.stats.StatisticsList;
import tigase.xmpp.NotAuthorizedException;
import tigase.xmpp.StanzaType;
import tigase.xmpp.XMPPResourceConnection;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by andrzej on 08.04.2017.
 */
public class MucMessageFilterEnsureToFullJid
		implements SpamFilter {

	private static final Logger log = Logger.getLogger(MucMessageFilterEnsureToFullJid.class.getCanonicalName());

	private long filteredMessages = 0L;
	private long avgProcessingTime = 0L;
	private long spamMessages = 0L;

	@Override
	public String getId() {
		return "muc-message-ensure-to-full-jid";
	}

	@Override
	public boolean filter(Packet packet, XMPPResourceConnection session) {
		if (packet.getElemName() != Message.ELEM_NAME || packet.getType() != StanzaType.groupchat) {
			return true;
		}

		filteredMessages++;
		long start = System.currentTimeMillis();
		try {
			if (session != null && session.isAuthorized()) {
				if (session.isUserId(packet.getStanzaTo().getBareJID())) {
					if (packet.getStanzaTo().getResource() == null) {
						spamMessages++;
						return false;
					}
					return true;
				}
			} else {
				spamMessages++;
				return false;
			}
		} catch (NotAuthorizedException ex) {
			log.log(Level.FINEST, "Could not compare packet " + packet +
					" destination with session bare jid as session is not authorized yet", ex);
			spamMessages++;
			return false;
		} finally {
			avgProcessingTime += (System.currentTimeMillis()-start) / 2;
		}
		return true;
	}

	@Override
	public void getStatistics(String name, StatisticsList list) {
		if (list.checkLevel(Level.FINE)) {
			list.add(name, getId() + "/Filtered messages", filteredMessages, Level.FINE);
			list.add(name, getId() + "/Spam messages", spamMessages, Level.FINE);
			list.add(name, getId() + "/Average processing time", avgProcessingTime, Level.FINE);
		}
	}
}
