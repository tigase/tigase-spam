package tigase.spam.filters;

import tigase.server.Packet;
import tigase.spam.SpamFilter;
import tigase.stats.StatisticsList;
import tigase.xmpp.XMPPResourceConnection;

import java.util.logging.Level;

/**
 * Created by andrzej on 13.04.2017.
 */
public abstract class AbstractSpamFilter implements SpamFilter {

	private long avgProcessingTime = 0L;
	private long totalProcessingTime = 0L;
	private long filteredMessages = 0L;
	private long spamMessages = 0L;

	protected abstract boolean filterPacket(Packet packet, XMPPResourceConnection session);

	@Override
	public boolean filter(Packet packet, XMPPResourceConnection session) {
		long start = System.currentTimeMillis();
		filteredMessages++;

		boolean result = filterPacket(packet, session);

		long time = System.currentTimeMillis() - start;
		avgProcessingTime += time / 2L;
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
}
