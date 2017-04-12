package tigase.spam;

import tigase.server.Packet;
import tigase.stats.StatisticsList;
import tigase.xmpp.XMPPResourceConnection;

import java.util.Map;

/**
 * Created by andrzej on 08.04.2017.
 */
public interface SpamFilter {

	boolean filter(Packet packet, XMPPResourceConnection session);

	String getId();

	default void init(Map<String, Object> props) {

	}

	default void getStatistics(String name, StatisticsList list) {

	}
}
