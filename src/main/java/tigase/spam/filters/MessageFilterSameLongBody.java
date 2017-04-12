package tigase.spam.filters;

import tigase.server.Message;
import tigase.server.Packet;
import tigase.spam.SpamFilter;
import tigase.stats.StatisticsList;
import tigase.util.Algorithms;
import tigase.xmpp.StanzaType;
import tigase.xmpp.XMPPResourceConnection;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by andrzej on 08.04.2017.
 */
public class MessageFilterSameLongBody implements SpamFilter {

	private static final Logger log = Logger.getLogger(MessageFilterSameLongBody.class.getCanonicalName());

	private static final Charset CHARSET_UTF8 = Charset.forName("utf-8");

	private static final String ID = "message-same-long-body";

	private final ConcurrentHashMap<String,Integer> counter = new ConcurrentHashMap<>();

	private int longMessageSize = 100;

	private int messageCounterSizeLimit = 10000;

	private int messageNumberLimit = 20;

	private final AtomicBoolean cleanerRunning = new AtomicBoolean(false);

	private long filteredMessages = 0L;
	private long spamMessages = 0L;
	private long avgProcessingTime = 0L;

	@Override
	public String getId() {
		return ID;
	}

	@Override
	public void init(Map<String, Object> props) {
		longMessageSize = (Integer) props.getOrDefault("size", 100);
		messageCounterSizeLimit = (Integer) props.getOrDefault("counter-size-limit", 10000);
		messageNumberLimit = (Integer) props.getOrDefault("number-limit", 20);
	}

	@Override
	public boolean filter(Packet packet, XMPPResourceConnection session) {
		if (packet.getElemName() != Message.ELEM_NAME || packet.getType() == StanzaType.groupchat) {
			return true;
		}

		filteredMessages++;

		long start = System.currentTimeMillis();

		try {
			String body = packet.getElemCDataStaticStr(Message.MESSAGE_BODY_PATH);
			if (body == null || body.length() <= longMessageSize) {
				return true;
			}

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String hash = Algorithms.bytesToHex(md.digest(body.getBytes(CHARSET_UTF8)));

			Integer count = counter.compute(hash, (k, v) -> {
				if (v == null) {
					return 1;
				} else {
					return v + 1;
				}
			});

			if (counter.size() > messageCounterSizeLimit) {
				if (cleanerRunning.compareAndSet(false, true)) {
					new CleanerTask().start();
				}
			}

			if (count > messageNumberLimit) {
				spamMessages++;
				if (log.isLoggable(Level.FINEST) && count < (messageNumberLimit + 10)) {
					log.log(Level.FINEST, "Message is assumed to be spam. Already seen {0} message with body: {1}",
							new Object[]{count, body});
				}
				return false;
			}
		} catch (NoSuchAlgorithmException ex) {
			log.log(Level.WARNING, "Algorithm SHA-256 in not available!", ex);
		} finally {
			avgProcessingTime += (System.currentTimeMillis()-start) / 2L;
		}
		return true;
	}

	@Override
	public void getStatistics(String name, StatisticsList list) {
		if (list.checkLevel(Level.FINE)) {
			list.add(name, getId() + "/Filtered messages", filteredMessages, Level.FINE);
			list.add(name, getId() + "/Spam messages", spamMessages, Level.FINE);
			list.add(name, getId() + "/Average processing time", avgProcessingTime, Level.FINE);
			list.add(name, getId() + "/Cache size", counter.size(), Level.FINE);
		}
	}

	private class CleanerTask extends Thread {

		public CleanerTask() {
			super(ID + "-cleaner-task");
		}

		@Override
		public void run() {
			try {
				counter.entrySet()
						.stream()
						.filter(e -> e.getValue() < messageNumberLimit)
						.forEach(e -> counter.remove(e.getKey(), e.getValue()));
			} catch (Throwable ex) {
				log.log(Level.WARNING, "Exception during cleanup of suspected SPAM message counter table", ex);
			}
			cleanerRunning.set(false);
		}
	}
}
