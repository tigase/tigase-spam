package tigase.spam.filters;

import tigase.kernel.beans.Bean;
import tigase.kernel.beans.config.ConfigField;
import tigase.server.Message;
import tigase.server.Packet;
import tigase.spam.SpamFilter;
import tigase.spam.SpamProcessor;
import tigase.util.Algorithms;
import tigase.xmpp.StanzaType;
import tigase.xmpp.XMPPResourceConnection;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by andrzej on 08.04.2017.
 */
@Bean(name = MessageFilterSameLongBody.ID, parent = SpamProcessor.class, active = true)
public class MessageFilterSameLongBody implements SpamFilter {

	private static final Logger log = Logger.getLogger(MessageFilterSameLongBody.class.getCanonicalName());

	private static final Charset CHARSET_UTF8 = Charset.forName("utf-8");

	protected static final String ID = "message-same-long-body";

	private final ConcurrentHashMap<String,Integer> counter = new ConcurrentHashMap<>();

	@ConfigField(desc = "Check message with body bigger that this limit", alias = "body-size")
	private int longMessageSize = 100;

	@ConfigField(desc = "Limit size of message counter cache", alias = "counter-size-limit")
	private int messageCounterSizeLimit = 10000;

	@ConfigField(desc = "Limit number of message with same body", alias = "number-limit")
	private int messageNumberLimit = 20;

	private final AtomicBoolean cleanerRunning = new AtomicBoolean(false);
	
	@Override
	public String getId() {
		return ID;
	}
	
	@Override
	public boolean filter(Packet packet, XMPPResourceConnection session) {
		if (packet.getElemName() != Message.ELEM_NAME || packet.getType() == StanzaType.groupchat) {
			return true;
		}

		String body = packet.getElemCDataStaticStr(Message.MESSAGE_BODY_PATH);
		if (body == null || body.length() <= longMessageSize) {
			return true;
		}

		try {
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

			boolean result = count <= messageNumberLimit;

			if (log.isLoggable(Level.FINEST) && !result && count < 30) {
				log.log(Level.FINEST, "Message is assumed to be spam. Already seen {0} message with body: {1}",
						new Object[]{count, body});
			}

			return result;
		} catch (NoSuchAlgorithmException ex) {
			log.log(Level.WARNING, "Algorithm SHA-256 in not available!", ex);
		}
		return true;
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
