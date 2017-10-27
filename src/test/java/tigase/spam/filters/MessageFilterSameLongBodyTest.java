package tigase.spam.filters;

import org.junit.Ignore;
import org.junit.Test;
import tigase.server.Packet;
import tigase.stats.StatisticsList;
import tigase.util.stringprep.TigaseStringprepException;
import tigase.xml.Element;

import java.util.ArrayDeque;
import java.util.Queue;
import java.util.logging.Level;

/**
 * Created by andrzej on 10.06.2017.
 */
@Ignore
public class MessageFilterSameLongBodyTest {

	public static final String SPAM_MESSAGE = "Here we need some long and ugly spam message!";

	@Test
	public void test() throws TigaseStringprepException, InterruptedException {
		MessageFilterSameLongBody filter = new MessageFilterSameLongBody();


		long start = System.currentTimeMillis();

		executeTest(() -> {
			for (int i=0; i < 50; i++) {
				long begin = System.currentTimeMillis();
				for (int j = 0; j < 10000; j++) {
					try {
						Packet spamMessage = createSpamMessage();
						filter.filter(spamMessage, null);
					} catch (Exception ex) {
						ex.printStackTrace();
					}
				}
				StatisticsList list = new StatisticsList(Level.FINEST);
				filter.getStatistics("SPAM", list);

				if (list.getValue("SPAM", "message-same-long-body/Average processing time", 0L) != 0) {
					list.forEach(rec -> {
						System.out.println(rec.toString());
					});
				}
				System.out.println("10000 messages in " + (System.currentTimeMillis() - begin) + "ms, " + (System.currentTimeMillis() - begin)/10000 + " per message");
			}
		});

		System.out.println("completed in " + (System.currentTimeMillis() - start) + "ms");
	}

	public void executeTest(Runnable task) throws InterruptedException {
		Queue<Thread> threads = new ArrayDeque<>();
		for (int i=0; i<Runtime.getRuntime().availableProcessors() * 8; i++) {
			Thread thread = new Thread(task);
			thread.start();
			threads.offer(thread);
		}

		Thread thread = null;
		while ((thread = threads.poll()) != null) {
			thread.join();
		}
	}

	public Packet createSpamMessage() throws TigaseStringprepException {
		return Packet.packetInstance(createSpamMessageEl());
	}

	public Element createSpamMessageEl() {
		return new Element("message", new Element[] {
				new Element("body", SPAM_MESSAGE)
		}, new String[] {
				"from", "to"
		}, new String[] {
				"spammer@example.com", "recipient@example.com"
		});
	}


}
