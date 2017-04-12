package tigase.spam;

import tigase.db.NonAuthUserRepository;
import tigase.kernel.beans.Bean;
import tigase.kernel.beans.Inject;
import tigase.kernel.beans.RegistrarBean;
import tigase.kernel.beans.config.ConfigField;
import tigase.kernel.core.Kernel;
import tigase.server.Packet;
import tigase.server.xmppsession.SessionManager;
import tigase.stats.StatisticsList;
import tigase.xmpp.XMPPPreprocessorIfc;
import tigase.xmpp.XMPPResourceConnection;
import tigase.xmpp.impl.annotation.AnnotatedXMPPProcessor;
import tigase.xmpp.impl.annotation.Id;

import java.util.Map;
import java.util.Queue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import static tigase.spam.SpamProcessor.ID;

/**
 * Created by andrzej on 08.04.2017.
 */
@Id(ID)
@Bean(name = ID, parent = SessionManager.class, active = false)
public class SpamProcessor
		extends AnnotatedXMPPProcessor
		implements XMPPPreprocessorIfc, RegistrarBean {

	protected static final String ID = "spam-filter";

	private static final Logger log = Logger.getLogger(SpamProcessor.class.getCanonicalName());

	@Inject
	private CopyOnWriteArrayList<SpamFilter> filters = new CopyOnWriteArrayList<>();

	@ConfigField(desc = "Return error if packet is dropped", alias = "return-error")
	private boolean returnError = false;

	@Override
	public boolean preProcess(Packet packet, XMPPResourceConnection session,
							  NonAuthUserRepository nonAuthUserRepository, Queue<Packet> queue,
							  Map<String, Object> map) {
		for (SpamFilter filter : filters) {
			
			if (!filter.filter(packet, session)) {
				if (log.isLoggable(Level.FINEST)) {
					log.log(Level.FINEST, "filter {0} detected spam message {1}, sending error = {2}",
							new Object[]{filter.getId(), packet, returnError});
				}
				if (!returnError) {
					packet.processedBy(ID);
				}
				return true;
			}
		}
		return false;
	}

	@Override
	public void register(Kernel kernel) {
		
	}

	@Override
	public void unregister(Kernel kernel) {

	}

	@Override
	public void getStatistics(StatisticsList list) {
		super.getStatistics(list);
		filters.forEach(filter -> filter.getStatistics(this.id(), list));
	}
}
