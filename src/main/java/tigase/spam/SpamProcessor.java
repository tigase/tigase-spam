package tigase.spam;

import tigase.db.NonAuthUserRepository;
import tigase.db.TigaseDBException;
import tigase.osgi.ModulesManagerImpl;
import tigase.server.Packet;
import tigase.spam.filters.MessageFilterSameLongBody;
import tigase.spam.filters.MucMessageFilterEnsureToFullJid;
import tigase.stats.StatisticsList;
import tigase.xmpp.XMPPPreprocessorIfc;
import tigase.xmpp.XMPPResourceConnection;
import tigase.xmpp.impl.annotation.AnnotatedXMPPProcessor;
import tigase.xmpp.impl.annotation.Id;

import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Created by andrzej on 08.04.2017.
 */
@Id(SpamProcessor.ID)
public class SpamProcessor
		extends AnnotatedXMPPProcessor
		implements XMPPPreprocessorIfc {

	protected static final String ID = "spam-filter";

	private static final Logger log = Logger.getLogger(SpamProcessor.class.getCanonicalName());

	private static final String[] DEFAULT_FILTERS = {MessageFilterSameLongBody.class.getCanonicalName(),
													 MucMessageFilterEnsureToFullJid.class.getCanonicalName()};

	private List<SpamFilter> filters = new CopyOnWriteArrayList<>();

	private boolean returnError = false;

	@Override
	public void init(Map<String, Object> settings) throws TigaseDBException {
		super.init(settings);

		returnError = (Boolean) settings.getOrDefault("return-error", false);

		String[] filterClasses = (String[]) settings.getOrDefault("filter-classes", DEFAULT_FILTERS);
		if (filterClasses != null) {
			for (String cls : filterClasses) {
				try {
					SpamFilter filter = (SpamFilter) ModulesManagerImpl.getInstance().forName(cls).newInstance();
					Map<String, Object> props = settings.entrySet()
							.stream()
							.filter(e -> e.getKey().startsWith(filter.getId() + "-"))
							.collect(Collectors.toMap(e -> e.getKey().replace(filter.getId() + "-", ""),
													  e -> e.getValue()));
					filter.init(props);
					filters.add(filter);
				} catch (Exception ex) {
					log.log(Level.WARNING, "Could not initialize SPAM filter " + cls);
				}
			}
		}
	}

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
	public void getStatistics(StatisticsList list) {
		super.getStatistics(list);
		filters.forEach(filter -> filter.getStatistics(this.id(), list));
	}
}
