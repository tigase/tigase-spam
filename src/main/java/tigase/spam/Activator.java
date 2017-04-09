package tigase.spam;

import org.osgi.framework.*;
import tigase.osgi.ModulesManager;
import tigase.spam.filters.MessageFilterSameLongBody;
import tigase.spam.filters.MucMessageFilterEnsureToFullJid;

import java.util.Arrays;
import java.util.List;

/**
 * Created by andrzej on 09.04.2017.
 */
public class Activator implements BundleActivator, ServiceListener {

	private final List<Class> exportedClasses = Arrays.asList(
			SpamProcessor.class, MessageFilterSameLongBody.class, MucMessageFilterEnsureToFullJid.class
	);
	private BundleContext context;
	private ServiceReference serviceReference;
	private ModulesManager modulesManager;

	@Override
	public void start(BundleContext bc) throws Exception {
		synchronized (this) {
			context = bc;
			bc.addServiceListener(this, "(&(objectClass=" + ModulesManager.class.getName() + "))");
			registerClasses(bc, bc.getServiceReference(ModulesManager.class.getName()));
		}
	}

	@Override
	public void stop(BundleContext bc) throws Exception {
		synchronized (this) {
			unregisterClasses(bc, serviceReference);
			bc.removeServiceListener(this);
			context = null;
		}
	}

	@Override
	public void serviceChanged(ServiceEvent serviceEvent) {
		switch (serviceEvent.getType()) {
			case ServiceEvent.REGISTERED:
				registerClasses(context, serviceEvent.getServiceReference());
				break;
			case ServiceEvent.UNREGISTERING:
				unregisterClasses(context, serviceEvent.getServiceReference());
				break;
			default:
				break;
		}
	}

	private void registerClasses(BundleContext bc, ServiceReference serviceReference) {
		if (serviceReference != null) {
			this.serviceReference = serviceReference;
			modulesManager = (ModulesManager) bc.getService(serviceReference);
			exportedClasses.stream().forEach(modulesManager::registerClass);
		}
	}

	private void unregisterClasses(BundleContext bc, ServiceReference serviceReference) {
		if (modulesManager != null && this.serviceReference == serviceReference) {
			exportedClasses.stream().forEach(modulesManager::unregisterClass);
			bc.ungetService(serviceReference);
			modulesManager = null;
			this.serviceReference = null;
		}
	}
}
