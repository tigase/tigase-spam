/*
 * Activator.java
 *
 * Tigase Jabber/XMPP Server
 * Copyright (C) 2004-2017 "Tigase, Inc." <office@tigase.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
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
package tigase.spam;

import org.osgi.framework.*;
import tigase.osgi.ModulesManager;
import tigase.spam.filters.KnownSpammersFilter;
import tigase.spam.filters.MessageErrorFilterEnsureErrorChild;
import tigase.spam.filters.MessageFilterSameLongBody;
import tigase.spam.filters.MucMessageFilterEnsureToFullJid;

import java.util.Arrays;
import java.util.List;

/**
 * Created by andrzej on 09.04.2017.
 */
public class Activator implements BundleActivator, ServiceListener {

	private final List<Class> exportedClasses = Arrays.asList(
			SpamProcessor.class, MessageFilterSameLongBody.class, MucMessageFilterEnsureToFullJid.class,
			KnownSpammersFilter.class, MessageErrorFilterEnsureErrorChild.class
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
