/*
 * Tigase Spam Filter - SPAM filters for Tigase XMPP Server
 * Copyright (C) 2017 Tigase, Inc. (office@tigase.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3 of the License.
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
package tigase.spam.adhocs;

import tigase.component.adhoc.AdHocCommand;
import tigase.component.adhoc.AdHocCommandException;
import tigase.component.adhoc.AdHocResponse;
import tigase.component.adhoc.AdhHocRequest;
import tigase.component.modules.impl.AdHocCommandModule;
import tigase.kernel.beans.Bean;
import tigase.kernel.beans.Inject;
import tigase.server.Command;
import tigase.server.DataForm;
import tigase.server.xmppsession.SessionManager;
import tigase.spam.SpamProcessor;
import tigase.spam.filters.KnownSpammersFilter;
import tigase.xml.Element;
import tigase.xmpp.Authorization;
import tigase.xmpp.jid.BareJID;
import tigase.xmpp.jid.JID;

import java.util.Collection;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

@Bean(name = "listKnownSpammers", parent = SessionManager.class, active = true)
public class ListKnownSpammers implements AdHocCommand {

	private static final Logger log = Logger.getLogger(ListKnownSpammers.class.getCanonicalName());

	@Inject
	private AdHocCommandModule.ScriptCommandProcessor scriptCommandProcessor;

	@Inject(nullAllowed = true)
	private SpamProcessor spamProcessor;
	
	@Override
	public void execute(AdhHocRequest request, AdHocResponse response) throws AdHocCommandException {
		try {
			final Element data = request.getCommand().getChild("x", "jabber:x:data");

			if (request.getAction() != null && "cancel".equals(request.getAction())) {
				response.cancelSession();
			} else {
				DataForm.Builder builder = new DataForm.Builder(Command.DataType.form);
				Optional<String> filter = Optional.ofNullable(DataForm.getFieldValue(data, "filter"));
				int limit = Optional.ofNullable(DataForm.getFieldValue(data, "limit")).map(value -> {
					try {
						return Integer.parseInt(value);
					} catch (Throwable ex) {
						return null;
					}
				}).orElse(25);

				Optional<Collection<KnownSpammersFilter.Spammer>> spammers = Optional.ofNullable(spamProcessor)
						.map(SpamProcessor::getSpammers);
				if (spammers.isPresent()) {
					builder.addField(DataForm.FieldType.TextSingle, "filter")
							.setLabel("Filter only spammers which contain")
							.setValue(filter.orElse(null)).build();
					builder.addField(DataForm.FieldType.TextSingle, "limit")
							.setLabel("Max no. of returned entries")
							.setValue(String.valueOf(limit)).build();
					builder.addField(DataForm.FieldType.JidMulti, "spammers")
							.setLabel("List of known spammers")
							.setValues(spammers.get()
											   .stream()
											   .map(KnownSpammersFilter.Spammer::getJID)
											   .map(BareJID::toString)
											   .filter(jid -> filter.isEmpty() || filter.filter(str -> jid.contains(str)).isPresent())
											   .sorted().limit(limit)
											   .toArray(String[]::new)).build();
				} else {
					builder.addField(DataForm.FieldType.Fixed, "note").setLabel("Warning").setValue("Known spammers storage is unavailable.").build();
				}
				response.setNewState(AdHocResponse.State.executing);
				response.getElements().add(builder.build());
				response.completeSession();
			}
		} catch (Exception e) {
			log.log(Level.FINEST, "Error during processing command", e);
			throw new AdHocCommandException(Authorization.INTERNAL_SERVER_ERROR, e.getMessage());
		}
	}

	@Override
	public String getName() {
		return "List known spammers";
	}

	@Override
	public String getNode() {
		return "list-known-spammers";
	}

	@Override
	public boolean isAllowedFor(JID jid) {
		return scriptCommandProcessor.isAllowed(getNode(), jid);
	}


}
