/*
 * DumpSpammersList.groovy
 *
 * Tigase Jabber/XMPP Server - SPAM Filter
 * Copyright (C) 2004-2017 "Tigase, Inc." <office@tigase.com>
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

/*

Get any file

AS:Description: Dump spammers list
AS:CommandId: dump-spammers-list
AS:Component: sess-man
*/

package tigase.admin.spam;

import tigase.server.Command
import tigase.server.Packet
import tigase.server.xmppsession.SessionManager
import tigase.spam.SpamProcessor
import tigase.spam.filters.KnownSpammersFilter

import java.util.stream.Collectors

def sessMan = (SessionManager) component
def p = (Packet)packet
def admins = (Set)adminsSet
def stanzaFromBare = p.getStanzaFrom().getBareJID()
def isServiceAdmin = admins.contains(stanzaFromBare)
SpamProcessor spamProcessor = sessMan.preProcessors.get(SpamProcessor.ID);
println("found spamProcessor = " + spamProcessor + " with filters = " + spamProcessor.filters.stream().map({filter -> filter.getClass().getCanonicalName()}).collect(Collectors.toList()));
Optional<KnownSpammersFilter> knownSpammersFilter = spamProcessor == null ? Optional.empty() : spamProcessor.filters.stream().filter({ filter -> filter instanceof KnownSpammersFilter}).map({filter -> (KnownSpammersFilter) filter}).findAny();

def FILE_PATH = "file";
def FORM_TYPE = "dump-spammers";

def filepath = Command.getFieldValue(p, FILE_PATH);
def formType = Command.getFieldValue(p, "form-type");

def result = p.commandResult(filepath ? Command.DataType.result : Command.DataType.form);

def getSpammersByTypeAndDomain = { KnownSpammersFilter filter ->
	return filter.spammers.values().
			stream().
			collect(Collectors.groupingBy({ spammer -> spammer.isLocalUser() },
										  Collectors.groupingBy({ spammer -> spammer.getJID().getDomain() }, Collectors.toList())));
}

Command.addHiddenField(result, "form-type", FORM_TYPE);

if (!isServiceAdmin) {
	Command.addTextField(result, "Error", "You are not service administrator");
}
else if (knownSpammersFilter.isPresent()) {
	if (formType == null) {
		Command.addInstructions(result, "Pass name of a file to which spammers list should be saved or leave blank to receive spammers list within response");
		Command.addFieldValue(result, FILE_PATH, "", "text-single", "File");
	} else if (filepath == null) {
		Map<Boolean, Map<String, List<KnownSpammersFilter.Spammer>>> spammers = getSpammersByTypeAndDomain(
				knownSpammersFilter.get());
		spammers.forEach({ local, domains ->
			List<String> values = domains.entrySet().stream().map({ e ->
				return e.getKey() + ": " + e.getValue().stream().map({ spammer -> spammer.getJID().toString() }).
						sorted().
						collect(Collectors.joining(", "));
			}).toArray({ size -> new String[size]});
			Command.addFieldMultiValue(result, local ? "Local domains" : "Remote domains", values);
		});
	}
	else {
		def file = new File(filepath);
		if (file.exists()) {
			// handle it somehow?
			Command.addTextField(result, "Error", "File already exists!");
		} else {
			if (file.createNewFile()) {
				Map<Boolean, Map<String, List<KnownSpammersFilter.Spammer>>> spammers = getSpammersByTypeAndDomain(
						knownSpammersFilter.get());
				file << "List of known spammers as of " << new Date() << "\n";
				file << "Total spammers count: " << knownSpammersFilter.get().spammers.size() << "\n";
				spammers.forEach({ local, domains ->
					if (local) {
						file << "Local domains: " << domains.size() << "\n";
					} else {
						file << "Remote domains: " << domains.size() << "\n";
					}
					domains.entrySet().stream().sorted({ e -> e.getKey() }).forEach({ e ->
						file << e.getKey() << ": " << e.getValue().
											stream().
											map({ spammer -> spammer.getJID().toString() }).
											sorted().
											collect(Collectors.joining(", ")) << "\n";
					})
				});
				Command.addTextField(result, "Success", "Spammers list dumped to " + file.getAbsolutePath());
			} else {
				Command.addTextField(result, "Error", "Failed to created an output file: " + file.getAbsolutePath());
			}
		}
	}
} else {
	Command.addTextField(result, "Error", "Spam filter is not available");
}

return result;
