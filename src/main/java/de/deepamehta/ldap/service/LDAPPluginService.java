package de.deepamehta.ldap.service;

import de.deepamehta.core.Topic;
import de.deepamehta.core.service.accesscontrol.Credentials;

public interface LDAPPluginService {

	Topic createUser(Credentials credentials);

	Topic changePassword(Credentials cred);
	
}
