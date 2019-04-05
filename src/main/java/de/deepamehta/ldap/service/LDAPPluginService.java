package de.deepamehta.ldap.service;

import de.deepamehta.core.Topic;
import de.deepamehta.core.service.accesscontrol.Credentials;
import de.deepamehta.ldap.profileservice.service.ProfileService;

public interface LDAPPluginService {

	Topic createUser(Credentials credentials);

	Topic changePassword(Credentials cred);

	ProfileService getProfileService(Credentials credentials);
	
}
