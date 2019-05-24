package systems.dmx.ldap.service;

import systems.dmx.core.Topic;
import systems.dmx.core.service.accesscontrol.Credentials;

public interface LDAPPluginService {

    Topic createUser(Credentials credentials);

    Topic changePassword(Credentials cred);

}
