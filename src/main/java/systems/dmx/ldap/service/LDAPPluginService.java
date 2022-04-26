package systems.dmx.ldap.service;

import systems.dmx.core.Topic;
import systems.dmx.core.service.accesscontrol.Credentials;

public interface LDAPPluginService {

    /**
     * Creates a new user account in the LDAP-connected service.

     * @param Credentials   { username: "username", plaintextPassword: "password" }
     * @return 
     */
    Topic createUser(Credentials credentials);

    /**
     * Updates the password for the user account identified by username in the LDAP-connected service.
     * @param Credentials   { username: "username", plaintextPassword: "password" }
     * @return 
     */
    Topic changePassword(Credentials credentials);

    /**
     * Delete the given user's topic and LDAP user representation.
     *
     * Note: The method requires an open transaction!
     *
     * @param userName
     */
    void deleteUser(String userName);

}
