package systems.dmx.ldap.service;

import systems.dmx.ldap.Configuration;

public interface LDAPService {

    /**
     * Returns the configuration that is in use by the plugin.
     *
     * Other plugins can use the information to check the validity or compatibility
     * of their own configuation with the one from the LDAP plugin.
     *
     * @return The plugin's configuration
     */
    Configuration getConfiguration();

    /**
     * Delete the given user's topic and LDAP user representation.
     *
     * Note: The method requires an open transaction!
     *
     * @param userName
     */
    void deleteUser(String userName);

}
