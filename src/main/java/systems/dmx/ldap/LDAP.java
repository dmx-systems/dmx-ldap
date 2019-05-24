package systems.dmx.ldap;

interface LDAP {

    boolean checkCredentials(String user, String password);

    boolean createUser(String user, String password, CompletableAction actionOnSuccess);

    boolean changePassword(String user, String password);

    static LDAP newInstance(Configuration configuration, PluginLog pluginLog) {
        switch (configuration.implementation) {
            default:
            case JNDI:
                return new JndiLDAP(configuration, pluginLog);
            case APACHE:
                return new ApacheLDAP(configuration, pluginLog);
        }
    }

    public interface CompletableAction {

        default boolean run(String userName) {
            return true;
        }

    }

}
