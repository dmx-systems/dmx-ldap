package systems.dmx.ldap;

interface LDAP {

    boolean checkCredentials(String user, String password);

    boolean createUser(String user, String password, CompletableAction actionOnSuccess);

    boolean changePassword(String user, String password);

    boolean addMember(String groupDn, String user, boolean addManagerIfGroupNotExists);

    boolean removeMember(String groupDn, String user);

    static LDAP newInstance(Configuration configuration, PluginLog pluginLog) {
        switch (configuration.implementation) {
            default:
            case JNDI:
                return new JndiLDAP(configuration, pluginLog);
            case APACHE:
                return new ApacheLDAP(configuration, pluginLog);
        }
    }

    static LDAP newDummyInstance(final PluginLog pluginLog) {
        return new LDAP() {

            private void logError() {
                pluginLog.actionError("LDAP plugin cannot fulfill request as it was not configured correctly.", null);
            }

            @Override
            public boolean checkCredentials(String user, String password) {
                logError();

                return false;
            }

            @Override
            public boolean createUser(String user, String password, CompletableAction actionOnSuccess) {
                logError();

                return false;
            }

            @Override
            public boolean changePassword(String user, String password) {
                logError();

                return false;
            }

            @Override
            public boolean addMember(String groupDn, String user, boolean addManagerIfGroupNotExists) {
                logError();

                return false;
            }

            @Override
            public boolean removeMember(String groupDn, String user) {
                logError();

                return false;
            }
        };
    }

    interface CompletableAction {

        default boolean run(String userName) {
            return true;
        }

    }

}
