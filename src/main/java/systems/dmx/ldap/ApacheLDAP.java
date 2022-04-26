package systems.dmx.ldap;

import java.util.List;

class ApacheLDAP implements LDAP {

    private final Configuration configuration;

    private final PluginLog pluginLog;

    ApacheLDAP(Configuration configuration, PluginLog pluginLog) {
        this.configuration = configuration;
        this.pluginLog = pluginLog;

        // TODO: Apache LDAP implementation not provided yet.
        throw new UnsupportedOperationException("Not yet implemented!");
    }

    @Override
    public boolean checkCredentials(String user, String password) {
        // TODO: Implement

        return false;
    }

    @Override
    public boolean createUser(String user, String password, CompletableAction actionOnSuccess) {
        // TODO: Implement

        return false;
    }

    @Override
    public boolean deleteUser(String user) {
        // TODO: Implement

        return false;
    }

    @Override
    public boolean changePassword(String user, String password) {
        // TODO: Implement

        return false;
    }

    @Override
    public boolean addMember(String group, String user) {
        // TODO: Implement

        return false;
    }

    @Override
    public boolean removeMember(String group, String user) {
        // TODO: Implement

        return false;
    }

    @Override
    public boolean createGroup(String group, String user, List<String> members) {
        // TODO: Implement

        return false;
    }

    @Override
    public boolean deleteGroup(String group) {
        // TODO: Implement

        return false;
    }
}
