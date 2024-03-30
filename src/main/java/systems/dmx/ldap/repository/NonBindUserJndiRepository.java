package systems.dmx.ldap.repository;

import javax.naming.NamingException;
import java.util.List;

class NonBindUserJndiRepository implements JndiRepository {

    private final JndiDatasource datasource;

    NonBindUserJndiRepository(JndiDatasource datasource) {
        this.datasource = datasource;
    }

    @Override
    public boolean createUser(String username, String password, CompletableAction actionOnSuccess) {
        return false;
    }

    @Override
    public boolean checkCredentials(String username, String password) {
        try {
            datasource.checkCredentials(username, password);
            return true;
        } catch (NamingException e) {
            return false;
        }
    }

    @Override
    public boolean changePassword(String username, String password) {
        return false;
    }

    @Override
    public boolean deleteUser(String user) {
        return false;
    }

    @Override
    public boolean addMember(String group, String user) {
        return false;
    }

    @Override
    public boolean createGroup(String group, String user, List<String> members) {
        return false;
    }

    @Override
    public boolean deleteGroup(String group) {
        return false;
    }

    @Override
    public boolean removeMember(String group, String user) {
        return false;
    }
}
