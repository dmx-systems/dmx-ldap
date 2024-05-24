package systems.dmx.ldap.repository;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

class BindUserJndiRepository implements JndiRepository {

    private static final Logger logger = Logger.getLogger(BindUserJndiRepository.class.getName());

    private final String manager;

    private final String password;

    private final JndiDatasource datasource;

    BindUserJndiRepository(String manager, String password, JndiDatasource datasource) {
        this.manager = manager;
        this.password = password;
        this.datasource = datasource;
    }

    /**
     * Ceates a new user in LDAP-connected service and encodes and hashes the
     * given plaintext password for the user.
     *
     * @param username String with username
     * @param password String with password in plaintext (not encoded).
     * @return
     */
    @Override
    public boolean createUser(String username, String password, CompletableAction actionOnSuccess) {
        LdapContext ctx = null;

        try {
            ctx = connect();

            datasource.createUser(ctx, username, password);

            return actionOnSuccess.run(username);
        } catch (NamingException ne) {
            logger.log(Level.WARNING, "Creating LDAP user did not succeed", ne);
            return false;
        } finally {
            datasource.closeQuietly(ctx);
        }
    }

    @Override
    public boolean checkCredentials(String username, String password) {
        return connectAndDo(ctx -> datasource.checkCredentialsWithLookup(ctx, username, password));
    }

    /**
     * Encodes and hashes the given plaintext password and issues a "userPassword"
     * attribute replacement call for the given username.
     *
     * @param username String with username
     * @param password String with password in plaintext (not encoded).
     * @return
     */
    @Override
    public boolean changePassword(String username, String password) {
        return connectAndDo(ctx -> datasource.changePassword(ctx, username, password));
    }

    @Override
    public boolean deleteUser(String user) {
        return connectAndDo(ctx -> datasource.deleteUser(ctx, user));
    }

    private LdapContext connect() throws NamingException {
        return datasource.connect(manager, password);
    }

    @Override
    public boolean addMember(String group, String user) {
        return connectAndDo(ctx -> datasource.addMember(ctx, group, user));
    }

    @Override
    public boolean createGroup(String group, String user, List<String> members) {
        return connectAndDo(ctx -> datasource.createGroup(ctx, group, user, members));
    }

    @Override
    public boolean deleteGroup(String group) {
        return connectAndDo(ctx -> datasource.deleteGroup(ctx, group));
    }

    @Override
    public boolean removeMember(String group, String user) {
        return connectAndDo(ctx -> datasource.removeMember(ctx, group, user));
    }

    private boolean connectAndDo(ContextRunnable r) {
        LdapContext ctx = null;
        try {
            ctx = connect();

            r.run(ctx);

            return true;
        } catch (NamingException ne) {
            return false;
        } finally {
            datasource.closeQuietly(ctx);
        }

    }

    private interface ContextRunnable {
        void run(LdapContext ctx) throws NamingException;
    }
}
