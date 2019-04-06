package de.deepamehta.ldap;

import org.apache.commons.lang.StringUtils;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.password.PasswordUtil;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

class ApacheLDAP implements LDAP {

    private final Configuration configuration;

    private final PluginLog pluginLog;

    private final LdapConnectionConfig defaultConnectionConfig;

    ApacheLDAP(Configuration configuration, PluginLog pluginLog) {
        this.configuration = configuration;
        this.pluginLog = pluginLog;

        defaultConnectionConfig = createConfig(configuration.manager, configuration.password);
    }

    private LdapConnectionConfig createConfig(String user, String password) {
        LdapConnectionConfig cc = new LdapConnectionConfig();
        cc.setName(user);
        cc.setCredentials(password);
        cc.setLdapHost(configuration.server);
        cc.setLdapPort(Integer.parseInt(configuration.port));
        if (configuration.protocol == Configuration.ProtocolType.LDAPS) {
            cc.setUseSsl(true);
        } else if (configuration.protocol == Configuration.ProtocolType.STARTTLS) {
            cc.setUseTls(true);
        }

        return cc;
    }

    interface LdapAction {
        void run(LdapConnection connection);
    }

    private void whenBound(String userDn, String password, LdapAction action) {
        LdapConnection connection = new LdapNetworkConnection(defaultConnectionConfig);

        try {
            // Binds to the admin user
            connection.bind(userDn, password);

            // Runs the command
            action.run(connection);

        } catch (LdapException le) {
            throw new RuntimeException("Error opening LDAP connection.", le);
        } finally {
            closeQuietly(connection);
        }
    }

    @Override
    public boolean checkCredentials(String user, String password) {
        AtomicBoolean result = new AtomicBoolean(false);

        // Bind with manager privileges
        whenBound(configuration.manager, configuration.password, (connection) -> {
            String searchFilter = StringUtils.isEmpty(configuration.userFilter)
                    ? String.format("(%s=%s)", configuration.userAttribute, user)
                    : String.format("(&(%s)(%s=%s))", configuration.userFilter, configuration.userAttribute, user);

            pluginLog.actionHint("Complete filter expression for user lookup: %s", searchFilter);
            pluginLog.actionHint("Search base is: %s", configuration.userBase);
            EntryCursor cursor = null;

            Attribute userPassword = new DefaultAttribute("userPassword");

            try {
                cursor = connection.search(configuration.userBase, searchFilter, SearchScope.ONELEVEL, userPassword.getId());

                if (!cursor.next()) {
                    pluginLog.actionWarning("Lookup using search filter was empty.", null);
                    return;
                }

                Entry entry = cursor.get();

                if (cursor.next()) {
                    pluginLog.actionWarning("Ambiguity in LDAP CN query: Matched multiple users for the accountName", null);
                    return;
                }

                pluginLog.actionHint("Lookup using search filter returned a single non-empty result.");

                if (!entry.contains(userPassword)) {
                    pluginLog.actionWarning("Result does not contains the requested userPassword attribute.", null);
                    return;
                }

                result.set(PasswordUtil.compareCredentials(
                        password.getBytes(),
                        entry.get(userPassword.getId()).get().getBytes()));

                pluginLog.actionHint("Password comparison: %s", result.get() ? "SUCEEDED" : "FAILED");

            } catch (CursorException | LdapException le) {
                throw new RuntimeException("Error while checking credentials.", le);
            } finally {
                closeQuietly(cursor);
            }
        });

        return result.get();
    }

    private void closeQuietly(Closeable cursor) {
        if (cursor != null) {
            try {
                cursor.close();
            } catch (IOException ioe) {
                pluginLog.actionWarning("Exception when closing resource.", ioe);
            }
        }

    }

    @Override
    public boolean createUser(String user, String password, CompletableAction actionOnSuccess) {
        // TODO: Implement

        return false;
    }

    @Override
    public boolean changePassword(String user, String password) {
        // TODO: Implement

        return false;
    }


}
