package systems.dmx.ldap;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.*;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.util.Hashtable;
import java.util.List;

class NonManagerJndiLDAP implements LDAP {

    private final Configuration configuration;

    private final PluginLog pluginLog;

    NonManagerJndiLDAP(Configuration configuration, PluginLog log) {
        this.configuration = configuration;
        this.pluginLog = log;
    }

    @Override
    public boolean createUser(String username, String password, CompletableAction actionOnSuccess) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean deleteUser(String user) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean checkCredentials(String username, String password) {
        pluginLog.actionHint("Checking credentials for user %s", username);

        LdapContext ctx = null;
        try {
            String url = configuration.connectionUrl;

            String cn = userNameToEntryDn(username);

            ctx = connect(url, cn, password);

            if (ctx == null) {
                pluginLog.actionHint("Provided credentials for user %s were wrong", username);
            }

            return ctx != null;
        } finally {
            closeQuietly(ctx);
        }
    }

    @Override
    public boolean changePassword(String username, String password) {
        throw new UnsupportedOperationException();
    }

    private String userNameToEntryDn(String userName) {
        return String.format("%s=%s,%s", configuration.userAttribute, userName, configuration.userBase);
    }

    private LdapContext connect(String serverUrl, String username, String password) {
        pluginLog.actionHint("creating LDAP connection using URL %s and username %s", serverUrl, username);

        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.PROVIDER_URL, serverUrl);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        // ensures that objectSID attribute values
        // will be returned as a byte[] instead of a String
        env.put("java.naming.ldap.attributes.binary", "objectSID");

        // Platform-specific logging options
        if (configuration.loggingMode == Configuration.LoggingMode.DEBUG) {
            pluginLog.actionHint("Enabling detailed SSL logging");
            System.setProperty("javax.net.debug", "all");
        }

        Control[] arr = new Control[0];
        try {
            LdapContext ctx = new InitialLdapContext(env, arr);
            pluginLog.actionHint("Initial context created");

            if (configuration.protocol == Configuration.ProtocolType.STARTTLS) {
                pluginLog.actionHint("Attempting TLS negotiation (StartTLS protocol)");

                StartTlsResponse tls = (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
                SSLSession session = tls.negotiate();

                pluginLog.actionHint("TLS negotiated successfully.");
            }
            pluginLog.actionHint("Initial context usable");

            return ctx;
        } catch (NamingException e) {
            // When used as part of checkCredentials an exception at this point is not grave
            pluginLog.actionWarning("Attempting to connect to LDAP server lead to Exception", e);

            return null;
        } catch (IOException e) {
            throw new RuntimeException("Could not establish TLS connection. Connecting failed.", e);
        }
    }

    private void closeQuietly(LdapContext ctx) {
        if (ctx != null) {
            try {
                ctx.close();
            } catch (NamingException ne) {
                pluginLog.actionWarning("Exception while closing connection", ne);
            }
        }
    }

    @Override
    public boolean addMember(String group, String user) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean createGroup(String group, String user, List<String> members) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean deleteGroup(String group) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean removeMember(String group, String user) {
        throw new UnsupportedOperationException();
    }
}
