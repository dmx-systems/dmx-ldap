package de.deepamehta.ldap.profileservice.repository.jndi;


import de.deepamehta.ldap.Configuration;
import de.deepamehta.ldap.PluginLog;
import de.deepamehta.ldap.profileservice.model.LdapAttribute;
import de.deepamehta.ldap.profileservice.model.Session;
import de.deepamehta.ldap.profileservice.repository.LdapRepository;

import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.LdapContext;


public class JndiLdapRepository implements LdapRepository {

    private final ContextManager contextManager;

    public JndiLdapRepository(Configuration configuration, PluginLog log) {
        this.contextManager = new ContextManager(configuration, log);
    }

    @Override
    public Session openConnection(String uid, String password) {
        LdapContext result = contextManager.openConnection(uid, password);
        return result != null
                ? new JndiSession(uid, result)
                : null;
    }

    @Override
    public void closeConnection(Session session) {
        contextManager.closeQuietly(ourSession(session).context);
    }

    @Override
    public boolean storeAttribute(Session session, LdapAttribute attribute, String encodedValue) {
        JndiSession jndiSession = ourSession(session);

        // get the search expression for the uid
        String entryDN = contextManager.dnByUid(jndiSession.uid);

        return contextManager.store(() -> {
            ModificationItem mi = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                    new BasicAttribute(attribute.getLdapAttributeName(), encodedValue));

            jndiSession.context.modifyAttributes(entryDN, new ModificationItem[]{mi});
        });

    }

    @Override
    public String loadAttribute(Session session, LdapAttribute attribute) {
        JndiSession jndiSession = ourSession(session);

        // get the search expression for the uid
        String entryDN = contextManager.dnByUid(jndiSession.uid);

        return contextManager.load(() ->
                jndiSession.context
                        .getAttributes(entryDN, new String[]{attribute.getLdapAttributeName()})
                        .get(attribute.getLdapAttributeName())
                        .get().toString());
    }

    private JndiSession ourSession(Session session) {
        try {
            return (JndiSession) session;
        } catch (ClassCastException exception) {
            throw new IllegalStateException(
                    String.format(
                            "API was called with wrong session instance. Must be %s",
                            JndiSession.class.getName()));
        }
    }

    class JndiSession implements Session {

        final String uid;

        final LdapContext context;

        JndiSession(String uid, LdapContext context) {
            this.uid = uid;
            this.context = context;
        }

    }
}
