package systems.dmx.ldap.repository;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import systems.dmx.ldap.Configuration;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

class JndiDatasource {

    private static final Logger logger = Logger.getLogger(JndiDatasource.class.getName());
    public static final String LDAP_SEARCH_TEMPLATE = "%s=%s,%s";

    private final Configuration.ProtocolType protocolType;

    private final String connectionUrl;

    private final String userFilter;

    private final String userAttribute;

    private final String userBase;

    private final String userMemberGroup;

    private final String groupBase;

    private final String adminUserName;
    private final String adminDn;

    JndiDatasource(Configuration configuration, String adminUserName, String adminDn) {
        this.protocolType = configuration.protocolType;
        this.connectionUrl = configuration.connectionUrl;
        this.userFilter = configuration.userFilter;
        this.userAttribute = configuration.userAttribute;
        this.userBase = configuration.userBase;
        this.userMemberGroup = configuration.userMemberGroup;
        this.groupBase = configuration.groupBase;
        this.adminUserName = adminUserName;
        this.adminDn = adminDn;
    }

    private String encodePassword(String password) {
        return new LdapShaPasswordEncoder().encode(password);
    }

    void createUser(
            LdapContext ctx,
            String userName,
            String password) throws NamingException {
        String entryDN = String.format(LDAP_SEARCH_TEMPLATE, userAttribute, userName, userBase);

        BasicAttributes entry = createUserNameEntry(userName, encodePassword(password));

        ctx.createSubcontext(entryDN, entry);
        if (StringUtils.isNotEmpty(userMemberGroup)) {
            ModificationItem mi = new ModificationItem(DirContext.ADD_ATTRIBUTE,
                    new BasicAttribute("member", entryDN));

            try {
                ctx.modifyAttributes(userMemberGroup, new ModificationItem[]{mi});
            } catch (NamingException ne) {
                // Removes user
                ctx.destroySubcontext(entryDN);

                // Rethrow
                throw ne;
            }
        }
    }

    private BasicAttributes createUserNameEntry(String userName, String encodedPassword) {
        Attribute cn = new BasicAttribute("cn", userName);
        Attribute sn = new BasicAttribute("sn", "deepamehta-ldap");
        Attribute userPassword = new BasicAttribute("userPassword", encodedPassword);

        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("person");
        oc.add("organizationalPerson");
        oc.add("inetOrgPerson");

        BasicAttributes entry = new BasicAttributes();
        entry.put(oc);
        entry.put(cn);
        entry.put(sn);
        entry.put(userPassword);
        return entry;
    }


    void checkCredentialsWithLookup(LdapContext ctx, String username, String password) throws NamingException {
        logger.info(() -> String.format("Checking credentials for user %s", username));

        LdapContext ctx2 = null;
        try {
            String cn = lookupUserCn(ctx, username);
            if (cn == null) {
                logger.warning(() -> String.format("User %s not found in LDAP", username));
                throw new NamingException();
            }

            ctx2 = connect(cn, password);
        } catch (NamingException ne) {
            logger.warning(() -> String.format("Provided credentials for user %s were wrong", username));
            throw ne;
        } finally {
            closeQuietly(ctx2);
        }
    }

    void checkCredentials(String username, String password) throws NamingException {
        logger.info(() -> String.format("Checking credentials for user %s", username));

        LdapContext ctx = null;
        try {
            String cn = userNameToEntryDn(username);

            ctx = connect(cn, password);
        } catch (NamingException ne) {
            logger.warning(() -> String.format("Provided credentials for user %s were wrong", username));

            throw ne;
        } finally {
            closeQuietly(ctx);
        }
    }


    private String lookupUserCn(LdapContext ctx, String uid) throws NamingException {

        String searchFilter = StringUtils.isEmpty(userFilter)
                ? String.format("(%s=%s)", userAttribute, uid)
                : String.format("(&(%s)(%s=%s))", userFilter, userAttribute, uid);

        logger.info(() -> String.format("Complete filter expression for user lookup: %s", searchFilter));

        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        NamingEnumeration<SearchResult> results = ctx.search(userBase, searchFilter, searchControls);
        logger.info(() -> String.format("Search base is: %s", userBase));

        if (results.hasMoreElements()) {
            logger.info("Lookup using search filter returned non-empty result");

            SearchResult searchResult = (SearchResult) results.nextElement();

            if (results.hasMoreElements()) {
                throw new RuntimeException("Ambiguity in LDAP CN query: Matched multiple users for the accountName");
            }

            return searchResult.getNameInNamespace();
        } else {
            logger.warning("Lookup using search filter was empty.");

            return null;
        }
    }

    /**
     * Encodes and hashes the given plaintext password and issues a "userPassword"
     * attribute replacement call for the given username.
     *
     * @param username String with username
     * @param password String with password in plaintext (not encoded).
     * @return
     */
    void changePassword(LdapContext ctx, String username, String password) throws NamingException {
        logger.info(() -> String.format("Changing password for user %s", username));

        changePasswordImpl(ctx, username, encodePassword(password));
    }

    private void changePasswordImpl(
            LdapContext ctx,
            String userName, String password) throws NamingException {
        String entryDN = userNameToEntryDn(userName);

        ModificationItem mi = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                new BasicAttribute("userPassword", password));

        try {
            ctx.modifyAttributes(entryDN, new ModificationItem[]{mi});
        } catch (NamingException ne) {
            logger.log(Level.WARNING, "Attempt to modify userPassword attribute lead to exception", ne);

            throw ne;
        }
    }

    void deleteUser(LdapContext ctx, String user) throws NamingException {
        try {
            ctx.destroySubcontext(userNameToEntryDn(user));
        } catch (NamingException e) {
            logger.log(Level.SEVERE, String.format("Unable to delete user from LDAP %s", user), e);
            throw e;
        } finally {
            closeQuietly(ctx);
        }
    }

    private String userNameToEntryDn(String userName) {
        return String.format(LDAP_SEARCH_TEMPLATE, userAttribute, userName, userBase);
    }

    LdapContext connect(String username, String password) throws NamingException {
        try {
            LdapContext ctx = new InitialLdapContext(createEnvironment(username, password), null);

            if (protocolType == Configuration.ProtocolType.STARTTLS) {
                logger.info("Attempting TLS negotiation (StartTLS protocol)");

                StartTlsResponse tls = (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
                tls.negotiate();

                logger.info("TLS negotiated successfully.");
            }
            logger.info(() -> String.format("Context for user %s usable", username));

            return ctx;
        } catch (IOException e) {
            throw new RuntimeException("Could not establish TLS connection. Connecting failed.", e);
        }
    }

    private Hashtable<String, Object> createEnvironment(String username, String password) {
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.PROVIDER_URL, connectionUrl);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        // ensures that objectSID attribute values
        // will be returned as a byte[] instead of a String
        env.put("java.naming.ldap.attributes.binary", "objectSID");
        return env;
    }

    void closeQuietly(LdapContext ctx) {
        if (ctx != null) {
            try {
                ctx.close();
            } catch (NamingException ne) {
                logger.log(Level.WARNING, "Exception while closing connection", ne);
            }
        }
    }

    private String groupDn(String groupName) {
        return String.format("cn=%s,%s", groupName, groupBase);
    }


    void createGroup(LdapContext ctx, String group, String user, List<String> members) throws NamingException {
        try {
            String groupDn = groupDn(group);
            String firstMemberDn = resolveUserDn(ctx, user);

            List<String> otherMemberDns = members.stream().map(it -> resolveUserDn(ctx, it)).filter(Objects::nonNull).collect(Collectors.toList());

            createGroupImpl(ctx, groupDn, firstMemberDn, otherMemberDns);
        } finally {
            closeQuietly(ctx);
        }
    }

    private void createGroupImpl(LdapContext ctx, String groupDn, String firstMemberDn, List<String> otherMemberDns) throws NamingException {
        logger.info(() -> String.format("Creating group %s with first member %s and %s other members", groupDn, firstMemberDn, otherMemberDns.size()));
        Attribute member = new BasicAttribute("member", firstMemberDn);

        // Handles other members
        otherMemberDns.forEach(member::add);

        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("groupOfNames");

        BasicAttributes entry = new BasicAttributes();
        entry.put(oc);
        entry.put(member);

        try {
            ctx.createSubcontext(groupDn, entry);
        } catch (NamingException ne) {
            logger.log(Level.SEVERE, "Unable to create group subcontext", ne);

            throw ne;
        }
    }

    void addMember(LdapContext ctx, String groupDn, String user) throws NamingException {
        String userEntryDn = resolveUserDn(ctx, user);
        if (userEntryDn == null) {
            throw new IllegalStateException("User not found");
        }

        try {
            ctx.lookup(groupDn);
        } catch (NamingException ne) {
            logger.info(() -> String.format("Group %s does not exist. Attempting to create it.", groupDn));

            createGroupImpl(ctx, groupDn, userEntryDn, Collections.emptyList());
        }

        // group exists, lets add our user
        ModificationItem mi = new ModificationItem(DirContext.ADD_ATTRIBUTE,
                new BasicAttribute("member", userEntryDn));

        try {
            ctx.modifyAttributes(groupDn, new ModificationItem[]{mi});
        } catch (NamingException ne) {
            logger.log(Level.WARNING, "Attempt to modify member attribute lead to exception", ne);
            throw ne;
        }
    }

    void deleteGroup(LdapContext ctx, String group) throws NamingException {
        String groupDn = groupDn(group);

        try {
            logger.info(() -> String.format("Trying to delete group %s", groupDn));
            ctx.destroySubcontext(groupDn);
        } catch (NamingException ne) {
            logger.log(Level.WARNING, "Attempt to delete group lead to exception", ne);

            throw ne;
        } finally {
            closeQuietly(ctx);
        }
    }

    void removeMember(LdapContext ctx, String group, String user) throws NamingException {
        String groupDn = groupDn(group);
        logger.info(() -> String.format("Removing user %s from group %s", user, groupDn));
        try {
            String userDn = resolveUserDn(ctx, user);
            if (userDn == null) {
                throw new IllegalStateException("User not found");
            }

            removeMemberImpl(ctx, groupDn, userDn);
        } finally {
            closeQuietly(ctx);
        }
    }

    void maybeDeleteGroup(LdapContext ctx, DirContext groupContext, String groupDn, String userEntryDn) throws NamingException {
        try {
            Attribute a = groupContext.getAttributes("").get("member");
            if (a.size() == 1 && userEntryDn.equals(a.get(0))) {
                logger.info(() -> String.format("Group %s is now empty. Attempting to delete.", groupDn));
                ctx.destroySubcontext(groupDn);
            }
        } catch (NamingException ne) {
            logger.warning(() -> String.format("Unable to check membership or delete the group %s", groupDn));
            throw ne;
        }
    }

    private String resolveUserDn(LdapContext ctx, String userName) {
        // Transform userName into DN by regular means.
        String userDn = userNameToEntryDn(userName);

        try {
            ctx.lookup(userDn);

            // User is in LDAP (regardless if admin or not)
            return userDn;
        } catch (NamingException ne) {
            // User is not in LDAP

            // If this is the admin, return the manager instead, otherwise null to indicate that
            // we should not reference this user in LDAP.
            if (userName.equals(adminUserName)) {
                return adminDn;
            } else {
                logger.warning(() -> String.format("Unable to find regular user %s in LDAP. Ignoring", userName));
                return null;
            }
        }
    }

    private void removeMemberImpl(LdapContext ctx, String groupDn, String userEntryDn) throws NamingException {
        DirContext groupContext;
        try {
            groupContext = (DirContext) ctx.lookup(groupDn);
        } catch (NamingException ne) {
            logger.log(Level.WARNING, "Unable to look up group lead to exception", ne);
            throw ne;
        }

        maybeDeleteGroup(ctx, groupContext, groupDn, userEntryDn);

        ModificationItem mi = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                new BasicAttribute("member", userEntryDn));

        try {
            ctx.modifyAttributes(groupDn, new ModificationItem[]{mi});
        } catch (NamingException ne) {
            logger.log(Level.WARNING, "Attempt to modify member attribute lead to exception", ne);

            throw ne;
        }
    }

}
