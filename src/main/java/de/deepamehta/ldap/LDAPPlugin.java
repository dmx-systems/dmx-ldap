package de.deepamehta.ldap;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Hashtable;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.SSLSession;

import de.deepamehta.accesscontrol.AccessControlService;
import de.deepamehta.accesscontrol.AuthorizationMethod;
import de.deepamehta.core.Topic;
import de.deepamehta.core.osgi.PluginActivator;
import de.deepamehta.core.service.Inject;
import de.deepamehta.core.service.accesscontrol.Credentials;
import de.deepamehta.core.storage.spi.DeepaMehtaTransaction;
import de.deepamehta.ldap.service.LDAPPluginService;


public class LDAPPlugin extends PluginActivator implements AuthorizationMethod, LDAPPluginService {

    private static Logger logger = Logger.getLogger(LDAPPlugin.class.getName());
    
    private static final String LDAP_SERVER = System.getProperty("dm4.ldap.server", "127.0.0.1");
    private static final String LDAP_PORT = System.getProperty("dm4.ldap.port");
    private static final String LDAP_MANAGER = System.getProperty("dm4.ldap.manager", "");
    private static final String LDAP_PASSWORD = System.getProperty("dm4.ldap.password", "");
    private static final String LDAP_USER_BASE = System.getProperty("dm4.ldap.user_base", "");
    private static final String LDAP_USER_ATTRIBUTE = System.getProperty("dm4.ldap.user_attribute", "");
    private static final String LDAP_FILTER = System.getProperty("dm4.ldap.filter", "");
    private static final String LDAP_PROTOCOL = System.getProperty("dm4.ldap.protocol", "");

    private static final String LDAP_USER_CREATION_ENABLED = System.getProperty("dm4.ldap.user_creation.enabled", "false");
    private static final String LDAP_MEMBER_GROUP = System.getProperty("dm4.ldap.member_group", "");

    private static final String LDAP_PASSWORD_HASH_METHOD = System.getProperty("dm4.ldap.password_hash.method", "SHA");
    private static final String LDAP_PASSWORD_HASH_SALT = System.getProperty("dm4.ldap.password_hash.salt", "");

    // ---------------------------------------------------------------------------------------------- Instance Variables

    @Inject
    private AccessControlService acs;



    // ****************************
    // *** Hook Implementations ***
    // ****************************



    @Override
    public void serviceArrived(Object service) {
        ((AccessControlService) service).registerAuthorizationMethod("LDAP", this);
    }

    @Override
    public void serviceGone(Object service) {
        ((AccessControlService) service).unregisterAuthorizationMethod("LDAP");
    }



    // ******************************************
    // *** AuthorizationMethod implementation ***
    // ******************************************



    @Override
    public Topic checkCredentials(Credentials cred) {
    	String saltedPassword = LDAP_PASSWORD_HASH_SALT + cred.plaintextPassword;
        if (checkLdapCredentials(cred.username, saltedPassword)) {
            logger.info("LDAP login: OK");
            Topic usernameTopic = acs.getUsernameTopic(cred.username);
            if (usernameTopic != null) {
                return usernameTopic;
            } else {
                return createUsernameTopic(cred.username);
            }
        } else {
            return null;
        }
    }

    @Override
    public Topic createUser(Credentials cred) {
    	if (!LDAP_USER_CREATION_ENABLED.equals("true")) {
    		logger.warning("User creation is disabled in plugin configuration!");
    		return null;
    	}
    	
    	String hashedPassword = null;
    	try {
    		hashedPassword = hashPassword(cred.plaintextPassword);
    	} catch (NoSuchAlgorithmException nsa) {
    		logger.info("Invalid hash algorithm: " + LDAP_PASSWORD_HASH_METHOD);
    		
    		return null;
    	}

    	if (createUser(LDAP_USER_BASE, LDAP_USER_ATTRIBUTE, cred.username, hashedPassword, LDAP_MEMBER_GROUP)) {
            logger.info("LDAP create user: OK");
            Topic usernameTopic = acs.getUsernameTopic(cred.username);
            if (usernameTopic != null) {
                return usernameTopic;
            } else {
                return createUsernameTopic(cred.username);
            }
    		
    	} else {
        	return null;
    	}
    	
    }

    // ------------------------------------------------------------------------------------------------- Private Methods
    
    private String hashPassword(String password) throws NoSuchAlgorithmException {
    	MessageDigest digest = MessageDigest.getInstance(LDAP_PASSWORD_HASH_METHOD);
    	
    	String saltedPassword = LDAP_PASSWORD_HASH_SALT + password;
    	
    	byte[] base64Hash = Base64.getEncoder().encode(digest.digest(saltedPassword.getBytes(StandardCharsets.UTF_8)));
    	
    	String result = String.format("{%s}%s", LDAP_PASSWORD_HASH_METHOD.replace("-", ""), new String(base64Hash));
    	
    	return result;
    }
    
    private static LdapContext createDefaultContext() throws NamingException {
        return createContext(LDAP_PROTOCOL, LDAP_SERVER, LDAP_PORT, LDAP_MANAGER, LDAP_PASSWORD);
    }
    
    private static LdapContext createContext(
    		String ldapProtocol,
    		String ldapServer,
    		String ldapPort,
    		String ldapManager,
    		String ldapPassword) throws NamingException {
        final String port = (ldapPort == null) ? (ldapProtocol.equals("LDAPS") ? "636" : "389") : ldapPort;
        final String protocol = ldapProtocol.equals("LDAPS") ? "ldaps://" : "ldap://";
        final String server = protocol + ldapServer + ":" + port;
        
        return connect(server, ldapManager, ldapPassword);
    }

    private Topic createUsernameTopic(String username) {
        DeepaMehtaTransaction tx = dm4.beginTx();
        try {
            Topic usernameTopic = acs.createUsername(username);
            tx.success();
            return usernameTopic;
        } catch (Exception e) {
            logger.warning("ROLLBACK! (" + this + ")");
            throw new RuntimeException("Creating username failed", e);
        } finally {
            tx.finish();
        }
    }
    
    private static boolean createUser(
    		String ldapUserBase,
    		String ldapUserAttribute,
    		String userName, String password,
    		String memberGroup) {
    	try {
    		LdapContext ctx = createDefaultContext();
    		if (ctx == null) {
    			return false;
    		}
    		
    		return createUserImpl(ctx, ldapUserBase, ldapUserAttribute, userName, password, memberGroup);
    				
    	} catch (Exception e) {
    		throw new RuntimeException("Creating user in LDAP failed", e);
    	}
    }
    
    private static boolean createUserImpl(
    		LdapContext ctx,
    		String ldapUserBase,
    		String ldapUserAttribute,
    		String userName, String password,
    		String memberGroup) throws NamingException {
    	String entryDN = String.format("%s=%s,%s", ldapUserAttribute, userName, ldapUserBase);
    	
    	Attribute cn = new BasicAttribute("cn", userName);
    	Attribute sn = new BasicAttribute("sn", "deepamehta-ldap");
    	Attribute userPassword = new BasicAttribute("userPassword", password);

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
    	
    	ctx.createSubcontext(entryDN, entry);
    	
    	if (!memberGroup.isEmpty()) {
    		ModificationItem mi = new ModificationItem(DirContext.ADD_ATTRIBUTE,
    				new BasicAttribute("member", entryDN));
    		
    		try {
    			ctx.modifyAttributes(memberGroup, new ModificationItem[] { mi });
    		} catch (NamingException ne) {
    			logger.warning("Membership attribute addition failed - rollback!");
    			
    			// Removes user
    			ctx.destroySubcontext(entryDN);
    			
    			return false;
    		}
    	}
    	
    	return true;
    }

    private boolean checkLdapCredentials(String username, String password) {
        try {
            final String port = (LDAP_PORT == null) ? (LDAP_PROTOCOL.equals("LDAPS") ? "636" : "389") : LDAP_PORT;
            final String protocol = LDAP_PROTOCOL.equals("LDAPS") ? "ldaps://" : "ldap://";
            final String server = protocol + LDAP_SERVER + ":" + port;
            LdapContext ctx = connect(server, LDAP_MANAGER, LDAP_PASSWORD);
            String cn = lookupUserCn(ctx, LDAP_USER_BASE, username);
            if (cn == null) {
                return false;
            }
            LdapContext ctx2 = connect(server, cn, password);
            return ctx2 != null;
        } catch (Exception e) {
            throw new RuntimeException("Checking LDAP credentials failed", e);
        }
    }

    private static LdapContext connect(String server, String username, String password) throws NamingException {
        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.PROVIDER_URL, server);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        //ensures that objectSID attribute values
        //will be returned as a byte[] instead of a String
        env.put("java.naming.ldap.attributes.binary", "objectSID");
        
        // the following is helpful in debugging errors
        // env.put("com.sun.jndi.ldap.trace.ber", System.err);
        Control[] arr = new Control[0];
        LdapContext ctx = new InitialLdapContext(env, arr);
        if (LDAP_PROTOCOL.equals("StartTLS")) {
            try {
                StartTlsResponse tls = (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
                SSLSession session = tls.negotiate();
            } catch (Exception e) {
                throw new RuntimeException("Could not establish TLS connection: " + e.toString());
            }
        }
        return ctx;
    }

    private static String lookupUserCn (LdapContext ctx, String ldapSearchBase, String uid) throws NamingException {
        String searchFilter = LDAP_FILTER.equals("")
                            ? "(" + LDAP_USER_ATTRIBUTE + "=" + uid + ")" 
                            : "(&(" + LDAP_FILTER + ")(" + LDAP_USER_ATTRIBUTE + "=" + uid + "))";
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> results = ctx.search(ldapSearchBase, searchFilter, searchControls);
        if(results.hasMoreElements()) {
            SearchResult searchResult = (SearchResult) results.nextElement();
            if(results.hasMoreElements()) {
                throw new RuntimeException("Ambiguity in LDAP CN query: Matched multiple users for the accountName");
            }
            return searchResult.getNameInNamespace();
        } else {
            return null;
        }
    }
}
