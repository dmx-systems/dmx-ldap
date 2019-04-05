package de.deepamehta.ldap.profile.repository.jndi;


import de.deepamehta.ldap.Configuration;
import de.deepamehta.ldap.PluginLog;
import org.apache.commons.lang.StringUtils;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.*;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.util.Hashtable;


class ContextManager {

	private final Configuration configuration;

	private final PluginLog pluginLog;

	ContextManager(Configuration configuration, PluginLog log) {
		this.configuration = configuration;
		this.pluginLog = log;
	}

	LdapContext openConnection(String username, String password) {
		pluginLog.actionHint("Checking credentials for user %s", username);
		
        LdapContext ctx = null;
        try {
        	String url = configuration.getConnectionUrl();
            ctx = connect(url, configuration.manager, configuration.password, false);
            
            String cn = lookupUserCn(ctx, username);
            if (cn == null) {
        		pluginLog.actionHint("User %s not found in LDAP", username);
                return null;
            }

			LdapContext ctx2 = connect(url, cn, password, true);
            
            if (ctx2 == null) {
                pluginLog.actionHint("Provided credentials for user %s were wrong", username);
            }
            
            return ctx2;
        } catch (NamingException e) {
        	throw new RuntimeException("Checking LDAP credentials lead to exception", e);
        } finally {
			closeQuietly(ctx);
		}
	}

    private LdapContext connect(String serverUrl, String username, String password, boolean suppressNamingException) {
    	pluginLog.actionHint("creating LDAP connection using URL %s and username %s", serverUrl, username);
    	
        Hashtable<String, Object> env = new Hashtable<String, Object>();
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
        	if (suppressNamingException) {
            	// When used as part of checkCredentials an exception at this point is not grave
        		pluginLog.actionWarning("Attempting to connect to LDAP server lead to Exception", e);
        		
            	return null;
        	} else {
        		throw new RuntimeException("Attempting to connect to LDAP server lead to Exception", e);
        	}
        } catch (IOException e) {
            throw new RuntimeException("Could not establish TLS connection. Connecting failed.", e);
        }
    }

	String dnByUid (String uid) {
		return String.format("%s=%s,%s", configuration.userAttribute, uid, configuration.userBase);
	}

	private String lookupUserCn (LdapContext ctx, String uid) throws NamingException {

		String searchFilter = StringUtils.isEmpty(configuration.userFilter)
				? String.format("(%s=%s)", configuration.userAttribute, uid)
				: String.format("(&(%s)(%s=%s))", configuration.userFilter, configuration.userAttribute, uid);

		pluginLog.actionHint("Complete filter expression for user lookup: %s", searchFilter);

		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		NamingEnumeration<SearchResult> results = ctx.search(configuration.userBase, searchFilter, searchControls);
		pluginLog.actionHint("Search base is: %s", configuration.userBase);

		if (results.hasMoreElements()) {
			pluginLog.actionHint("Lookup using search filter returned non-empty result");

			SearchResult searchResult = results.nextElement();

			if (results.hasMoreElements()) {
				throw new RuntimeException("Ambiguity in LDAP CN query: Matched multiple users for the accountName");
			}

			return searchResult.getNameInNamespace();
		} else {
			pluginLog.actionWarning("Lookup using search filter was empty.", null);

			return null;
		}
	}

    void closeQuietly(LdapContext ctx) {
		if (ctx != null) {
			try {
				ctx.close();
			} catch (NamingException ne) {
				pluginLog.actionWarning("Exception while closing connection", ne);
			}
		}
	}

	boolean store(StoreRunner runner) {
		try {
			runner.invoke();
		} catch (NamingException exception) {
			pluginLog.actionWarning("LDAP access failed.", exception);

			return false;
		}

		return true;
	}

		interface StoreRunner {
			void invoke() throws NamingException;
		}

	<T> T load(LoadRunner<T> runner) {
		try {
			return runner.invoke();
		} catch (NamingException exception) {
			pluginLog.actionWarning("LDAP access failed.", exception);

			return null;
		}
	}

	interface LoadRunner<T> {
		T invoke() throws NamingException;
	}
}
