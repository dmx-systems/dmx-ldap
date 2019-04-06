package de.deepamehta.ldap;


import java.io.IOException;
import java.util.Hashtable;

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

import org.apache.commons.lang.StringUtils;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;


class JndiLDAP implements LDAP {

	private final Configuration configuration;
	
	private final PluginLog pluginLog;

	JndiLDAP(Configuration configuration, PluginLog log) {
		this.configuration = configuration;
		this.pluginLog = log;
	}

    @Override
	public boolean createUser(String username, String password, JndiLDAP.CompletableAction actionOnSuccess) {
    	LdapContext ctx = null;
		
		try {
			ctx = connect();
		
			String encodedPassword = new LdapShaPasswordEncoder().encode(password);
    	
			return createUserImpl(ctx, username, encodedPassword)
					&& actionOnSuccess.run(username);
		} finally {
			closeQuietly(ctx);
		}
	}

    private boolean createUserImpl(
    		LdapContext ctx,
    		String userName, String password) {
    	String entryDN = String.format("%s=%s,%s", configuration.userAttribute, userName, configuration.userBase);
    	
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
    	
    	try {
        	// TODO: Make user entry creation and attribute modification a single transactional operation
    		
    		ctx.createSubcontext(entryDN, entry);
    	} catch (NamingException ne) {
    		pluginLog.actionError("Unable to create user subcontext", ne);
    		
    		return false;
    	}
    	
    	if (StringUtils.isNotEmpty(configuration.userMemberGroup)) {
    		ModificationItem mi = new ModificationItem(DirContext.ADD_ATTRIBUTE,
    				new BasicAttribute("member", entryDN));
    		
    		try {
    			ctx.modifyAttributes(configuration.userMemberGroup, new ModificationItem[] { mi });
    		} catch (NamingException ne) {
    			pluginLog.actionError("Membership attribute addition failed - rollback!", ne);
    			
    			// Removes user
    			try {
    				ctx.destroySubcontext(entryDN);
    			} catch (NamingException ne2) {
    				pluginLog.actionError("Unable to rollback context creation!", ne2);
    			}
    			
    			return false;
    		}
    	}
    	
    	return true;
    }

	@Override
	public boolean checkCredentials(String username, String password) {
		pluginLog.actionHint("Checking credentials for user %s", username);
		
        LdapContext ctx = null;
        LdapContext ctx2 = null;
        try {
        	String url = configuration.getConnectionUrl();
            ctx = connect(url, configuration.manager, configuration.password, false);
            
            String cn = lookupUserCn(ctx, username);
            if (cn == null) {
        		pluginLog.actionHint("User %s not found in LDAP", username);
                return false;
            }
            
            ctx2 = connect(url, cn, password, true);
            
            if (ctx == null) {
                pluginLog.actionHint("Provided credentials for user %s were wrong", username);
            }
            
            return ctx2 != null;
        } catch (NamingException e) {
        	throw new RuntimeException("Checking LDAP credentials lead to exception", e);
        } finally {
			closeQuietly(ctx);
			closeQuietly(ctx2);
		}
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
        	
            SearchResult searchResult = (SearchResult) results.nextElement();
            
            if (results.hasMoreElements()) {
                throw new RuntimeException("Ambiguity in LDAP CN query: Matched multiple users for the accountName");
            }
            
            return searchResult.getNameInNamespace();
        } else {
            pluginLog.actionWarning("Lookup using search filter was empty.", null);
            
            return null;
        }
    }

	@Override
	public boolean changePassword(String username, String password) {
		pluginLog.actionHint("Changing password for user %s", username);

		LdapContext ctx = null;
		
		try {
			ctx = connect();
		
			String encodedPassword = new LdapShaPasswordEncoder().encode(password);
    	
			return changePasswordImpl(ctx, username, encodedPassword);
		} finally {
			closeQuietly(ctx);
		}
	}
	
    private boolean changePasswordImpl(
    		LdapContext ctx,
    		String userName, String password) {
    	String entryDN = String.format("%s=%s,%s", configuration.userAttribute, userName, configuration.userBase);
    	
		ModificationItem mi = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
				new BasicAttribute("userPassword", password));
    	
    	try {
			ctx.modifyAttributes(entryDN, new ModificationItem[] { mi });
    	} catch (NamingException ne) {
    		pluginLog.actionWarning("Attempt to modify userPassword attribute lead to exception", ne);
    		
    		return false;
    	}
    	    	
    	return true;
    }

    private LdapContext connect() {
    	return connect(configuration.getConnectionUrl(), configuration.manager, configuration.password, false);
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

    private void closeQuietly(LdapContext ctx) {
		if (ctx != null) {
			try {
				ctx.close();
			} catch (NamingException ne) {
				pluginLog.actionWarning("Exception while closing connection", ne);
			}
		}
	}
	

}
