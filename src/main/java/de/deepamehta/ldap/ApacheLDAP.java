package de.deepamehta.ldap;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.lang.StringUtils;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

class ApacheLDAP implements LDAP {
	
	private final Configuration configuration;
	
	private final PluginLog pluginLog;
	
	private final LdapConnectionConfig defaultConnectionConfig;
	
	ApacheLDAP(Configuration configuration, PluginLog pluginLog) {
		this.configuration = configuration;
		this.pluginLog = pluginLog;
		
		defaultConnectionConfig = createConfig(configuration.manager, configuration.password);
	}
	
	LdapConnectionConfig createConfig(String user, String password) {
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
	
	private void whenConnected(LdapAction action) {
		LdapConnection connection = new LdapNetworkConnection(defaultConnectionConfig);
		
		try {
			connection.bind();
			
			// Runs the command
			action.run(connection);
			
		} catch (LdapException le) {
			throw new RuntimeException("Error opening LDAP connection.", le);
		} finally {
			try {
				if (connection != null) {
					connection.close();
				}
			} catch (IOException e) {
				throw new RuntimeException("Error closing LDAP connection.", e);
			}
		}
	}

	@Override
	public boolean checkCredentials(String user, String password) {
        String searchFilter = StringUtils.isEmpty(configuration.userFilter)
        		? String.format("(%s=%s)", configuration.userAttribute, user)
                : String.format("(&(%s)(%s=%s))", configuration.userFilter, configuration.userAttribute, user);

		pluginLog.actionHint("Complete filter expression for user lookup: %s", searchFilter);
        pluginLog.actionHint("Search base is: %s", configuration.userBase);

        AtomicBoolean result = new AtomicBoolean(false);
        
		whenConnected((connection) -> {
			try {
				EntryCursor cursor = connection.search(configuration.userBase, searchFilter, SearchScope.SUBTREE, "*");
				
				if (!cursor.first()) {
		            pluginLog.actionWarning("Lookup using search filter was empty.", null);
				}
					
				if (cursor.next()) {
	                throw new RuntimeException("Ambiguity in LDAP CN query: Matched multiple users for the accountName");
				}
					
				pluginLog.actionHint("Lookup using search filter returned a single non-empty result");
				
				result.set(checkLdapLogin(user, password));

			} catch (CursorException | LdapException le) {
				throw new RuntimeException("Error while checking credentials.", le);
			}
		});
		
		return result.get();
	}
	
	private boolean checkLdapLogin(String user, String password) {
		
		LdapConnection connection = new LdapNetworkConnection(createConfig(user, password));
		try {
			connection.bind();
			
			return connection.isConnected();
			
		} catch (LdapException le) {
            pluginLog.actionHint("Provided credentials for user %s were wrong", user);
            
            return false;
		} finally {
			try {
				if (connection != null) {
					connection.close();
				}
			} catch (IOException e) {
				throw new RuntimeException("Error closing LDAP connection.", e);
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
