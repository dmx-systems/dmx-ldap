package de.deepamehta.ldap;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import org.apache.commons.lang.StringUtils;

public class Configuration {
	
	ProtocolType protocol;
	String server;
	String port;
	
	ImplementationType implementation;
	LoggingMode loggingMode;

	boolean userCreationEnabled;
	
	String manager;
	String password;
	
	String userBase;
	String userAttribute;
	String userFilter;
	String userMemberGroup;
	
	private String connectionUrl;
	
	String getConnectionUrl() {
		return connectionUrl;
	}
	
	public enum ProtocolType {
		LDAP,
		LDAPS,
		STARTTLS
	}
	
	public enum ImplementationType {
		JNDI,
		APACHE
	};
	
	public enum LoggingMode {
		INFO,
		DEBUG
	}
	
	private Configuration() {
		// No op
	}
	
	//
	static Configuration createFromProperties() {
		Configuration c = new Configuration();
		
		c.server = System.getProperty("dm4.ldap.server", "127.0.0.1");
	    c.port = System.getProperty("dm4.ldap.port");

	    // ldap (default), ldaps and starttls
	    c.protocol = ProtocolType.valueOf(System.getProperty("dm4.ldap.protocol", "ldap").toUpperCase());
	    
	    // jndi (default) or apache
	    //c.implementation = ImplementationType.valueOf(System.getProperty("dm4.ldap.implementation", "jndi").toUpperCase());
	    c.implementation = ImplementationType.JNDI;

	    // production (default) or troubleshooting
	    c.loggingMode = LoggingMode.valueOf(System.getProperty("dm4.ldap.logging", "info").toUpperCase());
	    
	    c.userCreationEnabled = System.getProperty("dm4.ldap.user_creation.enabled", "false").equals("true");
	  
	    c.manager = System.getProperty("dm4.ldap.manager", "");
	    c.password = System.getProperty("dm4.ldap.password", "");

	    c.userBase = System.getProperty("dm4.ldap.user_base", "");
	    c.userAttribute = System.getProperty("dm4.ldap.user_attribute", "");
	    c.userFilter = System.getProperty("dm4.ldap.user_filter", "");
	    c.userMemberGroup = System.getProperty("dm4.ldap.user_member_group", "");

	    return c;
	}
	
	boolean check(PluginLog log) {
		int errorCount = 0;
		
		log.configurationHint("Logging is set up for %s environment.", loggingMode.toString().toLowerCase());
		
		if (StringUtils.isEmpty(manager)) {
			log.configurationError("No manager account provided.");
			errorCount++;
		}
		
		if (StringUtils.isEmpty(password)) {
			log.configurationWarning("No manager password provided.");
		}

		if (StringUtils.isEmpty(userBase)) {
			log.configurationError("No user base provided.");
			errorCount++;
		}

		if (StringUtils.isEmpty(userAttribute)) {
			log.configurationHint("User attribute not set. Defaults to 'uid'.");
			userAttribute = "uid";
		}
		
		if (StringUtils.isEmpty(userFilter)) {
			log.configurationHint("No filter expression provided. Defaulting to mere existance check.");
		}
		
		if (userCreationEnabled) {
			log.configurationHint("User creation enabled. LDAP entry creation and attribute modification may occur.");
			
			if (StringUtils.isEmpty(userMemberGroup)) {
				log.configurationHint("No member group provided. Automatically adding inetOrgPerson entries to groups is disabled.");

				if (StringUtils.isNotEmpty(userFilter)) {
					log.configurationWarning("Custom filter expression provided but no member group for new users. This might lead to new users not being able to log-in.");
				}
				
			} else {
				log.configurationHint("Automatically adding inetOrgPerson entries to groups is enabled.");
				
				if (StringUtils.isEmpty(userFilter)) {
					log.configurationWarning("Member group defined but no filter expression. As such group membership is not checked during log-in.");
				}

			}
			
		} else {
			log.configurationHint("User creation disabled. All LDAP accesses are read-only.");
		}
		
		// Checking keystore: A wrongly configured keystore leads to logged warnings but will not stop the plugin start.
		// The reason is that the keystore might have been set up for something else than the LDAP plugin
		// as it affects all SSL/TLS connections.
		String trustStore = System.getProperty("javax.net.ssl.trustStore", "");
		String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword", "");
		if (protocol != ProtocolType.LDAP) {
			if (StringUtils.isEmpty(trustStore)) {
				log.configurationWarning("Secure connection requested but no custom SSL/TLS trust store defined. Connection negotiation may fail.");
			} else {
				
				if (StringUtils.isEmpty(trustStorePassword)) {
					log.configurationWarning("Custom keystore was configured but password is empty. Opening the keystore and accessing its content may fail.");
				}

				try {
					KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
					
					keyStore.load(new FileInputStream(trustStore), trustStorePassword.toCharArray());

					log.configurationHint("Configured trust store %s is usable with provided password.", trustStore);
					
					int count = 0;
					Enumeration<String> aliases = keyStore.aliases();
					while (aliases.hasMoreElements()) {
						count++;
						aliases.hasMoreElements();
					}
					
					if (count == 0) {
						log.configurationError("Configured trust store does not contain any aliases. Please check the file.");
					} else {
						log.configurationHint("Configured trust store contains %s aliases. It appears valid for SSL/TLS connections");
					}
					
				} catch (KeyStoreException e) {
					log.configurationError("Unable to initialize default trust store. Expecting \"Java Keystore\" format: %s", e.getLocalizedMessage());
				} catch (NoSuchAlgorithmException e) {
					log.configurationError("Unable to load trust store. Check whether it is in the default \"Java Keystore\" format: %s", e.getLocalizedMessage());
				} catch (CertificateException e) {
					log.configurationError("Unable to load trust store. Issue with certificates: %s", e.getLocalizedMessage());
				} catch (FileNotFoundException e) {
					log.configurationError("Trust store configured to %s but file is not accessible: %s", trustStore, e.getLocalizedMessage());
				} catch (IOException e) {
					log.configurationError("Trust store configured to %s but reading the file failed: %s", trustStore, e.getLocalizedMessage());
				}
				
			}
		} else {
			if (StringUtils.isNotEmpty(trustStore)) {
				log.configurationWarning("A trust store located at %s was specified but using a non-SSL/TLS protocol. Check configuration.");
			}
		}
		
		return errorCount == 0;
	}
	
	void compile() {
		// If no port was set, select defaults by protocol
		if (StringUtils.isEmpty(port)) {
	        port = protocol == ProtocolType.LDAP ? "636" : "389";
		}
		
		connectionUrl = String.format("ldap%s://%s:%s",
						protocol == ProtocolType.LDAPS ? "s" : "",
						server,
						port);
	}

	String summary() {
		return String.format(
				"protocol=%s\nserver=%s\nport=%s\nimplementation=%s\nlogging=%s\nuser_creation.enabled=%s\nmanager=%s\npassword=%s\nuser_base=%s\nuser_attribute=%s\nuser_acceptance_filter=%s\nuser_member_group=%s",
				protocol, server, port, implementation, loggingMode, userCreationEnabled, manager, StringUtils.isEmpty(password) ? "" : "***", userBase,
				userAttribute, userFilter, userMemberGroup);
	}

	
}
