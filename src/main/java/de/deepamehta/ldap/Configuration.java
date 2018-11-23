package de.deepamehta.ldap;

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
	String userAcceptanceFilter;
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
		PRODUCTION,
		TROUBLESHOOTING
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
	    c.loggingMode = LoggingMode.valueOf(System.getProperty("dm4.ldap.logging_mode", "production").toUpperCase());
	    
	    c.userCreationEnabled = System.getProperty("dm4.ldap.user_creation.enabled", "false").equals("true");
	  
	    c.manager = System.getProperty("dm4.ldap.manager", "");
	    c.password = System.getProperty("dm4.ldap.password", "");

	    c.userBase = System.getProperty("dm4.ldap.user_base", "");
	    c.userAttribute = System.getProperty("dm4.ldap.user_attribute", "");
	    c.userAcceptanceFilter = System.getProperty("dm4.ldap.filter", "");
	    c.userMemberGroup = System.getProperty("dm4.ldap.member_group", "");

	    c.compile();
	    
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
		
		if (StringUtils.isEmpty(userAcceptanceFilter)) {
			log.configurationHint("No filter expression provided. Defaulting to mere existance check.");
		}
		
		if (userCreationEnabled) {
			log.configurationHint("User creation enabled. LDAP entry creation and attribute modification may occur.");
			
			if (StringUtils.isEmpty(userMemberGroup)) {
				log.configurationHint("No member group provided. Automatically adding inetOrgPerson entries to groups is disabled.");

				if (StringUtils.isNotEmpty(userAcceptanceFilter)) {
					log.configurationWarning("Custom filter expression provided but no member group for new users. This might lead to new users not being able to log-in.");
				}
				
			} else {
				log.configurationHint("Automatically adding inetOrgPerson entries to groups is enabled.");
				
				if (StringUtils.isEmpty(userAcceptanceFilter)) {
					log.configurationWarning("Member group defined but no filter expression. As such group membership is not checked during log-in.");
				}

			}
			
		} else {
			log.configurationHint("User creation disabled. All LDAP accesses are read-only.");
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
				"protocol=%s\nserver=%s\nport=%s\nimplementation=%s\nloggingMode=%s\nuserCreationEnabled=%s\nmanager=%s\npassword=%s\nuserBase=%s\nuserAttribute=%s\nuserAcceptanceFilter=%s\nuserMemberGroup=%s",
				protocol, server, port, implementation, loggingMode, userCreationEnabled, manager, password, userBase,
				userAttribute, userAcceptanceFilter, userMemberGroup);
	}

	
}
