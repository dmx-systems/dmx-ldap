package de.deepamehta.ldap;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

public class Program {

	public static void main(String[] args) throws Exception {
		System.out.println("user: " + args[0]);
		System.out.println("pass: " + args[1]);
		
		System.out.println("success: " + createUser(args[0], args[1]));
	}

	private static boolean createUser(String userName, String userPassword) {
		return createUserTest(
				"",
				"127.0.0.1",
				"389",
				"cn=admin,dc=dev,dc=climbo,dc=com",
				/*
				"cn=deepamehta,ou=systems,dc=dev,dc=climbo,dc=com",
				*/
				"12345678",
				"ou=users,dc=dev,dc=climbo,dc=com",
				"uid",
				userName,
				userPassword,
				"cn=climbousers,ou=groups,dc=dev,dc=climbo,dc=com");
	}
	
	static boolean createUserTest(
    		String protocol,
    		String server,
    		String port,
    		String manager,
    		String managerPassword,
    		String userBase,
    		String userAttribute,
    		String userName,
    		String userPassword,
    		String memberGroup) {
    	try {
    		LdapContext ctx = createContext(protocol, server, port, manager, managerPassword);
    		if (ctx == null) {
    			return false;
    		}
    		
    		return createUserImpl(ctx, userBase, userAttribute, userName, userPassword, memberGroup);
    				
    	} catch (Exception e) {
    		throw new RuntimeException("Creating user in LDAP failed", e);
    	}
    	
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
        
        return ctx;
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
    			// Removes user
    			ctx.destroySubcontext(entryDN);
    			
    			return false;
    		}
    	}
    	
    	return true;
    }

}
