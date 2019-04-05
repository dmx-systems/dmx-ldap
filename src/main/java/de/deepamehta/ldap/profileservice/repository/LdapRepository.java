package de.deepamehta.ldap.profileservice.repository;

import de.deepamehta.ldap.profileservice.model.LdapAttribute;
import de.deepamehta.ldap.profileservice.model.Session;

public interface LdapRepository {

    Session openConnection(String uid, String password);

    void closeConnection(Session session);

    boolean storeAttribute(Session session, LdapAttribute attribute, String encodedValue);

    String loadAttribute(Session session, LdapAttribute attribute);

}
