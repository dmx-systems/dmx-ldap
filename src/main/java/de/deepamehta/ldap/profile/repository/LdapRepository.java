package de.deepamehta.ldap.profile.repository;

import de.deepamehta.ldap.profile.model.LdapAttribute;
import de.deepamehta.ldap.profile.model.Session;

public interface LdapRepository {

    Session openConnection(String uid);

    void closeConnection(Session session);

    boolean storeAttribute(Session session, LdapAttribute attribute, String encodedValue);

    String loadAttribute(Session session, LdapAttribute attribute);

}
