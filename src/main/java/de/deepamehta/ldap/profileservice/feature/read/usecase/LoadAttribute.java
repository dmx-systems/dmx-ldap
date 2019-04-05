package de.deepamehta.ldap.profileservice.feature.read.usecase;

import de.deepamehta.ldap.profileservice.model.LdapAttribute;
import de.deepamehta.ldap.profileservice.model.Session;
import de.deepamehta.ldap.profileservice.repository.LdapRepository;

public class LoadAttribute {

    private final LdapRepository ldapRepository;

    public LoadAttribute(LdapRepository ldapRepository) {
        this.ldapRepository = ldapRepository;
    }

    public String invoke(Session session, LdapAttribute attribute) {
        return ldapRepository.loadAttribute(session, attribute);
    }


}
