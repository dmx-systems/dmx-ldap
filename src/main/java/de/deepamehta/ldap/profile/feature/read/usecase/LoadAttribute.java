package de.deepamehta.ldap.profile.feature.read.usecase;

import de.deepamehta.ldap.profile.model.LdapAttribute;
import de.deepamehta.ldap.profile.model.Session;
import de.deepamehta.ldap.profile.repository.LdapRepository;

public class LoadAttribute {

    private final LdapRepository ldapRepository;

    public LoadAttribute(LdapRepository ldapRepository) {
        this.ldapRepository = ldapRepository;
    }

    public String invoke(Session session, LdapAttribute attribute) {
        return ldapRepository.loadAttribute(session, attribute);
    }


}
