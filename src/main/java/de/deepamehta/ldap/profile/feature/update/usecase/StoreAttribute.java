package de.deepamehta.ldap.profile.feature.update.usecase;

import de.deepamehta.ldap.profile.model.LdapAttribute;
import de.deepamehta.ldap.profile.model.Session;
import de.deepamehta.ldap.profile.repository.LdapRepository;

public class StoreAttribute {

    private final LdapRepository ldapRepository;

    public StoreAttribute(LdapRepository ldapRepository) {
        this.ldapRepository = ldapRepository;
    }

    public boolean invoke(Session session, LdapAttribute attribute, String value) {
        // TODO: Encode value
        return ldapRepository.storeAttribute(session, attribute, value);
    }


}
