package de.deepamehta.ldap.profile.service;

import de.deepamehta.ldap.profile.model.LdapAttribute;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public interface ProfileService {

    enum Attribute {
        NICK_NAME(LdapAttribute.DISPLAY_NAME),
        EMAIL(LdapAttribute.MAIL),
        FIRST_NAME(LdapAttribute.GIVEN_NAME),
        FAMILY_NAME(LdapAttribute.SURNAME),
        INFO(LdapAttribute.DESCRIPTION),
        PICTURE(LdapAttribute.JPEG_PHOTO);

        public final LdapAttribute ldapAttribute;

        Attribute(LdapAttribute ldapAttribute) {
            this.ldapAttribute = ldapAttribute;
        }

        public static Attribute findByLdapAttribute(LdapAttribute ldapAttribute) {
            return Arrays.stream(values())
                    .findFirst()
                    .filter(attr -> attr.ldapAttribute == ldapAttribute)
                    .get();
        }
    }


    boolean update(String userName, String password, Attribute attribute, String value);

    boolean update(String userName, String password, Map<Attribute, String> values);

    String read(String userName, String password, Attribute attribute);

    Map<Attribute, String> read(String userName, String password, List<Attribute> attributes);

}
