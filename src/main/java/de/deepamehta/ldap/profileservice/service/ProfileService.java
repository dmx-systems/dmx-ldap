package de.deepamehta.ldap.profileservice.service;

import de.deepamehta.ldap.profileservice.model.LdapAttribute;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public interface ProfileService {

    public enum Attribute {
        NICK_NAME(LdapAttribute.DISPLAY_NAME),
        EMAIL(LdapAttribute.MAIL),
        FIRST_NAME(LdapAttribute.GIVEN_NAME),
        FAMILY_NAME(LdapAttribute.SURNAME),
        INFO(LdapAttribute.DESCRIPTION),
        PICTURE(LdapAttribute.JPEG_PHOTO);

        final LdapAttribute ldapAttribute;

        Attribute(LdapAttribute ldapAttribute) {
            this.ldapAttribute = ldapAttribute;
        }

        static Attribute findByLdapAttribute(LdapAttribute ldapAttribute) {
            return Arrays.stream(values())
                    .findFirst()
                    .filter(attr -> attr.ldapAttribute == ldapAttribute)
                    .get();
        }
    }


    boolean update(Attribute attribute, String value);

    boolean update(Map<Attribute, String> values);

    String read(Attribute attribute);

    Map<Attribute, String> read(List<Attribute> attributes);

}
