package de.deepamehta.ldap.profileservice.model;

public enum LdapAttribute {

    DISPLAY_NAME("displayName"),
    MAIL("mail"),
    GIVEN_NAME("givenName"),
    SURNAME("surname"),
    DESCRIPTION("description"),
    JPEG_PHOTO("jpegPhoto");

    private final String ldapAttributeName;

    LdapAttribute(String ldapAttributeName) {
        this.ldapAttributeName = ldapAttributeName;
    }

    public String getLdapAttributeName() {
        return ldapAttributeName;
    }

}
