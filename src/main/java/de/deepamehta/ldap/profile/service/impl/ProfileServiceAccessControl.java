package de.deepamehta.ldap.profile.service.impl;

import de.deepamehta.accesscontrol.AccessControlService;
import de.deepamehta.ldap.profile.service.ProfileService;

import java.util.List;
import java.util.Map;

/**
 * Checks all accesses to @{link ProfileService} methods.
 */
public class ProfileServiceAccessControl implements ProfileService {

    private final AccessControlService acService;

    private final ProfileService delegate;

    public ProfileServiceAccessControl(
            AccessControlService accessControlService,
            ProfileService delegate) {
        this.acService = accessControlService;
        this.delegate = delegate;
    }

    private void checkLogin(String userNameToTest) {
        String loggedInUser = acService.getUsername();

        if (userNameToTest == null
                || loggedInUser == null
                || !(loggedInUser.equals(AccessControlService.ADMIN_USERNAME)
                && loggedInUser.equals(userNameToTest))) {
            throw new IllegalStateException(String.format("'%s' is not allowed to access the profile data.", loggedInUser));
        }
    }

    @Override
    public boolean update(String userName, Attribute attribute, String value) {
        checkLogin(userName);

        return delegate.update(userName, attribute, value);
    }

    @Override
    public boolean update(String userName, Map<Attribute, String> values) {
        checkLogin(userName);

        return delegate.update(userName, values);
    }

    @Override
    public String read(String userName, Attribute attribute) {
        checkLogin(userName);

        return delegate.read(userName, attribute);
    }

    @Override
    public Map<Attribute, String> read(String userName, List<Attribute> attributes) {
        checkLogin(userName);

        return delegate.read(userName, attributes);
    }
}
