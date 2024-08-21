package systems.dmx.ldap;

import systems.dmx.accountmanagement.AccountManager;
import systems.dmx.accountmanagement.CheckCredentialsResult;
import systems.dmx.core.service.accesscontrol.Credentials;
import systems.dmx.ldap.repository.JndiRepository;

import java.util.Locale;
import java.util.logging.Logger;

class LDAPAccountManager implements AccountManager {
    private static final Logger logger = Logger.getLogger(LDAPAccountManager.class.getName());

    private final Configuration configuration;
    private final JndiRepository jndiRepository;

    LDAPAccountManager(Configuration configuration, JndiRepository jndiRepository) {
        this.configuration = configuration;
        this.jndiRepository = jndiRepository;
    }

    @Override
    public String name() {
        return "LDAP";
    }

    @Override
    public CheckCredentialsResult checkCredentials(Credentials cred) {
        String username = sanitise(cred.username);
        if (jndiRepository.checkCredentials(username, cred.password)) {
            logger.info(() -> String.format("LDAP credential check successful for user %s", username));
            return CheckCredentialsResult.lookupOrCreationRequired();
        } else {
            logger.severe(String.format("LDAP credential check failed for user %s", username));
            return CheckCredentialsResult.failed();
        }
    }

    @Override
    public void createAccount(Credentials credentials) {
        if (!configuration.userCreationEnabled) {
            throw new IllegalStateException("User creation is disabled in LDAP plugin configuration!");
        }

        jndiRepository.createUser(sanitise(credentials.username), credentials.password, new JndiRepository.CompletableAction() {
        });
    }

    @Override
    public void changePassword(Credentials currentCredentials, Credentials newCredentials) {
        if (!configuration.userCreationEnabled) {
            throw new IllegalStateException("Cannot change password because user creation is disabled in LDAP plugin configuration!");
        }
        String username = sanitise(newCredentials.username);
        if (jndiRepository.changePassword(username, newCredentials.password)) {
            logger.info(() -> String.format("Successfully changed password for %s", username));
        } else {
            throw new IllegalStateException("Password change failed");
        }
    }

    @Override
    public void onUsernameDeleted(String username) {
        if (configuration.userDeletionEnabled) {
            logger.info(() -> String.format("Deleting user from LDAP %s", username));
            jndiRepository.deleteUser(username);
        }
    }

    private String sanitise(String sourceUsername) {
        return sourceUsername.toLowerCase(Locale.ROOT);
    }

}
