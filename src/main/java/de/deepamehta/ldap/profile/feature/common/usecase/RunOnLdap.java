package de.deepamehta.ldap.profile.feature.common.usecase;

import de.deepamehta.ldap.profile.model.Session;
import de.deepamehta.ldap.profile.repository.LdapRepository;

public class RunOnLdap {

    private final LdapRepository ldapRepository;

    public RunOnLdap(LdapRepository ldapRepository) {
        this.ldapRepository = ldapRepository;
    }

    public void invoke(String userName, String password, LdapRunner runner) {
        Session session = ldapRepository.openConnection(userName, password);

        if (session == null) {
            throw new IllegalStateException("Unable to connect to LDAP.");
        }

        try {
            runner.run(session);
        } finally {
            ldapRepository.closeConnection(session);
        }
    }

    public interface LdapRunner {
        void run(Session session);
    }

    public <T> T invoke(String userName, String password, LdapRunnerWithReturnValue<T> runner) {
        Session session = ldapRepository.openConnection(userName, password);

        if (session == null) {
            throw new IllegalStateException("Unable to connect to LDAP.");
        }

        try {
            return runner.run(session);
        } finally {
            ldapRepository.closeConnection(session);
        }
    }

    public interface LdapRunnerWithReturnValue<T> {
        T run(Session session);
    }

}
