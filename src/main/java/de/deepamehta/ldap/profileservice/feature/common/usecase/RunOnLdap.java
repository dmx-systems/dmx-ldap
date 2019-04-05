package de.deepamehta.ldap.profileservice.feature.common.usecase;

import de.deepamehta.ldap.profileservice.model.Session;
import de.deepamehta.ldap.profileservice.repository.LdapRepository;

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
