package systems.dmx.ldap.repository;

import systems.dmx.accesscontrol.AccessControlService;
import systems.dmx.ldap.Configuration;

import java.util.List;
import java.util.logging.Logger;

public interface JndiRepository {

    boolean checkCredentials(String user, String password);

    boolean createUser(String user, String password, CompletableAction actionOnSuccess);

    boolean deleteUser(String user);

    boolean changePassword(String user, String password);

    boolean createGroup(String group, String user, List<String> members);

    boolean deleteGroup(String group);

    boolean addMember(String group, String user);

    boolean removeMember(String group, String user);

    interface CompletableAction {

        default boolean run(String userName) {
            return true;
        }

    }

    static JndiRepository newInstance(Configuration configuration) {
        JndiDatasource datasource = new JndiDatasource(configuration, AccessControlService.ADMIN_USERNAME, configuration.manager);
        return configuration.useBindAccount
                ? new BindUserJndiRepository(configuration.manager, configuration.password, datasource)
                : new NonBindUserJndiRepository(datasource);
    }

    static JndiRepository newDummyInstance() {

        final Logger logger = Logger.getLogger(JndiRepository.class.getName());

        return new JndiRepository() {

            private void logError() {
                logger.severe("LDAP plugin cannot fulfill request as it was not configured correctly.");
            }

            @Override
            public boolean checkCredentials(String user, String password) {
                logError();

                return false;
            }

            @Override
            public boolean createUser(String user, String password, CompletableAction actionOnSuccess) {
                logError();

                return false;
            }

            @Override
            public boolean deleteUser(String user) {
                logError();

                return false;
            }

            @Override
            public boolean changePassword(String user, String password) {
                logError();

                return false;
            }

            @Override
            public boolean addMember(String groupDn, String user) {
                logError();

                return false;
            }

            @Override
            public boolean removeMember(String groupDn, String user) {
                logError();

                return false;
            }

            @Override
            public boolean createGroup(String group, String user, List<String> members) {
                logError();

                return false;
            }

            @Override
            public boolean deleteGroup(String group) {
                logError();

                return false;
            }
        };
    }
}
