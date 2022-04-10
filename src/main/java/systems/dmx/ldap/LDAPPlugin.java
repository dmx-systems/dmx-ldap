package systems.dmx.ldap;

import systems.dmx.accesscontrol.AccessControlService;
import systems.dmx.accesscontrol.AuthorizationMethod;
import systems.dmx.core.Assoc;
import systems.dmx.core.Topic;
import systems.dmx.core.model.AssocModel;
import systems.dmx.core.model.PlayerModel;
import systems.dmx.core.osgi.PluginActivator;
import systems.dmx.core.service.Inject;
import systems.dmx.core.service.accesscontrol.Credentials;
import systems.dmx.core.service.event.PostCreateAssoc;
import systems.dmx.core.service.event.PostDeleteAssoc;
import systems.dmx.core.storage.spi.DMXTransaction;
import systems.dmx.ldap.service.LDAPPluginService;
import systems.dmx.workspaces.WorkspacesService;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class LDAPPlugin extends PluginActivator implements AuthorizationMethod, LDAPPluginService, PostCreateAssoc, PostDeleteAssoc {

    public static final String WORKSPACE_TYPE = "dmx.workspaces.workspace";
    public static final String GROUP_TYPE = "systems.dmx.ldap.group";

    public static final String COMPOSITION_ASSOC_TYPE = "dmx.core.composition";
    public static final String MEMBERSHIP_ASSOC_TYPE = "dmx.accesscontrol.membership";
    public static final String USERNAME_TOPIC_TYPE = "dmx.accesscontrol.username";

    private static Logger logger = Logger.getLogger(LDAPPlugin.class.getName());

    @Inject
    private AccessControlService acs;

    @Inject
    private WorkspacesService wss;

    private Configuration configuration;

    private PluginLog pluginLog;

    private LDAP ldap;

    @Override
    public void serviceArrived(Object service) {
        if (service instanceof AccessControlService) {
            ((AccessControlService) service).registerAuthorizationMethod("LDAP", this);
        }
    }

    @Override
    public void serviceGone(Object service) {
        if (service instanceof AccessControlService) {
            ((AccessControlService) service).unregisterAuthorizationMethod("LDAP");
        }
    }

    @Override
    public void init() {
        try {
            configuration = Configuration.createFromProperties();

            pluginLog = PluginLog.newInstance(configuration.loggingMode);
        } catch (Exception e) {
            configuration = Configuration.createFallback();

            pluginLog = PluginLog.newInstance(configuration.loggingMode);
            pluginLog.configurationError("Error parsing configuration", e);

            pluginLog.configurationHint("Configuration could not be parsed. Providing an emergency fallback configuration. LDAP logins will not work!");
        }

        pluginLog.configurationHint("Plugin configuration:\n%s", configuration.summary());

        if (!configuration.check(pluginLog)) {
            pluginLog.configurationError("LDAP Plugin configuration is not correct. Please fix the issues mentioned in the log.");
            ldap = LDAP.newDummyInstance(pluginLog);
        } else {
            configuration.compile();
            ldap = LDAP.newInstance(configuration, pluginLog);
        }
    }

    @Override
    public Topic checkCredentials(Credentials cred) {
        if (ldap.checkCredentials(cred.username, cred.plaintextPassword)) {
            Topic username = lookupOrCreateUsernameTopic(cred.username);
            if (username != null) {
                pluginLog.actionHint("LDAP log-in successful for user %s", cred.username);
                return username;
            } else {
                pluginLog.actionError("Credentials in LDAP are OK but unable find or create username topic", null);
                return null;
            }
        } else {
            pluginLog.actionError(String.format("Credential check for user %s failed.", cred.username), null);

            return null;
        }
    }

    @Override
    public Topic createUser(Credentials cred) {
        if (!configuration.userCreationEnabled) {
            logger.warning("User creation is disabled in plugin configuration!");
            return null;
        }

        // TODO: Rollback when DM user creation was not successful.
        AtomicReference<Topic> usernameTopicRef = new AtomicReference<>();

        ldap.createUser(cred.username, cred.plaintextPassword, new LDAP.CompletableAction() {

            public boolean run(String username) {
                Topic usernameTopic = null;
                try {
                    usernameTopic = lookupOrCreateUsernameTopic(username);

                    return usernameTopic != null;
                } catch (Exception e) {
                    pluginLog.actionError(String.format("Creating username %s failed but LDAP entry was already created. Rolling back.", username), e);

                    throw new RuntimeException("Creating username failed", e);
                } finally {
                    usernameTopicRef.set(usernameTopic);
                }
            }
        });

        return usernameTopicRef.get();
    }

    private Topic lookupOrCreateUsernameTopic(String username) {
        Topic usernameTopic = acs.getUsernameTopic(username);
        if (usernameTopic != null) {
            return usernameTopic;
        } else {
            DMXTransaction tx = dmx.beginTx();
            try {
                usernameTopic = acs.createUsername(username);
                tx.success();

                return usernameTopic;
            } finally {
                tx.finish();
            }
        }
    }

    @Override
    public Topic changePassword(Credentials credentials) {
        if (!configuration.userCreationEnabled) {
            pluginLog.actionWarning("Cannot change password because user creation is disabled in plugin configuration!", null);

            return null;
        }

        Topic usernameTopic = acs.getUsernameTopic(credentials.username);
        if (usernameTopic != null) {
            if (ldap.changePassword(credentials.username, credentials.plaintextPassword)) {
                pluginLog.actionHint("Succesfully changed password for %s", credentials.username);

                return usernameTopic;
            }
        }

        return null;
    }

    private List<String> getMembers(Topic workspaceTopic) {
        return workspaceTopic.getRelatedTopics(
                MEMBERSHIP_ASSOC_TYPE,
                null,
                null,
                USERNAME_TOPIC_TYPE
        ).stream().map(relatedTopic -> relatedTopic.getSimpleValue().toString()).collect(Collectors.toList());
    }

    private boolean isWorkspaceGroupComposition(AssocModel assoc) {
        return isType(assoc, COMPOSITION_ASSOC_TYPE)
                && isType(assoc.getPlayer1(), WORKSPACE_TYPE)
                && isType(assoc.getPlayer2(), GROUP_TYPE);
    }

    private boolean isUsernameWorkspaceMembership(AssocModel assoc) {
        return isType(assoc, MEMBERSHIP_ASSOC_TYPE)
                && isType(assoc.getPlayer1(), USERNAME_TOPIC_TYPE)
                && isType(assoc.getPlayer2(), WORKSPACE_TYPE);
    }

    @Override
    public void postCreateAssoc(Assoc assoc) {
        if (isWorkspaceGroupComposition(assoc.getModel())) {
            String userName = acs.getWorkspaceOwner(assoc.getPlayer1().getId());
            String group = dmx.getTopic(assoc.getPlayer2().getId()).getSimpleValue().toString();
            boolean isAdmin = userName.equals(AccessControlService.ADMIN_USERNAME);

            Topic workspace = dmx.getTopic(assoc.getPlayer1().getId());

            ldap.createGroup(group, userName, isAdmin, getMembers(workspace));
        } else if (isUsernameWorkspaceMembership(assoc.getModel())) {
            String group = dmx.getTopic(assoc.getPlayer2().getId()).getChildTopics().getString(GROUP_TYPE, null);

            String userName = dmx.getTopic(assoc.getPlayer1().getId()).getSimpleValue().toString();
            String workspaceOwner = acs.getWorkspaceOwner(assoc.getPlayer2().getId());

            if (group != null && !userName.equals(workspaceOwner)) {
                boolean isAdmin = userName.equals(AccessControlService.ADMIN_USERNAME);
                ldap.addMember(group, userName, isAdmin);
            }
        }
    }

    @Override
    public void postDeleteAssoc(AssocModel assoc) {
        if (isWorkspaceGroupComposition(assoc)) {
            // Group name is removed from workspace: Delete group entirely
            String group = dmx.getTopic(assoc.getPlayer2().getId()).getSimpleValue().toString();

            ldap.deleteGroup(group);
        } else if (isUsernameWorkspaceMembership(assoc)) {
            String group = dmx.getTopic(assoc.getPlayer2().getId()).getChildTopics().getString(GROUP_TYPE, null);

            String userName = dmx.getTopic(assoc.getPlayer1().getId()).getSimpleValue().toString();
            String workspaceOwner = acs.getWorkspaceOwner(assoc.getPlayer2().getId());

            if (group != null && !userName.equals(workspaceOwner)) {
                boolean isAdmin = userName.equals(AccessControlService.ADMIN_USERNAME);
                ldap.removeMember(group, userName, isAdmin);
            }

        }

    }

    private boolean isType(PlayerModel playerModel, String typeUri) {
        return playerModel.getTypeUri().equals(typeUri);
    }

    private boolean isType(AssocModel assoc, String typeUri) {
        return assoc.getTypeUri().equals(typeUri);
    }

}
