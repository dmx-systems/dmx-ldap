package systems.dmx.ldap;

import systems.dmx.accesscontrol.AccessControlService;
import systems.dmx.accountmanagement.AccountManagementService;
import systems.dmx.accountmanagement.AccountManager;
import systems.dmx.core.Assoc;
import systems.dmx.core.Topic;
import systems.dmx.core.model.AssocModel;
import systems.dmx.core.model.PlayerModel;
import systems.dmx.core.osgi.PluginActivator;
import systems.dmx.core.service.Inject;
import systems.dmx.core.service.Transactional;
import systems.dmx.core.service.event.PostCreateAssoc;
import systems.dmx.core.service.event.PreDeleteAssoc;
import systems.dmx.ldap.repository.JndiRepository;
import systems.dmx.ldap.service.LDAPService;
import systems.dmx.workspaces.WorkspacesService;

import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@Path("/ldap")
public class LDAPPlugin extends PluginActivator implements LDAPService, PostCreateAssoc, PreDeleteAssoc {

    public static final String WORKSPACE_TYPE = "dmx.workspaces.workspace";
    public static final String GROUP_TYPE = "systems.dmx.ldap.group";
    public static final String COMPOSITION_ASSOC_TYPE = "dmx.core.composition";
    public static final String MEMBERSHIP_ASSOC_TYPE = "dmx.accesscontrol.membership";
    public static final String USERNAME_TOPIC_TYPE = "dmx.accesscontrol.username";

    private static final Logger logger = Logger.getLogger(LDAPPlugin.class.getName());

    @Inject
    private AccessControlService acs;

    @Inject
    private WorkspacesService wss;

    @Inject
    private AccountManagementService accountManagementService;

    private Configuration configuration;

    private JndiRepository repository;

    private AccountManager accountManager;

    @Override
    public void serviceArrived(Object service) {
        // Nothing to do
    }

    @Override
    public void serviceGone(Object service) {
        if (service instanceof AccountManagementService && accountManager != null) {
            ((AccountManagementService) service).unregisterAccountManager(accountManager);
        }
    }

    @Override
    public void init() {
        try {
            configuration = Configuration.createFromProperties();
        } catch (Exception e) {
            configuration = Configuration.createFallback();
            logger.log(Level.SEVERE, "Error parsing configuration", e);
            logger.log(Level.SEVERE, "Configuration could not be parsed. Providing an emergency fallback " +
                    "configuration. LDAP logins will not work!");
        }
        logger.info(() -> String.format("Plugin configuration:\n%s", configuration.summary()));
        if (!configuration.check()) {
            logger.log(Level.SEVERE, "LDAP Plugin configuration is not correct. Please fix the issues mentioned " +
                    "in the log.");
            repository = JndiRepository.newDummyInstance();
        } else {
            repository = JndiRepository.newInstance(configuration);
        }

        accountManager = new LDAPAccountManager(configuration, repository);
        accountManagementService.registerAccountManager(accountManager);
    }

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    private String sanitise(String sourceUsername) {
        return sourceUsername.toLowerCase(Locale.ROOT);
    }

    @DELETE
    @Path("/user/{username}")
    @Transactional
    @Override
    public void deleteUser(@PathParam("username") String userName) {
        try {
            userName = sanitise(userName);
            // delete from DMX
            dmx.getPrivilegedAccess().getUsernameTopic(userName).delete();
            // delete from LDAP
            boolean success = repository.deleteUser(userName);
            if (!success) {
                throw new RuntimeException("ldap.deleteUser() returned false; see server log for actual error");
            }
        } catch (Exception e) {
            throw new RuntimeException("Deleting LDAP user \"" + userName + "\" failed", e);
        }
    }

    private List<String> getMembers(Topic workspaceTopic, String excluded) {
        return workspaceTopic.getRelatedTopics(
            MEMBERSHIP_ASSOC_TYPE,
            null,
            null,
            USERNAME_TOPIC_TYPE
        ).stream().map(relatedTopic -> relatedTopic.getSimpleValue().toString())
            .filter(name -> !name.equals(excluded)).collect(Collectors.toList());
    }

    private boolean isWorkspaceGroupComposition(AssocModel assoc) {
        return isType(assoc, COMPOSITION_ASSOC_TYPE)
            && isType(assoc.getPlayer1(), WORKSPACE_TYPE)
            && isType(assoc.getPlayer2(), GROUP_TYPE);
    }

    private boolean isUsernameWorkspaceMembership(AssocModel assoc) {
        return isType(assoc, MEMBERSHIP_ASSOC_TYPE)
            && isPlayerType(assoc, USERNAME_TOPIC_TYPE)
            && isPlayerType(assoc, WORKSPACE_TYPE);
    }

    @Override
    public void postCreateAssoc(Assoc assoc) {
        if (isWorkspaceGroupComposition(assoc.getModel())) {
            String userName = acs.getWorkspaceOwner(assoc.getPlayer1().getId());
            String group = dmx.getTopic(assoc.getPlayer2().getId()).getSimpleValue().toString();
            Topic workspace = dmx.getTopic(assoc.getPlayer1().getId());
            repository.createGroup(group, userName, getMembers(workspace, userName));
        } else if (isUsernameWorkspaceMembership(assoc.getModel())) {
            String group = assoc.getDMXObjectByType(WORKSPACE_TYPE).getChildTopics().getString(GROUP_TYPE, null);
            String userName = assoc.getDMXObjectByType(USERNAME_TOPIC_TYPE).getSimpleValue().toString();
            String workspaceOwner = acs.getWorkspaceOwner(assoc.getPlayer2().getId());
            if (group != null && !userName.equals(workspaceOwner)) {
                repository.addMember(group, userName);
            }
        }
    }

    @Override
    public void preDeleteAssoc(Assoc assoc) {
        AssocModel _assoc = assoc.getModel();
        if (isWorkspaceGroupComposition(_assoc)) {
            // Group name is removed from workspace: Delete group entirely
            String group = dmx.getTopic(_assoc.getPlayer2().getId()).getSimpleValue().toString();
            repository.deleteGroup(group);
        } else if (isUsernameWorkspaceMembership(_assoc)) {
            String group = assoc.getDMXObjectByType(WORKSPACE_TYPE).getChildTopics().getString(GROUP_TYPE, null);
            String userName = assoc.getDMXObjectByType(USERNAME_TOPIC_TYPE).getSimpleValue().toString();
            String workspaceOwner = acs.getWorkspaceOwner(_assoc.getPlayer2().getId());
            if (group != null && !userName.equals(workspaceOwner)) {
                repository.removeMember(group, userName);
            }
        }
    }

    private boolean isPlayerType(AssocModel assoc, String typeUri) {
        return assoc.getPlayer1().getTypeUri().equals(typeUri)
            || assoc.getPlayer2().getTypeUri().equals(typeUri);
    }

    private boolean isType(PlayerModel playerModel, String typeUri) {
        return playerModel.getTypeUri().equals(typeUri);
    }

    private boolean isType(AssocModel assoc, String typeUri) {
        return assoc.getTypeUri().equals(typeUri);
    }
}
