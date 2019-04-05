package de.deepamehta.ldap.profileservice.service;

import de.deepamehta.ldap.Configuration;
import de.deepamehta.ldap.PluginLog;
import de.deepamehta.ldap.profileservice.feature.common.usecase.RunOnLdap;
import de.deepamehta.ldap.profileservice.feature.read.handler.ReadAttributesHandler;
import de.deepamehta.ldap.profileservice.feature.read.usecase.LoadAttribute;
import de.deepamehta.ldap.profileservice.feature.update.handler.UpdateAttributesHandler;
import de.deepamehta.ldap.profileservice.feature.update.usecase.StoreAttribute;
import de.deepamehta.ldap.profileservice.model.LdapAttribute;
import de.deepamehta.ldap.profileservice.repository.LdapRepository;
import de.deepamehta.ldap.profileservice.repository.jndi.JndiLdapRepository;

import java.util.*;
import java.util.stream.Collectors;

public class ProfileServiceImpl implements ProfileService {

    private final ReadAttributesHandler readAttributesHandler;

    private final UpdateAttributesHandler updateAttributesHandler;

    private final String userName;

    private final String password;

    public ProfileServiceImpl(
            Configuration configuration,
            PluginLog pluginLog,
            String userName,
            String password) {
        this.userName = userName;
        this.password = password;

        LdapRepository ldapRepository = new JndiLdapRepository(configuration, pluginLog);

        RunOnLdap runOnLdap = new RunOnLdap(ldapRepository);

        readAttributesHandler = new ReadAttributesHandler(
                runOnLdap,
                new LoadAttribute(ldapRepository));

        updateAttributesHandler = new UpdateAttributesHandler(
                runOnLdap,
                new StoreAttribute(ldapRepository));
    }

    private HashMap<LdapAttribute, String> setupMap(MapSetupRunner runner) {
        HashMap<LdapAttribute, String> map = new HashMap<>();

        runner.invoke(map);

        return map;
    }

    private interface MapSetupRunner {
        void invoke(HashMap<LdapAttribute, String> map);
    }

    @Override
    public boolean update(Attribute attribute, String value) {
        return updateAttributesHandler.invoke(userName, password, setupMap(map -> {
            map.put(attribute.ldapAttribute, value);
        }));
    }

    @Override
    public boolean update(Map<Attribute, String> values) {
        return updateAttributesHandler.invoke(userName, password, setupMap(map -> {
            for (Map.Entry<Attribute, String> entry : values.entrySet()) {
                map.put(entry.getKey().ldapAttribute, entry.getValue());
            }
        }));
    }

    @Override
    public String read(Attribute attribute) {
        return readAttributesHandler
                .invoke(userName,
                        password,
                        Collections.singletonList(attribute.ldapAttribute))
                .get(attribute.ldapAttribute);
    }

    @Override
    public Map<Attribute, String> read(List<Attribute> attributes) {
        return readAttributesHandler
                .invoke(userName,
                        password,
                        attributes.stream().map(a -> a.ldapAttribute).collect(Collectors.toList()))
                .entrySet()
                .stream()
                .collect(Collectors.toMap(
                        e -> Attribute.findByLdapAttribute(e.getKey()),
                        Map.Entry::getValue));
    }
}
