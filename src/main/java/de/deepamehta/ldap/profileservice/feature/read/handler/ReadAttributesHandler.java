package de.deepamehta.ldap.profileservice.feature.read.handler;

import de.deepamehta.ldap.profileservice.feature.common.usecase.RunOnLdap;
import de.deepamehta.ldap.profileservice.feature.read.usecase.LoadAttribute;
import de.deepamehta.ldap.profileservice.model.LdapAttribute;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ReadAttributesHandler {

    private final RunOnLdap runOnLdap;

    private final LoadAttribute loadAttribute;

    public ReadAttributesHandler(RunOnLdap runOnLdap,
                          LoadAttribute loadAttribute) {
        this.runOnLdap = runOnLdap;
        this.loadAttribute = loadAttribute;
    }

    public Map<LdapAttribute, String> invoke(String userName, String password, List<LdapAttribute> requestedAttributes) {
        HashMap<LdapAttribute, String> resultMap = new HashMap<>();

        runOnLdap.invoke(userName, password, (session -> {

            for (LdapAttribute attribute : requestedAttributes) {
                String value = loadAttribute.invoke(session, attribute);

                resultMap.put(attribute, value);
            }

        }));

        return resultMap;
    }

}
