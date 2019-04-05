package de.deepamehta.ldap.profileservice.feature.update.handler;

import de.deepamehta.ldap.profileservice.feature.common.usecase.RunOnLdap;
import de.deepamehta.ldap.profileservice.feature.update.usecase.StoreAttribute;
import de.deepamehta.ldap.profileservice.model.LdapAttribute;

import java.util.Map;

public class UpdateAttributesHandler {

    private final RunOnLdap runOnLdap;

    private final StoreAttribute storeAttribute;

    public UpdateAttributesHandler(RunOnLdap runOnLdap,
                            StoreAttribute storeAttribute) {
        this.runOnLdap = runOnLdap;
        this.storeAttribute = storeAttribute;
    }

    public boolean invoke(String userName, String password, Map<LdapAttribute, String> data) {
        return runOnLdap.invoke(userName, password, (session -> {

            for (Map.Entry<LdapAttribute, String> entry : data.entrySet()) {
                if (!storeAttribute.invoke(session, entry.getKey(), entry.getValue())) {
                    return false;
                }
            }

            return true;
        }));


    }

}
