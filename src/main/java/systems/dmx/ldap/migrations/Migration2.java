package systems.dmx.ldap.migrations;

import systems.dmx.core.TopicType;
import systems.dmx.core.service.Migration;
import systems.dmx.ldap.LDAPPlugin;

public class Migration2 extends Migration {

    @Override
    public void run() {
        TopicType wsType = dmx.getTopicType(LDAPPlugin.WORKSPACE_TYPE);
        wsType.addCompDef(
                mf.newCompDefModel(
                        LDAPPlugin.WORKSPACE_TYPE,
                        LDAPPlugin.GROUP_TYPE,
                        "dmx.core.one"
                )
        );
    }

}
