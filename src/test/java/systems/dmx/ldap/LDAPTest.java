package systems.dmx.ldap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class LDAPTest {

    @Test
    @DisplayName("newInstance() should create JndiLDAP when bind account is used")
    void newInstance_should_create_JndiLDAP() {
        // given:
        boolean useBindAccount = true;
        Configuration configuration = new Configuration(
                Configuration.ProtocolType.LDAP, "localhost", "", Configuration.LoggingMode.INFO, false,
                useBindAccount,
                "", "", "", "", "", "", ""
        );

        // when:
        LDAP result = LDAP.newInstance(configuration, mock());

        // then:
        assertThat(result).isInstanceOf(JndiLDAP.class);
    }

    @Test
    @DisplayName("newInstance() should create NonManagerJndiLDAP when no bind account is used")
    void NonManagerJndiLDAP() {
        // given:
        boolean useBindAccount = false;
        Configuration configuration = new Configuration(
                Configuration.ProtocolType.LDAP, "localhost", "", Configuration.LoggingMode.INFO, false,
                useBindAccount,
                "", "", "", "", "", "", ""
        );

        // when:
        LDAP result = LDAP.newInstance(configuration, mock());

        // then:
        assertThat(result).isInstanceOf(NonManagerJndiLDAP.class);
    }
}