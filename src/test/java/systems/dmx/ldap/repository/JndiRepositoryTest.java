package systems.dmx.ldap.repository;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import systems.dmx.ldap.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class JndiRepositoryTest {

    @Test
    @DisplayName("newInstance() should create BindUserJndiRepository instance when bind account is used")
    void newInstance_should_create_BindUserJndiRepository_instance() {
        // given:
        boolean useBindAccount = true;
        Configuration configuration = new Configuration(
                Configuration.ProtocolType.LDAP, "localhost", "", false, false,
                useBindAccount,
                "", "", "", "", "", "", ""
        );

        // when:
        JndiRepository result = JndiRepository.newInstance(configuration);

        // then:
        assertThat(result).isInstanceOf(BindUserJndiRepository.class);
    }

    @Test
    @DisplayName("newInstance() should create NonBindUserJndiRepository instance when no bind account is used")
    void newInstance_should_create_NonBindUserJndiRepository_instance() {
        // given:
        boolean useBindAccount = false;
        Configuration configuration = new Configuration(
                Configuration.ProtocolType.LDAP, "localhost", "", false, false,
                useBindAccount,
                "", "", "", "", "", "", ""
        );

        // when:
        JndiRepository result = JndiRepository.newInstance(configuration);

        // then:
        assertThat(result).isInstanceOf(NonBindUserJndiRepository.class);
    }
}