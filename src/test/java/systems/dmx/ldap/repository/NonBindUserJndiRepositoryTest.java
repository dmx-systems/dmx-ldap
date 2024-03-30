package systems.dmx.ldap.repository;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class NonBindUserJndiRepositoryTest {

    private final LdapContext ctx = mock();

    private final JndiDatasource datasource = mock();

    private final NonBindUserJndiRepository subject = new NonBindUserJndiRepository(
            datasource
    );

    @Test
    @DisplayName("checkCredentials() should not connect")
    void checkCredentials_should_not_connect() throws NamingException {
        // given:
        String username = "someuser";
        String password = "somepassword";
        doNothing().when(datasource).checkCredentialsWithLookup(any(), any(), any());

        // when:
        subject.checkCredentials(username, password);

        // then:
        verify(datasource, times(0)).connect(any(), any());
    }

    @Test
    @DisplayName("checkCredentials() should check credentials directly")
    void checkCredentials_should_check_credentials_directly() throws NamingException {
        // given:
        String username = "someuser";
        String password = "somepassword";
        doNothing().when(datasource).checkCredentials(any(), any());

        // when:
        subject.checkCredentials(username, password);

        // then:
        verify(datasource).checkCredentials(username, password);
    }

    @Test
    @DisplayName("checkCredentials() should return true when check succeeds")
    void checkCredentials_should_return_true_when_check_succeeds() throws NamingException {
        // given:
        String username = "someuser";
        String password = "somepassword";
        doNothing().when(datasource).checkCredentials(any(), any());

        // when:
        boolean result = subject.checkCredentials(username, password);

        // then:
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("checkCredentials() should return false when check fails")
    void checkCredentials_should_return_false_when_check_fails() throws NamingException {
        // given:
        String username = "someuser";
        String password = "somepassword";
        NamingException exception = mock();
        doThrow(exception).when(datasource).checkCredentials(any(), any());

        // when:
        boolean result = subject.checkCredentials(username, password);

        // then:
        assertThat(result).isFalse();
    }
}