package systems.dmx.ldap.repository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class BindUserJndiRepositoryTest {

    private final LdapContext ctx = mock();

    private final String managerUser = "manager user";

    private final String managerPassword = "manager password";

    private final JndiDatasource datasource = mock();

    private final BindUserJndiRepository subject = new BindUserJndiRepository(
            managerUser,
            managerPassword,
            datasource
    );

    @BeforeEach
    void beforeEach() throws NamingException {
        when(datasource.connect(any(), any())).thenReturn(ctx);
    }

    @Test
    @DisplayName("checkCredentials() should connect with manager user")
    void checkCredentials_should_connect_with_manager_user() throws NamingException {
        // given:
        String username = "someuser";
        String password = "somepassword";
        doNothing().when(datasource).checkCredentialsWithLookup(any(), any(), any());

        // when:
        subject.checkCredentials(username, password);

        // then:
        verify(datasource).connect(managerUser, managerPassword);
    }

    @Test
    @DisplayName("checkCredentials() should check credentials with lookup")
    void checkCredentials_should_check_credentials_with_lookup() throws NamingException {
        // given:
        String username = "someuser";
        String password = "somepassword";
        doNothing().when(datasource).checkCredentialsWithLookup(any(), any(), any());

        // when:
        subject.checkCredentials(username, password);

        // then:
        verify(datasource).checkCredentialsWithLookup(ctx, username, password);
    }

    @Test
    @DisplayName("checkCredentials() should return true when check succeeds")
    void checkCredentials_should_return_true_when_check_succeeds() throws NamingException {
        // given:
        String username = "someuser";
        String password = "somepassword";
        doNothing().when(datasource).checkCredentialsWithLookup(any(), any(), any());

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
        doThrow(exception).when(datasource).checkCredentialsWithLookup(any(), any(), any());

        // when:
        boolean result = subject.checkCredentials(username, password);

        // then:
        assertThat(result).isFalse();
    }
}