package systems.dmx.ldap;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import org.apache.commons.lang.StringUtils;

public class Configuration {

    ProtocolType protocol;
    String server;
    String port;

    ImplementationType implementation;
    LoggingMode loggingMode;

    boolean userCreationEnabled;

    String manager;
    String password;

    String userBase;
    String userAttribute;
    String userFilter;
    String userMemberGroup;

    String groupBase;

    private String connectionUrl;

    String getConnectionUrl() {
        return connectionUrl;
    }

    public enum ProtocolType {
        LDAP,
        LDAPS,
        STARTTLS
    }

    public enum ImplementationType {
        JNDI,
        APACHE
    };

    public enum LoggingMode {
        INFO,
        DEBUG
    }

    private Configuration() {
        // No op
    }

    //
    static Configuration createFromProperties() {
        Configuration c = new Configuration();
        // 1) Providing default configuration
        c.server = System.getProperty("dmx.ldap.server", "127.0.0.1");
        // ldap (default), ldaps and starttls
        c.protocol = ProtocolType.valueOf(System.getProperty("dmx.ldap.protocol", "ldap").toUpperCase());
        c.port = System.getProperty("dmx.ldap.port", "389");
        // production (default) or troubleshooting
        c.loggingMode = LoggingMode.valueOf(System.getProperty("dmx.ldap.logging", "info").toUpperCase());
        c.userCreationEnabled = System.getProperty("dmx.ldap.user_creation.enabled", "false").equals("true");
        // jndi (default) or apache
        // c.implementation = ImplementationType.valueOf(System.getProperty("dmx.ldap.implementation", "jndi").toUpperCase());
        c.implementation = ImplementationType.JNDI;
        // 2) ### FIXME: no config defaults provided
        c.manager = System.getProperty("dmx.ldap.manager", "");
        c.password = System.getProperty("dmx.ldap.password", "");
        c.userBase = System.getProperty("dmx.ldap.user_base", "");
        c.userAttribute = System.getProperty("dmx.ldap.user_attribute", "");
        c.userFilter = System.getProperty("dmx.ldap.user_filter", "");
        c.userMemberGroup = System.getProperty("dmx.ldap.user_member_group", "");
        c.groupBase = System.getProperty("dmx.ldap.group_base", "");
        return c;
    }

    static Configuration createFallback() {
        Configuration c = new Configuration();
        c.server = "127.0.0.1";
        c.protocol = ProtocolType.LDAP;
        c.port = "389";
        c.loggingMode = LoggingMode.DEBUG;
        c.implementation = ImplementationType.JNDI;
        c.manager = "";
        c.password = "";
        c.userBase = "";
        c.userAttribute = "";
        c.userFilter = "";
        c.userMemberGroup = "";
        c.groupBase = "";

        return c;
    }

    boolean check(PluginLog log) {
        int errorCount = 0;

        log.configurationHint("Logging is set up for %s environment.", loggingMode.toString().toLowerCase());

        if (StringUtils.isEmpty(manager)) {
            log.configurationError("No manager account provided. Check property 'dmx.ldap.manager'!");
            errorCount++;
        }

        if (StringUtils.isEmpty(password)) {
            log.configurationWarning("No manager password provided. Check property 'dmx.ldap.password'!");
        }

        if (StringUtils.isEmpty(userBase)) {
            log.configurationError("No user base provided. Check property 'dmx.ldap.user_base'!");
            errorCount++;
        }

        if (StringUtils.isEmpty(userAttribute)) {
            log.configurationHint("User attribute not set. Defaults to 'uid'. Check property 'dmx.ldap.user_attribute' to customize!");
            userAttribute = "uid";
        }

        if (StringUtils.isEmpty(userFilter)) {
            log.configurationHint("No filter expression provided. Defaulting to mere existance check. Check property 'dmx.ldap.user_filter' to customize!");
        }

        if (StringUtils.isEmpty(groupBase)) {
            log.configurationHint("No group base defined. LDAP Group handling will not work. Check property 'dmx.ldap.group_base'!");
        }

        if (userCreationEnabled) {
            log.configurationHint("User creation enabled. LDAP entry creation and attribute modification may occur.");

            if (StringUtils.isEmpty(userMemberGroup)) {
                log.configurationHint("No member group provided. Automatically adding inetOrgPerson entries to groups is disabled. Check property 'dmx.ldap.user_member_group' to customize!");

                if (StringUtils.isNotEmpty(userFilter)) {
                    log.configurationWarning("Custom filter expression provided but no member group for new users. This might lead to new users not being able to log-in. Check property 'dmx.ldap.user_member_group'!");
                }

            } else {
                log.configurationHint("Automatically adding inetOrgPerson entries to groups is enabled.");

                if (StringUtils.isEmpty(userFilter)) {
                    log.configurationWarning("Member group defined but no filter expression. As such group membership is not checked during log-in. Check property 'dmx.ldap.user_filter'!");
                }

            }

        } else {
            log.configurationHint("User creation disabled. All LDAP accesses are read-only.");
        }

        // Checking keystore: A wrongly configured keystore leads to logged warnings but will not stop the plugin start.
        // The reason is that the keystore might have been set up for something else than the LDAP plugin
        // as it affects all SSL/TLS connections.
        String trustStore = System.getProperty("javax.net.ssl.trustStore", "");
        String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword", "");
        if (protocol != ProtocolType.LDAP) {
            if (StringUtils.isEmpty(trustStore)) {
                log.configurationWarning("Secure connection requested but no custom SSL/TLS trust store defined. Connection negotiation may fail. Check system property 'javax.net.ssl.trustStore' and 'javax.net.ssl.trustStorePassword'!");
            } else {

                if (StringUtils.isEmpty(trustStorePassword)) {
                    log.configurationWarning("Custom keystore was configured but password is empty. Opening the keystore and accessing its content may fail. Check system property 'javax.net.ssl.trustStorePassword'!");
                }

                try {
                    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

                    keyStore.load(new FileInputStream(trustStore), trustStorePassword.toCharArray());

                    log.configurationHint("Configured trust store %s is usable with provided password.", trustStore);

                    int count = 0;
                    Enumeration<String> aliases = keyStore.aliases();
                    while (aliases.hasMoreElements()) {
                        count++;
                        aliases.nextElement();
                    }

                    if (count == 0) {
                        log.configurationError("Configured trust store does not contain any aliases. Please check the file.");
                    } else {
                        log.configurationHint("Configured trust store contains %s aliases. It appears valid for SSL/TLS connections", count);
                    }

                } catch (KeyStoreException e) {
                    log.configurationError("Unable to initialize default trust store. Expecting \"Java Keystore\" format: %s", e.getLocalizedMessage());
                } catch (NoSuchAlgorithmException e) {
                    log.configurationError("Unable to load trust store. Check whether it is in the default \"Java Keystore\" format: %s", e.getLocalizedMessage());
                } catch (CertificateException e) {
                    log.configurationError("Unable to load trust store. Issue with certificates: %s", e.getLocalizedMessage());
                } catch (FileNotFoundException e) {
                    log.configurationError("Trust store configured to %s but file is not accessible: %s. Check system property 'javax.net.ssl.trustStore' and 'javax.net.ssl.trustStorePassword'!", trustStore, e.getLocalizedMessage());
                } catch (IOException e) {
                    log.configurationError("Trust store configured to %s but reading the file failed: %s. Check system property 'javax.net.ssl.trustStore' and 'javax.net.ssl.trustStorePassword'!", trustStore, e.getLocalizedMessage());
                }

            }
        } else {
            if (StringUtils.isNotEmpty(trustStore)) {
                log.configurationWarning("A trust store located at %s was specified but using a non-SSL/TLS protocol. Check configuration.", trustStore);
            }
        }

        return errorCount == 0;
    }

    void compile() {
        // If no port was set, select defaults by protocol
        if (StringUtils.isEmpty(port)) {
            port = protocol == ProtocolType.LDAP ? "636" : "389";
        }

        connectionUrl = String.format("ldap%s://%s:%s",
                protocol == ProtocolType.LDAPS ? "s" : "",
                server,
                port);
    }

    String summary() {
        String trustStore = System.getProperty("javax.net.ssl.trustStore", "");
        String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword", "");

        // Shows trust store information when protocol is not-LDAP or a non-empty trust store is given
        String trustStoreSummary = (protocol != ProtocolType.LDAP || StringUtils.isNotEmpty(trustStore))
                ? String.format("javax.net.ssl.trustStore=%s\njavax.net.ssl.trustStorePassword=%s", trustStore, StringUtils.isEmpty(trustStorePassword) ? "" : "***")
                : "";

        String maskedPassword = StringUtils.isEmpty(password) ? "" : "***";
        return String.format(
                "dmx.ldap.protocol=%s\ndmx.ldap.server=%s\ndmx.ldap.port=%s\ndmx.ldap.implementation=%s\ndmx.ldap.logging=%s\ndmx.ldap.user_creation.enabled=%s\ndmx.ldap.manager=%s\ndmx.ldap.password=%s\ndmx.ldap.user_base=%s\ndmx.ldap.user_attribute=%s\ndmx.ldap.user_acceptance_filter=%s\ndmx.ldap.user_member_group=%s\ndmx.ldap.group_base=%s\n%s",
                protocol, server, port, implementation, loggingMode, userCreationEnabled, manager, maskedPassword, userBase,
                userAttribute, userFilter, userMemberGroup, groupBase, trustStoreSummary);
    }

}
