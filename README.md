## LDAP Authentication for DMX

### Configuration / Usage

In `config.properties` operatores have the following properties to configure:

#### LDAP Protocol without encryption

```
dmx.ldap.protocol = LDAP
dmx.ldap.server = 127.0.0.1
dmx.ldap.port = 389  
dmx.ldap.manager = 
dmx.ldap.password = 
dmx.ldap.user_base = 
dmx.ldap.user_attribute = 
dmx.ldap.user_filter = 
dmx.ldap.user_member_group = 
dmx.ldap.logging = INFO
```

Known Protocols are: 

- StartTLS (ldap://HOST:389) - default port is 389
- LDAPS (ldaps://HOST:636) - default port is 636
- LDAP (ldap://HOST:389) - default port is 389

Additional settings for self-signed certificates used with keystore:

```
javax.net.ssl.trustStore = /path/to/keystore.jks
javax.net.ssl.trustStorePassword = changeit
```

Note: For self signed certificates, dmx.ldap.server must contain the hostname of the certificate, not the IP address.

Known logging values are:
 
- INFO (default): Only warnings and errors are logged including possible misconfigurations.
- DEBUG: Hints, warning and errors are extensively logged during configuration and runtime phase.

