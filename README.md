## LDAP Authentication for DeepaMehta 4

### Configuration / Usage

In `config.properties` operatores have the following properties to configure:

#### LDAP Protocol without encryption

```
dm4.ldap.protocol = LDAP
dm4.ldap.server = 127.0.0.1
dm4.ldap.port = 
dm4.ldap.manager = 
dm4.ldap.password = 
dm4.ldap.user_base = 
dm4.ldap.user_attribute = 
dm4.ldap.user_filter = 
dm4.ldap.user_member_group = 
dm4.ldap.logging = INFO
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

Note: For self signed certificates, dm4.ldap.server must contain the hostname of the certificate, not the IP address.

Known logging values are:
 
- INFO (default): Only warnings and errors are logged including possible misconfigurations.
- DEBUG: Hints, warning and errors are extensively logged during configuration and runtime phase.

#### Changelog

Next Feature Release: 

* Fetch and write user profile data in LDAP System
* Creating new user accounts in LDAP System

**0.3.7** -- Sep 8, 2020

* DM4-only
* Check credentials before deletion

**0.3.6** -- Aug 5, 2020

* DM4-only
* Delete User

**0.3.4** -- Nov 26, 2018

* Throw exceptions in cases of misconfiguration or any kind of error
* User creation, including automatic placing in memberOf group)
* Password change (SSHA passwords-only)
* Info and Debug Log setting
* Added many more logging locations
* Extensive checking of configuration validity (including keystore)

**0.3.0** -- Feb 27, 2018

* Add StartTLS and LDAPS/SSL protocols

**0.2.0** -- Feb 4, 2018

* Creates only a DM Username topic (along with private workspace) on first successful LDAP login
* Requires DeepaMehta 4.9.1

**0.1.0** -- Nov 30, 2017

* Basic functionality
* Creates full DM User Account on first successful LDAP login
* Requires DeepaMehta 4.9
