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

#### Changelog

Next Feature Release: 

* Fetch and write user profile data in LDAP System
* Creating new user accounts in LDAP System

**0.4.0** -- Apr 11, 2019

* Source code compatible with DMX
* Log messages contain configuration keys
* Fixed plugin crashing when no or no valid configuration given

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
