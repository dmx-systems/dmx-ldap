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
dmx.ldap.user_creation.enabled = false
dmx.ldap.group_base = 
```
LDAP Group functionality:
If a proper group base is set, then the plugin will allow setting a group attribute on Workspace topics. The group
name forms a distinguished name together with the group base configuration value in the form
``` 
 cn=<group name>,<group base>
```
When the group attribute is first set, then a corresponding LDAP Group (groupOf) is created with the user that
is the owner of the workspace as the first member. If that member is the admin and the admin is not handled in
LDAP the LDAP manager account is used as a fallback.

User creation:
The plugin is able to create new entries in the LDAP through a plugin method. However this critical functionality is
only available if the property dmx.ldap.user_creation.enabled is set to true and the given manager account has write
privilege in the LDAP.

Known Protocols are: 

- StartTLS (ldap://HOST:389) - default port is 389
- LDAPS (ldaps://HOST:636) - default port is 636
- LDAP (ldap://HOST:389) - default port is 389

Additional settings for self-signed certificates used with keystore:
javax.net.ssl.trustStore = /path/to/keystore.jksffero General Public License, version 3.
All third party components incorporated into the DMX Tableview Software are licensed under the original license provided by the owner of the applicable component.
javax.net.ssl.trustStorePassword = changeit

```
Note: For self signed certificates, dmx.ldap.server must contain the hostname of the certificate, not the IP address.
```

Interaction using Topics

Topics of type systems.dmx.ldap.groupdn (GroupDN) can define a DN which denotes a groupOf object in LDAP.

When a default association between a Workspace and the GroupDN topic is created the LDAP plugin creates the
groupOf object. Additionally it sets the owner of the workspace as the first member of the groupOf object.

It is assumed that the workspace owner, a DMX user, has a LDAP representation.

If the workspace owner is the admin user but does not have a LDAP representation, the plugin uses the
configured manager account instead. 

When the association between a workspace and a GroupDN is deleted, the corresponding workspace owner's
member attribute is removed. When the last entry is about to be removed, the actual groupOf object is
deleted as well.

### Usage without bind account
By default the LDAP plugin needs a bind (or manager) account. This allows operations such as changing passwords or group
management. However in some installations an LDAP manager account is not present but the LDAP plugin should still be
used for DMX login purposes. This is made possible by setting:

```
dmx.ldap.use_bind_account = false
```

In this mode the manager account is not used for checking the credentials. This implies that a group lookup is also not
done or possible. Instead the username is converted into a distinguished name using the user base and user attribute
settings. Be sure to have those set up correctly for your environment!

Note: The non-bind account operation only allows logins. Password change and group management operations are not
possible in such a configuration!

## Licensing

DMX LDAP is available freely under the GNU Affero General Public License, version 3.<br/>

All third party components incorporated into the DMX LDAP Software are licensed under the original license provided by the owner of the applicable component.<br/>
Spring Security Crypto 5.0.7, Apache API LDAP Client API 2.0.0.AM2, and Commons Lang 2.6 are all Apache-2.0 licensed.

## Release History
**0.8.0** -- TBD

* Compatible with DMX 5.3.5
* Allow usage for login purposes without bind (manager) account

**0.7.0** -- Nov, 22, 2023

* API change: service interface renamed to LDAPService
* Compatible with DMX 5.3.3

**0.6.2** -- Jul, 14, 2023

* Compatible with DMX 5.3

**0.6.1** -- May, 27, 2022

* All usernames given by DMX are sanitised by lowercasing them 

**0.6.0** -- Apr 27, 2022

* Deleting user in DMX and LDAP
* Workspace/LDAP Group handling

**0.5.3** -- Jun 30, 2021

* Compatible with DMX 5.2

**0.5.2.** -- Jan 02, 2021

* Compatible with DMX 5.1

**0.5.1** -- Dec 15, 2019

* Compatible with DMX 5.0-beta-6

## Copyright

Copyright (C) 2018-2019 DMX Systems

