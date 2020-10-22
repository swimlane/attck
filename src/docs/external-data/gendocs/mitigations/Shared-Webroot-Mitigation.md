
# Shared Webroot Mitigation

## Description

### MITRE Description

> Networks that allow for open development and testing of Web content and allow users to set up their own Web servers on the enterprise network may be particularly vulnerable if the systems and Web servers are not properly secured to limit privileged account use, unauthenticated network share access, and network/system isolation.

Ensure proper permissions on directories that are accessible through a Web server. Disallow remote access to the webroot or other directories used to serve Web content. Disable execution on directories within the webroot. Ensure that permissions of the Web server process are only what is required by not using built-in accounts; instead, create specific accounts to limit unnecessary access or permissions overlap across multiple systems. (Citation: acunetix Server Secuirty) (Citation: NIST Server Security July 2008)


# Techniques


* [Shared Webroot](../techniques/Shared-Webroot.md)

