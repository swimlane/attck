
# Forced Authentication Mitigation

## Description

### MITRE Description

> Block SMB  traffic from exiting an enterprise network with egress filtering or by blocking TCP ports 139, 445 and UDP port 137. Filter or block WebDAV protocol traffic from exiting the network. If access to external resources over SMB and WebDAV is necessary, then traffic should be tightly limited with whitelisting. (Citation: US-CERT SMB Security) (Citation: US-CERT APT Energy Oct 2017)

For internal traffic, monitor the workstation-to-workstation unusual (vs. baseline) SMB traffic. For many networks there should not be any, but it depends on how systems on the network are configured and where resources are located.

Use strong passwords to increase the difficulty of credential hashes from being cracked if they are obtained.


# Techniques


* [Forced Authentication](../techniques/Forced-Authentication.md)

