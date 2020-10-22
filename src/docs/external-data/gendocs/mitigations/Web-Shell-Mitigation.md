
# Web Shell Mitigation

## Description

### MITRE Description

> Ensure that externally facing Web servers are patched regularly to prevent adversary access through [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) to gain remote code access or through file inclusion weaknesses that may allow adversaries to upload files or scripts that are automatically served as Web pages. 

Audit account and group permissions to ensure that accounts used to manage servers do not overlap with accounts and permissions of users in the internal network that could be acquired through Credential Access and used to log into the Web server and plant a Web shell or pivot from the Web server into the internal network. (Citation: US-CERT Alert TA15-314A Web Shells)


# Techniques


* [Web Shell](../techniques/Web-Shell.md)

