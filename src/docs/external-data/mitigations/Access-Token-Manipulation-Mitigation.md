
# Access Token Manipulation Mitigation

## Description

### MITRE Description

> Access tokens are an integral part of the security system within Windows and cannot be turned off. However, an attacker must already have administrator level access on the local system to make full use of this technique; be sure to restrict users and accounts to the least privileges they require to do their job.

Any user can also spoof access tokens if they have legitimate credentials. Follow mitigation guidelines for preventing adversary use of [Valid Accounts](https://attack.mitre.org/techniques/T1078). Limit permissions so that users and user groups cannot create tokens. This setting should be defined for the local system account only. GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Create a token object. (Citation: Microsoft Create Token) Also define who can create a process level token to only the local and network service through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Replace a process level token. (Citation: Microsoft Replace Process Token)

Also limit opportunities for adversaries to increase privileges by limiting Privilege Escalation opportunities.


# Techniques


* [Access Token Manipulation](../techniques/Access-Token-Manipulation.md)

