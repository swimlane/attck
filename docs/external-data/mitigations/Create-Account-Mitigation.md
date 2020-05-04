
# Create Account Mitigation

## Description

### MITRE Description

> Use and enforce multifactor authentication. Follow guidelines to prevent or limit adversary access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) that may be used to create privileged accounts within an environment.

Adversaries that create local accounts on systems may have limited access within a network if access levels are properly locked down. These accounts may only be needed for persistence on individual systems and their usefulness depends on the utility of the system they reside on.

Protect domain controllers by ensuring proper security configuration for critical servers. Configure access controls and firewalls to limit access to these systems. Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.


# Techniques


* [Create Account](../techniques/Create-Account.md)

