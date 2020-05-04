
# Third-party Software Mitigation

## Description

### MITRE Description

> Evaluate the security of third-party software that could be used in the enterprise environment. Ensure that access to management systems for third-party systems is limited, monitored, and secure. Have a strict approval policy for use of third-party systems.

Grant access to Third-party systems only to a limited number of authorized administrators. Ensure proper system and access isolation for critical network systems through use of firewalls, account privilege separation, group policy, and multi-factor authentication. Verify that account credentials that may be used to access third-party systems are unique and not used throughout the enterprise network. Ensure that any accounts used by third-party providers to access these systems are traceable to the third-party and are not used throughout the network or used by other third-party providers in the same environment. Ensure third-party systems are regularly patched by users or the provider to prevent potential remote access through [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068). 

Ensure there are regular reviews of accounts provisioned to these systems to verify continued business need, and ensure there is governance to trace de-provisioning of access that is no longer required.

Where the third-party system is used for deployment services, ensure that it can be configured to deploy only signed binaries, then ensure that the trusted signing certificates are not co-located with the third-party system and are instead located on a system that cannot be accessed remotely or to which remote access is tightly controlled.


# Techniques


* [Third-party Software](../techniques/Third-party-Software.md)

