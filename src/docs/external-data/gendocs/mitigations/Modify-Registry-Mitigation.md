
# Modify Registry Mitigation

## Description

### MITRE Description

> Misconfiguration of permissions in the Registry may lead to opportunities for an adversary to execute code, like through [Service Registry Permissions Weakness](https://attack.mitre.org/techniques/T1058). Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.

Identify and block unnecessary system utilities or potentially malicious software that may be used to modify the Registry by using whitelisting (Citation: Beechey 2010) tools like AppLocker (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) or Software Restriction Policies (Citation: Corio 2008) where appropriate. (Citation: TechNet Applocker vs SRP)


# Techniques


* [Modify Registry](../techniques/Modify-Registry.md)

