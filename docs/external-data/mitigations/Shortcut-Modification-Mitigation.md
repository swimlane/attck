
# Shortcut Modification Mitigation

## Description

### MITRE Description

> Limit permissions for who can create symbolic links in Windows to appropriate groups such as Administrators and necessary groups for virtualization. This can be done through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Create symbolic links. (Citation: UCF STIG Symbolic Links)

Identify and block unknown, potentially malicious software that may be executed through shortcut modification by using whitelisting (Citation: Beechey 2010) tools, like AppLocker, (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) or Software Restriction Policies (Citation: Corio 2008) where appropriate. (Citation: TechNet Applocker vs SRP)


# Techniques


* [Shortcut Modification](../techniques/Shortcut-Modification.md)

