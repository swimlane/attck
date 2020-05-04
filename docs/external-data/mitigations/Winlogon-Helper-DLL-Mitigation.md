
# Winlogon Helper DLL Mitigation

## Description

### MITRE Description

> Limit the privileges of user accounts so that only authorized administrators can perform Winlogon helper changes.

Identify and block potentially malicious software that may be executed through the Winlogon helper process by using whitelisting (Citation: Beechey 2010) tools like AppLocker (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) that are capable of auditing and/or blocking unknown DLLs.


# Techniques


* [Winlogon Helper DLL](../techniques/Winlogon-Helper-DLL.md)

