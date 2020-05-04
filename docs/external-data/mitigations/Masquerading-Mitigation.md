
# Masquerading Mitigation

## Description

### MITRE Description

> When creating security rules, avoid exclusions based on file name or file path. Require signed binaries. Use file system access controls to protect folders such as C:\Windows\System32. Use tools that restrict program execution via whitelisting by attributes other than file name.

Identify potentially malicious software that may look like a legitimate program based on name and location, and audit and/or block it by using whitelisting (Citation: Beechey 2010) tools like AppLocker (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) or Software Restriction Policies (Citation: Corio 2008) where appropriate. (Citation: TechNet Applocker vs SRP)


# Techniques


* [Masquerading](../techniques/Masquerading.md)

