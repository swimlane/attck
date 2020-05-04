
# Accessibility Features Mitigation

## Description

### MITRE Description

> To use this technique remotely, an adversary must use it in conjunction with RDP. Ensure that Network Level Authentication is enabled to force the remote desktop session to authenticate before the session is created and the login screen displayed. It is enabled by default on Windows Vista and later. (Citation: TechNet RDP NLA)

If possible, use a Remote Desktop Gateway to manage connections and security configuration of RDP within a network. (Citation: TechNet RDP Gateway)

Identify and block potentially malicious software that may be executed by an adversary with this technique by using whitelisting (Citation: Beechey 2010) tools, like AppLocker, (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) or Software Restriction Policies (Citation: Corio 2008) where appropriate. (Citation: TechNet Applocker vs SRP)


# Techniques


* [Accessibility Features](../techniques/Accessibility-Features.md)

