
# SIP and Trust Provider Hijacking Mitigation

## Description

### MITRE Description

> Ensure proper permissions are set for Registry hives to prevent users from modifying keys related to SIP and trust provider components. Also ensure that these values contain their full path to prevent [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1038). (Citation: SpectorOps Subverting Trust Sept 2017)

Consider removing unnecessary and/or stale SIPs. (Citation: SpectorOps Subverting Trust Sept 2017)

Restrict storage and execution of SIP DLLs to protected directories, such as C:\Windows, rather than user directories.

Enable whitelisting solutions such as AppLocker and/or Device Guard to block the loading of malicious SIP DLLs. Components may still be able to be hijacked to suitable functions already present on disk if malicious modifications to Registry keys are not prevented.


# Techniques


* [SIP and Trust Provider Hijacking](../techniques/SIP-and-Trust-Provider-Hijacking.md)

