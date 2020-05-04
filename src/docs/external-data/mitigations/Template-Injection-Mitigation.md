
# Template Injection Mitigation

## Description

### MITRE Description

> Consider disabling Microsoft Office macros/active content to prevent the execution of malicious payloads in documents (Citation: Microsoft Disable Macros), though this setting may not mitigate the [Forced Authentication](https://attack.mitre.org/techniques/T1187) use for this technique.

Because this technique involves user interaction on the endpoint, it's difficult to fully mitigate. However, there are potential mitigations including training users to identify social engineering techniques and spearphishing emails. Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads. (Citation: Anomali Template Injection MAR 2018)


# Techniques


* [Template Injection](../techniques/Template-Injection.md)

