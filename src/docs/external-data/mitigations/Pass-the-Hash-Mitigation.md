
# Pass the Hash Mitigation

## Description

### MITRE Description

> Monitor systems and domain logs for unusual credential logon activity. Prevent access to [Valid Accounts](https://attack.mitre.org/techniques/T1078). Apply patch KB2871997 to Windows 7 and higher systems to limit the default access of accounts in the local administrator group. 

Enable pass the hash mitigations to apply UAC restrictions to local accounts on network logon. The associated Registry key is located <code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy</code> Through GPO: Computer Configuration > [Policies] > Administrative Templates > SCM: Pass the Hash Mitigations: Apply UAC restrictions to local accounts on network logons. (Citation: GitHub IAD Secure Host Baseline UAC Filtering)

Limit credential overlap across systems to prevent the damage of credential compromise and reduce the adversary's ability to perform Lateral Movement between systems. Ensure that built-in and created local administrator accounts have complex, unique passwords. Do not allow a domain user to be in the local administrator group on multiple systems.


# Techniques


* [Pass the Hash](../techniques/Pass-the-Hash.md)

