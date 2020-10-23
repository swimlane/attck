
# Unsecured Credentials

## Description

### MITRE Description

> Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Bash History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)), or other specialized files/artifacts (e.g. [Private Keys](https://attack.mitre.org/techniques/T1552/004)).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure', 'Office 365', 'Azure AD', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1552

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: credentials to enumerate the registry\n'
           'description: win7 test\n'
           'references: http://www.rinige.com/index.php/archives/770/\n'
           'tags: T1552-002\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: sysmon\n'
           'detection:\n'
           '    selection:\n'
           '        EventID: 1 # Process Creation\n'
           "        Image: 'C: \\ * \\ reg.exe'\n"
           '        OriginalFileName: reg.exe\n'
           '        CommandLine: \'reg query "HKLM \\ SOFTWARE \\ Microsoft \\ '
           'Windows NT \\ Currentversion \\ Winlogon"\'\n'
           '        ParentCommandLine: "C: \\ * \\ cmd.exe"\n'
           '    condition: selection\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: the attacker to find the private key file under linux\n'
           'description: Ubuntu18.04\n'
           'references: '
           'https://github.com/12306Bro/Threathunting/blob/master/T1145-linux- '
           'private .md\n'
           'tags: T1552-004\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: linux\n'
           '    service: history\n'
           'detection:\n'
           '    keywords:\n'
           '       - sudo find / -name * .pgp\n'
           '       - sudo find / -name * .pem\n'
           '       - sudo find / -name * .ppk\n'
           '       - sudo find / -name * .p12\n'
           '       - sudo find / -name * .key\n'
           '    condition: keywords\n'
           'level: medium'}]
```

## Raw Dataset

```json

```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Audit](../mitigations/Audit.md)

* [Active Directory Configuration](../mitigations/Active-Directory-Configuration.md)
    
* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [User Training](../mitigations/User-Training.md)
    
* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    
* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    
* [Update Software](../mitigations/Update-Software.md)
    

# Actors

None
