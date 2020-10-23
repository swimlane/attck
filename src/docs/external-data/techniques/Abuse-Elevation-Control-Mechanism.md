
# Abuse Elevation Control Mechanism

## Description

### MITRE Description

> Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1548

## Potential Commands

```
History
Oct 18 11:09:54 icbc sudo: test321: TTY = pts / 1; PWD = /; USER = # - 1; COMMAND = / usr / bin / id
Oct 18 11:11:59 icbc sudo: test321: TTY = pts / 1; PWD = /; USER = # 4294967295; COMMAND = / usr / bin / id
```

## Commands Dataset

```
[{'command': 'History\n'
             'Oct 18 11:09:54 icbc sudo: test321: TTY = pts / 1; PWD = /; USER '
             '= # - 1; COMMAND = / usr / bin / id\n'
             'Oct 18 11:11:59 icbc sudo: test321: TTY = pts / 1; PWD = /; USER '
             '= # 4294967295; COMMAND = / usr / bin / id',
  'name': 'History',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: CVE-2019-14287 sudo misconfigured - Privilege Escalation\n'
           'description:. Ubuntu19.04 x64 test results (when sudo when '
           'configured to allow users to run any user command, the user can '
           'press to become root by specifying the user ID-1 or 4,294,967,295 '
           'has sufficient privileges sudo Runas specification keyword ALL '
           'users can use it to run commands as root, even if the '
           'specification is expressly prohibited Runas root access, as long '
           'as the specification Runas\n'
           ' Conditions listed first in the keyword ALL can)\n'
           'references: https://sysdig.com/blog/detecting-cve-2019-14287/\n'
           'tags: T1548-003\n'
           'status: experimental\n'
           'author: Blue team\n'
           'logsource:\n'
           '    product: linux\n'
           'detection:\n'
           '    selection:\n'
           "        proc.name: 'sudo:'\n"
           '        proc.USER:\n'
           "            - '#-1'\n"
           "            - '# 4294967295'\n"
           '    condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json

```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Control](../mitigations/User-Account-Control.md)

* [Audit](../mitigations/Audit.md)
    
* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [Execution Prevention](../mitigations/Execution-Prevention.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    

# Actors

None
