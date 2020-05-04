
# Sudo

## Description

### MITRE Description

> The sudoers file, <code>/etc/sudoers</code>, describes which users can run which commands and from which terminals. This also describes which commands users can run as other users or groups. This provides the idea of least privilege such that users are running in their lowest possible permissions for most of the time and only elevate to other users or permissions as needed, typically by prompting for a password. However, the sudoers file can also specify when to not prompt users for passwords with a line like <code>user1 ALL=(ALL) NOPASSWD: ALL</code> (Citation: OSX.Dok Malware). 

Adversaries can take advantage of these configurations to execute commands as other users or spawn processes with higher privileges. You must have elevated privileges to edit this file though.

## Additional Attributes

* Bypass: None
* Effective Permissions: ['root']
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1169

## Potential Commands

```
sudo -l
sudo su
cat /etc/sudoers
vim /etc/sudoers

History
Oct 18 11:09:54 icbc sudo: test321: TTY = pts / 1; PWD = /; USER = # - 1; COMMAND = / usr / bin / id
Oct 18 11:11:59 icbc sudo: test321: TTY = pts / 1; PWD = /; USER = # 4294967295; COMMAND = / usr / bin / id
```

## Commands Dataset

```
[{'command': 'sudo -l\nsudo su\ncat /etc/sudoers\nvim /etc/sudoers\n',
  'name': None,
  'source': 'atomics/T1169/T1169.yaml'},
 {'command': 'History\n'
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
           '\xa0Conditions listed first in the keyword ALL can)\n'
           'references: https://sysdig.com/blog/detecting-cve-2019-14287/\n'
           'tags: T1169\n'
           'status: experimental\n'
           'author: Blue team\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: linux\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0proc.name: 'sudo:'\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0proc.USER:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- '#-1'\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- '# 4294967295'\n"
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - SUDO': {'atomic_tests': [{'description': 'Common '
                                                                   'Sudo '
                                                                   'enumeration '
                                                                   'methods.\n',
                                                    'executor': {'command': 'sudo '
                                                                            '-l\n'
                                                                            'sudo '
                                                                            'su\n'
                                                                            'cat '
                                                                            '/etc/sudoers\n'
                                                                            'vim '
                                                                            '/etc/sudoers\n',
                                                                 'name': 'sh'},
                                                    'name': 'Sudo usage',
                                                    'supported_platforms': ['macos',
                                                                            'linux']}],
                                  'attack_technique': 'T1169',
                                  'display_name': 'SUDO'}}]
```

# Tactics


* [Privilege Escalation](../tactics/Privilege-Escalation.md)


# Mitigations

None

# Actors

None
