
# Sudo

## Description

### MITRE Description

> The sudoers file, <code>/etc/sudoers</code>, describes which users can run which commands and from which terminals. This also describes which commands users can run as other users or groups. This provides the idea of least privilege such that users are running in their lowest possible permissions for most of the time and only elevate to other users or permissions as needed, typically by prompting for a password. However, the sudoers file can also specify when to not prompt users for passwords with a line like <code>user1 ALL=(ALL) NOPASSWD: ALL</code> (Citation: OSX.Dok Malware). 

Adversaries can take advantage of these configurations to execute commands as other users or spawn processes with higher privileges. You must have elevated privileges to edit this file though.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['root']
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: None
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
cat /etc/sudoers
vim /etc/sudoers
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
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'cat /etc/sudoers',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'vim /etc/sudoers',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': 'auditlogs (audit.rules)'},
 {'data_source': 'bash_history logs'},
 {'data_source': {'action': 'global',
                  'author': 'Florian Roth',
                  'date': '2019/10/15',
                  'description': 'Detects users trying to exploit sudo '
                                 'vulnerability reported in CVE-2019-14287',
                  'falsepositives': ['Unlikely'],
                  'id': 'f74107df-b6c6-4e80-bf00-4170b658162b',
                  'level': 'critical',
                  'logsource': {'product': 'linux'},
                  'modified': '2019/10/20',
                  'references': ['https://www.openwall.com/lists/oss-security/2019/10/14/1',
                                 'https://access.redhat.com/security/cve/cve-2019-14287',
                                 'https://twitter.com/matthieugarin/status/1183970598210412546'],
                  'status': 'experimental',
                  'tags': ['attack.privilege_escalation',
                           'attack.t1068',
                           'attack.t1169'],
                  'title': 'Sudo Privilege Escalation CVE-2019-14287'}},
 {'data_source': {'detection': {'condition': 'selection_keywords',
                                'selection_keywords': ['* -u#*']}}},
 {'data_source': {'detection': {'condition': 'selection_user',
                                'selection_user': {'USER': ['#-*',
                                                            '#*4294967295']}}}}]
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
           'level: medium'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="linux_audit" sudoers_change'},
 {'name': None,
  'product': 'Splunk',
  'query': 'Audit Rule : -w /etc/sudoers -p wa -k sudoers_change'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - SUDO': {'atomic_tests': [{'auto_generated_guid': '150c3a08-ee6e-48a6-aeaf-3659d24ceb4e',
                                                    'description': 'Common '
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
