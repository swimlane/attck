
# Access Token Manipulation

## Description

### MITRE Description

> Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.

An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001)) or used to spawn a new process (i.e. [Create Process with Token](https://attack.mitre.org/techniques/T1134/002)). An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.(Citation: Pentestlab Token Manipulation)

Any standard user can use the <code>runas</code> command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Windows User Account Control', 'System access controls', 'File system access controls', 'Heuristic Detection', 'Host forensic analysis']
* Effective Permissions: ['SYSTEM']
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1134

## Potential Commands

```
Token Stealing:
use incognito
list_tokens -u
impersonate_token DOMAIN\\User
or:
steal_token {pid}
Token Stealing:
steal_token pid#
powershell/credentials/tokens
powershell/management/runas
powershell/privesc/getsystem
```

## Commands Dataset

```
[{'command': 'Token Stealing:\nsteal_token pid#',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Token Stealing:\n'
             'use incognito\n'
             'list_tokens -u\n'
             'impersonate_token DOMAIN\\\\User\n'
             'or:\n'
             'steal_token {pid}',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'powershell/credentials/tokens',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/tokens',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/runas',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/runas',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/getsystem',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/getsystem',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Access Tokens']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Access Tokens']}]
```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Windows SID History permission to create a domain '
           'controller back door\n'
           'description: domain environment test\n'
           'references: https://adsecurity.org/?p=1772\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection:\n'
           '        EventID:\n'
           '         --4766 # attempt to add SID History to an account '
           'failed.\n'
           '         --4765 # SID history has been added to the account.\n'
           '    condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': '',
                                                  'Category': 'T1134',
                                                  'Cobalt Strike': 'Token '
                                                                   'Stealing:\n'
                                                                   'steal_token '
                                                                   'pid#',
                                                  'Description': 'This steals '
                                                                 'the access '
                                                                 'token from '
                                                                 'another '
                                                                 'process and '
                                                                 'uses it to '
                                                                 'gain access '
                                                                 'to other '
                                                                 'services or '
                                                                 'computers. '
                                                                 'In Cobalt '
                                                                 'Strike, this '
                                                                 'token is '
                                                                 'only used '
                                                                 'when '
                                                                 'accessing '
                                                                 'remote '
                                                                 'systems, but '
                                                                 'in '
                                                                 'Meterpreter, '
                                                                 'this token '
                                                                 'is used for '
                                                                 'everything '
                                                                 "until it's "
                                                                 'dropped via '
                                                                 'rev2self. '
                                                                 'You need to '
                                                                 'be in a high '
                                                                 'integrity '
                                                                 'process for '
                                                                 'this to '
                                                                 'work.',
                                                  'Metasploit': 'Token '
                                                                'Stealing:\n'
                                                                'use '
                                                                'incognito\n'
                                                                'list_tokens '
                                                                '-u\n'
                                                                'impersonate_token '
                                                                'DOMAIN\\\\User\n'
                                                                'or:\n'
                                                                'steal_token '
                                                                '{pid}'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1134',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/tokens":  '
                                                                                 '["T1134"],',
                                            'Empire Module': 'powershell/credentials/tokens',
                                            'Technique': 'Access Token '
                                                         'Manipulation'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1134',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/runas":  '
                                                                                 '["T1134"],',
                                            'Empire Module': 'powershell/management/runas',
                                            'Technique': 'Access Token '
                                                         'Manipulation'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1134',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/getsystem":  '
                                                                                 '["T1134"],',
                                            'Empire Module': 'powershell/privesc/getsystem',
                                            'Technique': 'Access Token '
                                                         'Manipulation'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Access Token Manipulation Mitigation](../mitigations/Access-Token-Manipulation-Mitigation.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [User Account Management](../mitigations/User-Account-Management.md)
    

# Actors


* [Blue Mockingbird](../actors/Blue-Mockingbird.md)

