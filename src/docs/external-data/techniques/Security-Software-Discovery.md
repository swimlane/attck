
# Security Software Discovery

## Description

### MITRE Description

> Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as firewall rules and anti-virus. Adversaries may use the information from [Security Software Discovery](https://attack.mitre.org/techniques/T1518/001) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Example commands that can be used to obtain security software information are [netsh](https://attack.mitre.org/software/S0108), <code>reg query</code> with [Reg](https://attack.mitre.org/software/S0075), <code>dir</code> with [cmd](https://attack.mitre.org/software/S0106), and [Tasklist](https://attack.mitre.org/software/S0057), but other indicators of discovery behavior may be more specific to the type of software or security system the adversary is looking for. It is becoming more common to see macOS malware perform checks for LittleSnitch and KnockKnock software.

Adversaries may also utilize cloud APIs to discover the configurations of firewall rules within an environment.(Citation: Expel IO Evil in AWS)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure', 'Office 365', 'Azure AD', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1518/001

## Potential Commands

```
wmic.exe /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
ps -ef | grep Little\ Snitch | grep -v grep
ps aux | grep CbOsxSensorService
ps aux | grep falcond
fltmc.exe | findstr.exe 385201
get-process | ?{$_.Description -like "*virus*"}
get-process | ?{$_.Description -like "*carbonblack*"}
get-process | ?{$_.Description -like "*defender*"}
get-process | ?{$_.Description -like "*cylance*"}
netsh.exe advfirewall  show allprofiles
tasklist.exe
tasklist.exe | findstr /i virus
tasklist.exe | findstr /i cb
tasklist.exe | findstr /i defender
tasklist.exe | findstr /i cylance
```

## Commands Dataset

```
[{'command': 'netsh.exe advfirewall  show allprofiles\n'
             'tasklist.exe\n'
             'tasklist.exe | findstr /i virus\n'
             'tasklist.exe | findstr /i cb\n'
             'tasklist.exe | findstr /i defender\n'
             'tasklist.exe | findstr /i cylance\n',
  'name': None,
  'source': 'atomics/T1518.001/T1518.001.yaml'},
 {'command': 'get-process | ?{$_.Description -like "*virus*"}\n'
             'get-process | ?{$_.Description -like "*carbonblack*"}\n'
             'get-process | ?{$_.Description -like "*defender*"}\n'
             'get-process | ?{$_.Description -like "*cylance*"}\n',
  'name': None,
  'source': 'atomics/T1518.001/T1518.001.yaml'},
 {'command': 'ps -ef | grep Little\\ Snitch | grep -v grep\n'
             'ps aux | grep CbOsxSensorService\n'
             'ps aux | grep falcond\n',
  'name': None,
  'source': 'atomics/T1518.001/T1518.001.yaml'},
 {'command': 'fltmc.exe | findstr.exe 385201\n',
  'name': None,
  'source': 'atomics/T1518.001/T1518.001.yaml'},
 {'command': 'wmic.exe /Namespace:\\\\root\\SecurityCenter2 Path '
             'AntiVirusProduct Get displayName /Format:List',
  'name': None,
  'source': 'atomics/T1518.001/T1518.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Software Discovery: Security Software Discovery': {'atomic_tests': [{'auto_generated_guid': 'f92a380f-ced9-491f-b338-95a991418ce2',
                                                                                               'description': 'Methods '
                                                                                                              'to '
                                                                                                              'identify '
                                                                                                              'Security '
                                                                                                              'Software '
                                                                                                              'on '
                                                                                                              'an '
                                                                                                              'endpoint\n'
                                                                                                              '\n'
                                                                                                              'when '
                                                                                                              'sucessfully '
                                                                                                              'executed, '
                                                                                                              'the '
                                                                                                              'test '
                                                                                                              'is '
                                                                                                              'going '
                                                                                                              'to '
                                                                                                              'display '
                                                                                                              'running '
                                                                                                              'processes, '
                                                                                                              'firewall '
                                                                                                              'configuration '
                                                                                                              'on '
                                                                                                              'network '
                                                                                                              'profiles\n'
                                                                                                              'and '
                                                                                                              'specific '
                                                                                                              'security '
                                                                                                              'software.\n',
                                                                                               'executor': {'command': 'netsh.exe '
                                                                                                                       'advfirewall  '
                                                                                                                       'show '
                                                                                                                       'allprofiles\n'
                                                                                                                       'tasklist.exe\n'
                                                                                                                       'tasklist.exe '
                                                                                                                       '| '
                                                                                                                       'findstr '
                                                                                                                       '/i '
                                                                                                                       'virus\n'
                                                                                                                       'tasklist.exe '
                                                                                                                       '| '
                                                                                                                       'findstr '
                                                                                                                       '/i '
                                                                                                                       'cb\n'
                                                                                                                       'tasklist.exe '
                                                                                                                       '| '
                                                                                                                       'findstr '
                                                                                                                       '/i '
                                                                                                                       'defender\n'
                                                                                                                       'tasklist.exe '
                                                                                                                       '| '
                                                                                                                       'findstr '
                                                                                                                       '/i '
                                                                                                                       'cylance\n',
                                                                                                            'name': 'command_prompt'},
                                                                                               'name': 'Security '
                                                                                                       'Software '
                                                                                                       'Discovery',
                                                                                               'supported_platforms': ['windows']},
                                                                                              {'auto_generated_guid': '7f566051-f033-49fb-89de-b6bacab730f0',
                                                                                               'description': 'Methods '
                                                                                                              'to '
                                                                                                              'identify '
                                                                                                              'Security '
                                                                                                              'Software '
                                                                                                              'on '
                                                                                                              'an '
                                                                                                              'endpoint\n'
                                                                                                              '\n'
                                                                                                              'when '
                                                                                                              'sucessfully '
                                                                                                              'executed, '
                                                                                                              'powershell '
                                                                                                              'is '
                                                                                                              'going '
                                                                                                              'to '
                                                                                                              'processes '
                                                                                                              'related '
                                                                                                              'AV '
                                                                                                              'products '
                                                                                                              'if '
                                                                                                              'they '
                                                                                                              'are '
                                                                                                              'running.\n',
                                                                                               'executor': {'command': 'get-process '
                                                                                                                       '| '
                                                                                                                       '?{$_.Description '
                                                                                                                       '-like '
                                                                                                                       '"*virus*"}\n'
                                                                                                                       'get-process '
                                                                                                                       '| '
                                                                                                                       '?{$_.Description '
                                                                                                                       '-like '
                                                                                                                       '"*carbonblack*"}\n'
                                                                                                                       'get-process '
                                                                                                                       '| '
                                                                                                                       '?{$_.Description '
                                                                                                                       '-like '
                                                                                                                       '"*defender*"}\n'
                                                                                                                       'get-process '
                                                                                                                       '| '
                                                                                                                       '?{$_.Description '
                                                                                                                       '-like '
                                                                                                                       '"*cylance*"}\n',
                                                                                                            'name': 'powershell'},
                                                                                               'name': 'Security '
                                                                                                       'Software '
                                                                                                       'Discovery '
                                                                                                       '- '
                                                                                                       'powershell',
                                                                                               'supported_platforms': ['windows']},
                                                                                              {'auto_generated_guid': 'ba62ce11-e820-485f-9c17-6f3c857cd840',
                                                                                               'description': 'Methods '
                                                                                                              'to '
                                                                                                              'identify '
                                                                                                              'Security '
                                                                                                              'Software '
                                                                                                              'on '
                                                                                                              'an '
                                                                                                              'endpoint\n'
                                                                                                              'when '
                                                                                                              'sucessfully '
                                                                                                              'executed, '
                                                                                                              'command '
                                                                                                              'shell  '
                                                                                                              'is '
                                                                                                              'going '
                                                                                                              'to '
                                                                                                              'display '
                                                                                                              'AV '
                                                                                                              'software '
                                                                                                              'it '
                                                                                                              'is '
                                                                                                              'running( '
                                                                                                              'Little '
                                                                                                              'snitch '
                                                                                                              'or '
                                                                                                              'carbon '
                                                                                                              'black '
                                                                                                              ').\n',
                                                                                               'executor': {'command': 'ps '
                                                                                                                       '-ef '
                                                                                                                       '| '
                                                                                                                       'grep '
                                                                                                                       'Little\\ '
                                                                                                                       'Snitch '
                                                                                                                       '| '
                                                                                                                       'grep '
                                                                                                                       '-v '
                                                                                                                       'grep\n'
                                                                                                                       'ps '
                                                                                                                       'aux '
                                                                                                                       '| '
                                                                                                                       'grep '
                                                                                                                       'CbOsxSensorService\n'
                                                                                                                       'ps '
                                                                                                                       'aux '
                                                                                                                       '| '
                                                                                                                       'grep '
                                                                                                                       'falcond\n',
                                                                                                            'name': 'sh'},
                                                                                               'name': 'Security '
                                                                                                       'Software '
                                                                                                       'Discovery '
                                                                                                       '- '
                                                                                                       'ps',
                                                                                               'supported_platforms': ['linux',
                                                                                                                       'macos']},
                                                                                              {'auto_generated_guid': 'fe613cf3-8009-4446-9a0f-bc78a15b66c9',
                                                                                               'description': 'Discovery '
                                                                                                              'of '
                                                                                                              'an '
                                                                                                              'installed '
                                                                                                              'Sysinternals '
                                                                                                              'Sysmon '
                                                                                                              'service '
                                                                                                              'using '
                                                                                                              'driver '
                                                                                                              'altitude '
                                                                                                              '(even '
                                                                                                              'if '
                                                                                                              'the '
                                                                                                              'name '
                                                                                                              'is '
                                                                                                              'changed).\n'
                                                                                                              '\n'
                                                                                                              'when '
                                                                                                              'sucessfully '
                                                                                                              'executed, '
                                                                                                              'the '
                                                                                                              'test '
                                                                                                              'is '
                                                                                                              'going '
                                                                                                              'to '
                                                                                                              'display '
                                                                                                              'sysmon '
                                                                                                              'driver '
                                                                                                              'instance '
                                                                                                              'if '
                                                                                                              'it '
                                                                                                              'is '
                                                                                                              'installed.\n',
                                                                                               'executor': {'command': 'fltmc.exe '
                                                                                                                       '| '
                                                                                                                       'findstr.exe '
                                                                                                                       '385201\n',
                                                                                                            'elevation_required': True,
                                                                                                            'name': 'command_prompt'},
                                                                                               'name': 'Security '
                                                                                                       'Software '
                                                                                                       'Discovery '
                                                                                                       '- '
                                                                                                       'Sysmon '
                                                                                                       'Service',
                                                                                               'supported_platforms': ['windows']},
                                                                                              {'auto_generated_guid': '1553252f-14ea-4d3b-8a08-d7a4211aa945',
                                                                                               'description': 'Discovery '
                                                                                                              'of '
                                                                                                              'installed '
                                                                                                              'antivirus '
                                                                                                              'products '
                                                                                                              'via '
                                                                                                              'a '
                                                                                                              'WMI '
                                                                                                              'query.\n'
                                                                                                              '\n'
                                                                                                              'when '
                                                                                                              'sucessfully '
                                                                                                              'executed, '
                                                                                                              'the '
                                                                                                              'test '
                                                                                                              'is '
                                                                                                              'going '
                                                                                                              'to '
                                                                                                              'display '
                                                                                                              'installed '
                                                                                                              'AV '
                                                                                                              'software.\n',
                                                                                               'executor': {'command': 'wmic.exe '
                                                                                                                       '/Namespace:\\\\root\\SecurityCenter2 '
                                                                                                                       'Path '
                                                                                                                       'AntiVirusProduct '
                                                                                                                       'Get '
                                                                                                                       'displayName '
                                                                                                                       '/Format:List',
                                                                                                            'elevation_required': True,
                                                                                                            'name': 'command_prompt'},
                                                                                               'name': 'Security '
                                                                                                       'Software '
                                                                                                       'Discovery '
                                                                                                       '- '
                                                                                                       'AV '
                                                                                                       'Discovery '
                                                                                                       'via '
                                                                                                       'WMI',
                                                                                               'supported_platforms': ['windows']}],
                                                                             'attack_technique': 'T1518.001',
                                                                             'display_name': 'Software '
                                                                                             'Discovery: '
                                                                                             'Security '
                                                                                             'Software '
                                                                                             'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [Patchwork](../actors/Patchwork.md)

* [MuddyWater](../actors/MuddyWater.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [Naikon](../actors/Naikon.md)
    
* [The White Company](../actors/The-White-Company.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Rocke](../actors/Rocke.md)
    
* [Turla](../actors/Turla.md)
    
