
# Dynamic Data Exchange

## Description

### MITRE Description

> Windows Dynamic Data Exchange (DDE) is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.

Object Linking and Embedding (OLE), or the ability to link data between documents, was originally implemented through DDE. Despite being superseded by COM, DDE may be enabled in Windows 10 and most of Microsoft Office 2016 via Registry keys. (Citation: BleepingComputer DDE Disabled in Word Dec 2017) (Citation: Microsoft ADV170021 Dec 2017) (Citation: Microsoft DDE Advisory Nov 2017)

Adversaries may use DDE to execute arbitrary commands. Microsoft Office documents can be poisoned with DDE commands (Citation: SensePost PS DDE May 2016) (Citation: Kettle CSV DDE Aug 2014), directly or through embedded files (Citation: Enigma Reviving DDE Jan 2018), and used to deliver execution via phishing campaigns or hosted Web content, avoiding the use of Visual Basic for Applications (VBA) macros. (Citation: SensePost MacroLess DDE Oct 2017) DDE could also be leveraged by an adversary operating on a compromised machine who does not have direct access to command line execution.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1173

## Potential Commands

```
start $PathToAtomicsFolder\T1173\bin\DDE_Document.docx

```

## Commands Dataset

```
[{'command': 'start $PathToAtomicsFolder\\T1173\\bin\\DDE_Document.docx\n',
  'name': None,
  'source': 'atomics/T1173/T1173.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Dynamic Data Exchange': {'atomic_tests': [{'description': 'Executes '
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
                                                                    {'description': 'When '
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
                                                                                             '$PathToAtomicsFolder\\T1173\\bin\\DDE_Document.docx\n',
                                                                                  'elevation_required': False,
                                                                                  'name': 'command_prompt'},
                                                                     'name': 'Execute '
                                                                             'PowerShell '
                                                                             'script '
                                                                             'via '
                                                                             'Word '
                                                                             'DDE',
                                                                     'supported_platforms': ['windows']}],
                                                   'attack_technique': 'T1173',
                                                   'display_name': 'Dynamic '
                                                                   'Data '
                                                                   'Exchange'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations

None

# Actors


* [Patchwork](../actors/Patchwork.md)

* [APT28](../actors/APT28.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [APT37](../actors/APT37.md)
    
* [Gallmaker](../actors/Gallmaker.md)
    
* [TA505](../actors/TA505.md)
    
