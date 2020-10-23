
# Visual Basic

## Description

### MITRE Description

> Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as [Component Object Model](https://attack.mitre.org/techniques/T1559/001) and the [Native API](https://attack.mitre.org/techniques/T1106) through the Windows API. Although tagged as legacy with no planned future evolutions, VB is integrated and supported in the .NET Framework and cross-platform .NET Core.(Citation: VB .NET Mar 2020)(Citation: VB Microsoft)

Derivative languages based on VB have also been created, such as Visual Basic for Applications (VBA) and VBScript. VBA is an event-driven programming language built into Office applications.(Citation: Microsoft VBA)  VBA enables documents to contain macros used to automate the execution of tasks and other functionality on the host. VBScript is a default scripting language on Windows hosts and can also be used in place of [JavaScript/JScript](https://attack.mitre.org/techniques/T1059/007) on HTML Application (HTA) webpages served to Internet Explorer (though most modern browsers do not come with VBScript support).(Citation: Microsoft VBScript)

Adversaries may use VB payloads to execute malicious commands. Common malicious usage includes automating execution of behaviors with VBScript or embedding VBA content into [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) payloads.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows', 'macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1059/005

## Potential Commands

```
cscript PathToAtomicsFolder\T1059.005\src\sys_info.vbs > $env:TEMP\out.txt
```

## Commands Dataset

```
[{'command': 'cscript PathToAtomicsFolder\\T1059.005\\src\\sys_info.vbs > '
             '$env:TEMP\\out.txt',
  'name': None,
  'source': 'atomics/T1059.005/T1059.005.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Command and Scripting Interpreter: Visual Basic': {'atomic_tests': [{'auto_generated_guid': '1620de42-160a-4fe5-bbaf-d3fef0181ce9',
                                                                                               'dependencies': [{'description': 'Sample '
                                                                                                                                'script '
                                                                                                                                'must '
                                                                                                                                'exist '
                                                                                                                                'on '
                                                                                                                                'disk '
                                                                                                                                'at '
                                                                                                                                'specified '
                                                                                                                                'location '
                                                                                                                                '(#{vbscript})',
                                                                                                                 'get_prereq_command': 'Invoke-WebRequest '
                                                                                                                                       '"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.005/src/sys_info.vbs" '
                                                                                                                                       '-OutFile '
                                                                                                                                       '"$env:TEMP\\sys_info.vbs"\n'
                                                                                                                                       'New-Item '
                                                                                                                                       '-ItemType '
                                                                                                                                       'Directory '
                                                                                                                                       '(Split-Path '
                                                                                                                                       '#{vbscript}) '
                                                                                                                                       '-Force '
                                                                                                                                       '| '
                                                                                                                                       'Out-Null\n'
                                                                                                                                       'Copy-Item '
                                                                                                                                       '$env:TEMP\\sys_info.vbs '
                                                                                                                                       '#{vbscript} '
                                                                                                                                       '-Force',
                                                                                                                 'prereq_command': 'if '
                                                                                                                                   '(Test-Path '
                                                                                                                                   '#{vbscript}) '
                                                                                                                                   '{exit '
                                                                                                                                   '0} '
                                                                                                                                   'else '
                                                                                                                                   '{exit '
                                                                                                                                   '1} '}],
                                                                                               'dependency_executor_name': 'powershell',
                                                                                               'description': 'Visual '
                                                                                                              'Basic '
                                                                                                              'execution '
                                                                                                              'test, '
                                                                                                              'execute '
                                                                                                              'vbscript '
                                                                                                              'via '
                                                                                                              'PowerShell.\n'
                                                                                                              '\n'
                                                                                                              'When '
                                                                                                              'successful, '
                                                                                                              'system '
                                                                                                              'information '
                                                                                                              'will '
                                                                                                              'be '
                                                                                                              'written '
                                                                                                              'to '
                                                                                                              '$env:TEMP\\T1059.005.out.txt.',
                                                                                               'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                               '$env:TEMP\\sys_info.vbs '
                                                                                                                               '-ErrorAction '
                                                                                                                               'Ignore\n'
                                                                                                                               'Remove-Item '
                                                                                                                               '$env:TEMP\\T1059.005.out.txt '
                                                                                                                               '-ErrorAction '
                                                                                                                               'Ignore',
                                                                                                            'command': 'cscript '
                                                                                                                       '#{vbscript} '
                                                                                                                       '> '
                                                                                                                       '$env:TEMP\\out.txt',
                                                                                                            'name': 'powershell'},
                                                                                               'input_arguments': {'vbscript': {'default': 'PathToAtomicsFolder\\T1059.005\\src\\sys_info.vbs',
                                                                                                                                'description': 'Path '
                                                                                                                                               'to '
                                                                                                                                               'sample '
                                                                                                                                               'script',
                                                                                                                                'type': 'String'}},
                                                                                               'name': 'Visual '
                                                                                                       'Basic '
                                                                                                       'script '
                                                                                                       'execution '
                                                                                                       'to '
                                                                                                       'gather '
                                                                                                       'local '
                                                                                                       'computer '
                                                                                                       'information',
                                                                                               'supported_platforms': ['windows']}],
                                                                             'attack_technique': 'T1059.005',
                                                                             'display_name': 'Command '
                                                                                             'and '
                                                                                             'Scripting '
                                                                                             'Interpreter: '
                                                                                             'Visual '
                                                                                             'Basic'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Antivirus/Antimalware](../mitigations/Antivirus-Antimalware.md)
    
* [Restrict Web-Based Content](../mitigations/Restrict-Web-Based-Content.md)
    

# Actors


* [Magic Hound](../actors/Magic-Hound.md)

* [Leviathan](../actors/Leviathan.md)
    
* [TA459](../actors/TA459.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [FIN4](../actors/FIN4.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [WIRTE](../actors/WIRTE.md)
    
* [Silence](../actors/Silence.md)
    
* [TA505](../actors/TA505.md)
    
* [Turla](../actors/Turla.md)
    
* [APT32](../actors/APT32.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [APT37](../actors/APT37.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [Rancor](../actors/Rancor.md)
    
* [APT-C-36](../actors/APT-C-36.md)
    
* [Inception](../actors/Inception.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Molerats](../actors/Molerats.md)
    
* [Sharpshooter](../actors/Sharpshooter.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
* [APT33](../actors/APT33.md)
    
