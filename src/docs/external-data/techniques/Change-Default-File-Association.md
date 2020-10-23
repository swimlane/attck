
# Change Default File Association

## Description

### MITRE Description

> Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access (Citation: Microsoft Change Default Programs) (Citation: Microsoft File Handlers) or by administrators using the built-in assoc utility. (Citation: Microsoft Assoc Oct 2017) Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.

System file associations are listed under <code>HKEY_CLASSES_ROOT\.[extension]</code>, for example <code>HKEY_CLASSES_ROOT\.txt</code>. The entries point to a handler for that extension located at <code>HKEY_CLASSES_ROOT\[handler]</code>. The various commands are then listed as subkeys underneath the shell key at <code>HKEY_CLASSES_ROOT\[handler]\shell\[action]\command</code>. For example: 
* <code>HKEY_CLASSES_ROOT\txtfile\shell\open\command</code>
* <code>HKEY_CLASSES_ROOT\txtfile\shell\print\command</code>
* <code>HKEY_CLASSES_ROOT\txtfile\shell\printto\command</code>

The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to continually execute arbitrary commands. (Citation: TrendMicro TROJ-FAKEAV OCT 2012)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM', 'User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1546/001

## Potential Commands

```
assoc #{extension_to_change}=txtfile
assoc .hta=#{target_extension_handler}
```

## Commands Dataset

```
[{'command': 'assoc #{extension_to_change}=txtfile\n',
  'name': None,
  'source': 'atomics/T1546.001/T1546.001.yaml'},
 {'command': 'assoc .hta=#{target_extension_handler}\n',
  'name': None,
  'source': 'atomics/T1546.001/T1546.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Event Triggered Execution: Change Default File Association': {'atomic_tests': [{'auto_generated_guid': '10a08978-2045-4d62-8c42-1957bbbea102',
                                                                                                          'description': 'Change '
                                                                                                                         'Default '
                                                                                                                         'File '
                                                                                                                         'Association '
                                                                                                                         'From '
                                                                                                                         'cmd.exe '
                                                                                                                         'of '
                                                                                                                         'hta '
                                                                                                                         'to '
                                                                                                                         'notepad.\n'
                                                                                                                         '\n'
                                                                                                                         'Upon '
                                                                                                                         'successful '
                                                                                                                         'execution, '
                                                                                                                         'cmd.exe '
                                                                                                                         'will '
                                                                                                                         'change '
                                                                                                                         'the '
                                                                                                                         'file '
                                                                                                                         'association '
                                                                                                                         'of '
                                                                                                                         '.hta '
                                                                                                                         'to '
                                                                                                                         'notepad.exe. \n',
                                                                                                          'executor': {'cleanup_command': 'assoc '
                                                                                                                                          '.hta=htafile '
                                                                                                                                          '>nul '
                                                                                                                                          '2>&1\n',
                                                                                                                       'command': 'assoc '
                                                                                                                                  '#{extension_to_change}=#{target_extension_handler}\n',
                                                                                                                       'name': 'command_prompt'},
                                                                                                          'input_arguments': {'extension_to_change': {'default': '.hta',
                                                                                                                                                      'description': 'File '
                                                                                                                                                                     'Extension '
                                                                                                                                                                     'To '
                                                                                                                                                                     'Hijack',
                                                                                                                                                      'type': 'String'},
                                                                                                                              'target_extension_handler': {'default': 'txtfile',
                                                                                                                                                           'description': 'txtfile '
                                                                                                                                                                          'maps '
                                                                                                                                                                          'to '
                                                                                                                                                                          'notepad.exe',
                                                                                                                                                           'type': 'Path'}},
                                                                                                          'name': 'Change '
                                                                                                                  'Default '
                                                                                                                  'File '
                                                                                                                  'Association',
                                                                                                          'supported_platforms': ['windows']}],
                                                                                        'attack_technique': 'T1546.001',
                                                                                        'display_name': 'Event '
                                                                                                        'Triggered '
                                                                                                        'Execution: '
                                                                                                        'Change '
                                                                                                        'Default '
                                                                                                        'File '
                                                                                                        'Association'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Change Default File Association Mitigation](../mitigations/Change-Default-File-Association-Mitigation.md)


# Actors


* [Kimsuky](../actors/Kimsuky.md)

