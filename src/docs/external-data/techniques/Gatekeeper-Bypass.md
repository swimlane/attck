
# Gatekeeper Bypass

## Description

### MITRE Description

> Adversaries may modify file attributes that signify programs are from untrusted sources to subvert Gatekeeper controls. In macOS and OS X, when applications or programs are downloaded from the internet, there is a special attribute set on the file called <code>com.apple.quarantine</code>. This attribute is read by Apple's Gatekeeper defense program at execution time and provides a prompt to the user to allow or deny execution. 

Apps loaded onto the system from USB flash drive, optical disk, external hard drive, or even from a drive shared over the local network won’t set this flag. Additionally, it is possible to avoid setting this flag using [Drive-by Compromise](https://attack.mitre.org/techniques/T1189). This completely bypasses the built-in Gatekeeper check. (Citation: Methods of Mac Malware Persistence) The presence of the quarantine flag can be checked by the xattr command <code>xattr /path/to/MyApp.app</code> for <code>com.apple.quarantine</code>. Similarly, given sudo access or elevated permission, this attribute can be removed with xattr as well, <code>sudo xattr -r -d com.apple.quarantine /path/to/MyApp.app</code>. (Citation: Clearing quarantine attribute) (Citation: OceanLotus for OS X)
 
In typical operation, a file will be downloaded from the internet and given a quarantine flag before being saved to disk. When the user tries to open the file or application, macOS’s gatekeeper will step in and check for the presence of this flag. If it exists, then macOS will then prompt the user to confirmation that they want to run the program and will even provide the URL where the application came from. However, this is all based on the file being downloaded from a quarantine-savvy application. (Citation: Bypassing Gatekeeper)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1553/001

## Potential Commands

```
sudo xattr -r -d com.apple.quarantine myapp.app
sudo spctl --master-disable
```

## Commands Dataset

```
[{'command': 'sudo xattr -r -d com.apple.quarantine myapp.app\n'
             'sudo spctl --master-disable\n',
  'name': None,
  'source': 'atomics/T1553.001/T1553.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Subvert Trust Controls: Gatekeeper Bypass': {'atomic_tests': [{'auto_generated_guid': 'fb3d46c6-9480-4803-8d7d-ce676e1f1a9b',
                                                                                         'description': 'Gatekeeper '
                                                                                                        'Bypass '
                                                                                                        'via '
                                                                                                        'command '
                                                                                                        'line\n',
                                                                                         'executor': {'command': 'sudo '
                                                                                                                 'xattr '
                                                                                                                 '-r '
                                                                                                                 '-d '
                                                                                                                 'com.apple.quarantine '
                                                                                                                 '#{app_path}\n'
                                                                                                                 'sudo '
                                                                                                                 'spctl '
                                                                                                                 '--master-disable\n',
                                                                                                      'elevation_required': True,
                                                                                                      'name': 'sh'},
                                                                                         'input_arguments': {'app_path': {'default': 'myapp.app',
                                                                                                                          'description': 'Path '
                                                                                                                                         'to '
                                                                                                                                         'app '
                                                                                                                                         'to '
                                                                                                                                         'be '
                                                                                                                                         'used',
                                                                                                                          'type': 'Path'}},
                                                                                         'name': 'Gatekeeper '
                                                                                                 'Bypass',
                                                                                         'supported_platforms': ['macos']}],
                                                                       'attack_technique': 'T1553.001',
                                                                       'display_name': 'Subvert '
                                                                                       'Trust '
                                                                                       'Controls: '
                                                                                       'Gatekeeper '
                                                                                       'Bypass'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)


# Actors

None
