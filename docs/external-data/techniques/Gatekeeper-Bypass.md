
# Gatekeeper Bypass

## Description

### MITRE Description

> In macOS and OS X, when applications or programs are downloaded from the internet, there is a special attribute set on the file called <code>com.apple.quarantine</code>. This attribute is read by Apple's Gatekeeper defense program at execution time and provides a prompt to the user to allow or deny execution. 

Apps loaded onto the system from USB flash drive, optical disk, external hard drive, or even from a drive shared over the local network won’t set this flag. Additionally, other utilities or events like drive-by downloads don’t necessarily set it either. This completely bypasses the built-in Gatekeeper check. (Citation: Methods of Mac Malware Persistence) The presence of the quarantine flag can be checked by the xattr command <code>xattr /path/to/MyApp.app</code> for <code>com.apple.quarantine</code>. Similarly, given sudo access or elevated permission, this attribute can be removed with xattr as well, <code>sudo xattr -r -d com.apple.quarantine /path/to/MyApp.app</code>. (Citation: Clearing quarantine attribute) (Citation: OceanLotus for OS X)
 
In typical operation, a file will be downloaded from the internet and given a quarantine flag before being saved to disk. When the user tries to open the file or application, macOS’s gatekeeper will step in and check for the presence of this flag. If it exists, then macOS will then prompt the user to confirmation that they want to run the program and will even provide the URL where the application came from. However, this is all based on the file being downloaded from a quarantine-savvy application. (Citation: Bypassing Gatekeeper)

## Additional Attributes

* Bypass: ['Application whitelisting', 'Anti-virus']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1144

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
  'source': 'atomics/T1144/T1144.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Gatekeeper Bypass': {'atomic_tests': [{'description': 'Gatekeeper '
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
                                               'attack_technique': 'T1144',
                                               'display_name': 'Gatekeeper '
                                                               'Bypass'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors

None
