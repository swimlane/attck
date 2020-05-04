
# Dylib Hijacking

## Description

### MITRE Description

> macOS and OS X use a common method to look for required dynamic libraries (dylib) to load into a program based on search paths. Adversaries can take advantage of ambiguous paths to plant dylibs to gain privilege escalation or persistence.

A common method is to see what dylibs an application uses, then plant a malicious version with the same name higher up in the search path. This typically results in the dylib being in the same folder as the application itself. (Citation: Writing Bad Malware for OSX) (Citation: Malware Persistence on OS X)

If the program is configured to run at a higher privilege level than the current user, then when the dylib is loaded into the application, the dylib will also run at that elevated level. This can be used by adversaries as a privilege escalation technique.

## Additional Attributes

* Bypass: None
* Effective Permissions: ['Administrator', 'root']
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1157

## Potential Commands

```
python/persistence/osx/CreateHijacker
python/persistence/osx/CreateHijacker
python/situational_awareness/host/osx/HijackScanner
python/situational_awareness/host/osx/HijackScanner
```

## Commands Dataset

```
[{'command': 'python/persistence/osx/CreateHijacker',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/osx/CreateHijacker',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/host/osx/HijackScanner',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/host/osx/HijackScanner',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1157',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/persistence/osx/CreateHijacker":  '
                                                                                 '["T1157"],',
                                            'Empire Module': 'python/persistence/osx/CreateHijacker',
                                            'Technique': 'Dylib Hijacking'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1157',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/host/osx/HijackScanner":  '
                                                                                 '["T1157"],',
                                            'Empire Module': 'python/situational_awareness/host/osx/HijackScanner',
                                            'Technique': 'Dylib Hijacking'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
