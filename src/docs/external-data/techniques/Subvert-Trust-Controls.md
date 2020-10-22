
# Subvert Trust Controls

## Description

### MITRE Description

> Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.

Adversaries may attempt to subvert these trust mechanisms. The method adversaries use will depend on the specific mechanism they seek to subvert. Adversaries may conduct [File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222) or [Modify Registry](https://attack.mitre.org/techniques/T1112) in support of subverting these controls.(Citation: SpectorOps Subverting Trust Sept 2017) Adversaries may also create or steal code signing certificates to acquire trust on target systems.(Citation: Securelist Digital Certificates)(Citation: Symantec Digital Certificates) 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control', 'Anti-virus', 'Autoruns Analysis', 'Digital Certificate Validation', 'Process whitelisting', 'User Mode Signature Validation', 'Windows User Account Control']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows', 'macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1553

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    
* [Software Configuration](../mitigations/Software-Configuration.md)
    
* [Restrict Registry Permissions](../mitigations/Restrict-Registry-Permissions.md)
    

# Actors

None
