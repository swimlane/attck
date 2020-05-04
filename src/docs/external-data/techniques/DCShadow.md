
# DCShadow

## Description

### MITRE Description

> DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a Domain Controller (DC). (Citation: DCShadow Blog) (Citation: BlueHat DCShadow Jan 2018) Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys.

Registering a rogue DC involves creating a new server and nTDSDSA objects in the Configuration partition of the AD schema, which requires Administrator privileges (either Domain or local to the DC) or the KRBTGT hash. (Citation: Adsecurity Mimikatz Guide)

This technique may bypass system logging and security monitors such as security information and event management (SIEM) products (since actions taken on a rogue DC may not be reported to these sensors). (Citation: DCShadow Blog) The technique may also be used to alter and delete replication and other associated metadata to obstruct forensic analysis. Adversaries may also utilize this technique to perform [SID-History Injection](https://attack.mitre.org/techniques/T1178) and/or manipulate AD objects (such as accounts, access control lists, schemas) to establish backdoors for Persistence. (Citation: DCShadow Blog) (Citation: BlueHat DCShadow Jan 2018)

## Additional Attributes

* Bypass: ['Log analysis']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1207

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
[{'Atomic Red Team Test - DCShadow': {'atomic_tests': [{'description': 'Utilize '
                                                                       'Mimikatz '
                                                                       'DCShadow '
                                                                       'method '
                                                                       'to '
                                                                       'simulate '
                                                                       'behavior '
                                                                       'of a '
                                                                       'Domain '
                                                                       'Controller\n'
                                                                       '\n'
                                                                       '[DCShadow](https://www.dcshadow.com/)\n'
                                                                       '[Additional '
                                                                       'Reference](http://www.labofapenetrationtester.com/2018/04/dcshadow.html)\n',
                                                        'executor': {'name': 'manual',
                                                                     'steps': '1. '
                                                                              'Start '
                                                                              'Mimikatz '
                                                                              'and '
                                                                              'use '
                                                                              '!processtoken '
                                                                              '(and '
                                                                              'not '
                                                                              'token::elevate '
                                                                              '- '
                                                                              'as '
                                                                              'it '
                                                                              'elevates '
                                                                              'a '
                                                                              'thread) '
                                                                              'to '
                                                                              'escalate '
                                                                              'to '
                                                                              'SYSTEM.\n'
                                                                              '2. '
                                                                              'Start '
                                                                              'another '
                                                                              'mimikatz '
                                                                              'with '
                                                                              'DA '
                                                                              'privileges. '
                                                                              'This '
                                                                              'is '
                                                                              'the '
                                                                              'instance '
                                                                              'which '
                                                                              'registers '
                                                                              'a '
                                                                              'DC '
                                                                              'and '
                                                                              'is '
                                                                              'used '
                                                                              'to '
                                                                              '"push" '
                                                                              'the '
                                                                              'attributes.\n'
                                                                              '3. '
                                                                              'lsadump::dcshadow '
                                                                              '/object:ops-user19$ '
                                                                              '/attribute:userAccountControl '
                                                                              '/value:532480\n'
                                                                              '4. '
                                                                              'lsadump::dcshadow '
                                                                              '/push\n'},
                                                        'name': 'DCShadow - '
                                                                'Mimikatz',
                                                        'supported_platforms': ['windows']}],
                                      'attack_technique': 'T1207',
                                      'display_name': 'DCShadow'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors

None
