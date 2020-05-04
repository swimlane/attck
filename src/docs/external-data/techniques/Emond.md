
# Emond

## Description

### MITRE Description

> Adversaries may use Event Monitor Daemon (emond) to establish persistence by scheduling malicious commands to run on predictable event triggers. Emond is a [Launch Daemon](https://attack.mitre.org/techniques/T1160) that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at <code>/sbin/emond</code> will load any rules from the <code>/etc/emond.d/rules/</code> directory and take action once an explicitly defined event takes place. The rule files are in the plist format and define the name, event type, and action to take. Some examples of event types include system startup and user authentication. Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path <code>/private/var/db/emondClients</code>, specified in the [Launch Daemon](https://attack.mitre.org/techniques/T1160) configuration file at<code>/System/Library/LaunchDaemons/com.apple.emond.plist</code>.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019)

Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019) Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the [Launch Daemon](https://attack.mitre.org/techniques/T1160) service.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator']
* Platforms: ['macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1519

## Potential Commands

```
sudo cp "PathToAtomicsFolder/T1519/src/T1519_emond.plist" /etc/emond.d/rules/T1519_emond.plist
sudo touch /private/var/db/emondClients/T1519

```

## Commands Dataset

```
[{'command': 'sudo cp "PathToAtomicsFolder/T1519/src/T1519_emond.plist" '
             '/etc/emond.d/rules/T1519_emond.plist\n'
             'sudo touch /private/var/db/emondClients/T1519\n',
  'name': None,
  'source': 'atomics/T1519/T1519.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Emond': {'atomic_tests': [{'description': 'Establish '
                                                                    'persistence '
                                                                    'via a '
                                                                    'rule run '
                                                                    "by OSX's "
                                                                    'emond '
                                                                    '(Event '
                                                                    'Monitor) '
                                                                    'daemon at '
                                                                    'startup, '
                                                                    'based on '
                                                                    'https://posts.specterops.io/leveraging-emond-on-macos-for-persistence-a040a2785124\n',
                                                     'executor': {'cleanup_command': 'sudo '
                                                                                     'rm '
                                                                                     '/etc/emond.d/rules/T1519_emond.plist\n'
                                                                                     'sudo '
                                                                                     'rm '
                                                                                     '/private/var/db/emondClients/T1519\n',
                                                                  'command': 'sudo '
                                                                             'cp '
                                                                             '"#{plist}" '
                                                                             '/etc/emond.d/rules/T1519_emond.plist\n'
                                                                             'sudo '
                                                                             'touch '
                                                                             '/private/var/db/emondClients/T1519\n',
                                                                  'elevation_required': True,
                                                                  'name': 'sh'},
                                                     'input_arguments': {'plist': {'default': 'PathToAtomicsFolder/T1519/src/T1519_emond.plist',
                                                                                   'description': 'Path '
                                                                                                  'to '
                                                                                                  'attacker '
                                                                                                  'emond '
                                                                                                  'plist '
                                                                                                  'file',
                                                                                   'type': 'path'}},
                                                     'name': 'Persistance with '
                                                             'Event Monitor - '
                                                             'emond',
                                                     'supported_platforms': ['macos']}],
                                   'attack_technique': 'T1519',
                                   'display_name': 'Emond'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
