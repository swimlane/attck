
# Emond

## Description

### MITRE Description

> Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at <code>/sbin/emond</code> will load any rules from the <code>/etc/emond.d/rules/</code> directory and take action once an explicitly defined event takes place.

The rule files are in the plist format and define the name, event type, and action to take. Some examples of event types include system startup and user authentication. Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path <code>/private/var/db/emondClients</code>, specified in the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) configuration file at<code>/System/Library/LaunchDaemons/com.apple.emond.plist</code>.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019)

Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019) Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) service.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1546/014

## Potential Commands

```
sudo cp "PathToAtomicsFolder/T1546.014/src/T1546.014_emond.plist" /etc/emond.d/rules/T1546.014_emond.plist
sudo touch /private/var/db/emondClients/T1546.014
```

## Commands Dataset

```
[{'command': 'sudo cp '
             '"PathToAtomicsFolder/T1546.014/src/T1546.014_emond.plist" '
             '/etc/emond.d/rules/T1546.014_emond.plist\n'
             'sudo touch /private/var/db/emondClients/T1546.014\n',
  'name': None,
  'source': 'atomics/T1546.014/T1546.014.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Event Triggered Execution: Emond': {'atomic_tests': [{'auto_generated_guid': '23c9c127-322b-4c75-95ca-eff464906114',
                                                                                'description': 'Establish '
                                                                                               'persistence '
                                                                                               'via '
                                                                                               'a '
                                                                                               'rule '
                                                                                               'run '
                                                                                               'by '
                                                                                               "OSX's "
                                                                                               'emond '
                                                                                               '(Event '
                                                                                               'Monitor) '
                                                                                               'daemon '
                                                                                               'at '
                                                                                               'startup, '
                                                                                               'based '
                                                                                               'on '
                                                                                               'https://posts.specterops.io/leveraging-emond-on-macos-for-persistence-a040a2785124\n',
                                                                                'executor': {'cleanup_command': 'sudo '
                                                                                                                'rm '
                                                                                                                '/etc/emond.d/rules/T1546.014_emond.plist\n'
                                                                                                                'sudo '
                                                                                                                'rm '
                                                                                                                '/private/var/db/emondClients/T1546.014\n',
                                                                                             'command': 'sudo '
                                                                                                        'cp '
                                                                                                        '"#{plist}" '
                                                                                                        '/etc/emond.d/rules/T1546.014_emond.plist\n'
                                                                                                        'sudo '
                                                                                                        'touch '
                                                                                                        '/private/var/db/emondClients/T1546.014\n',
                                                                                             'elevation_required': True,
                                                                                             'name': 'sh'},
                                                                                'input_arguments': {'plist': {'default': 'PathToAtomicsFolder/T1546.014/src/T1546.014_emond.plist',
                                                                                                              'description': 'Path '
                                                                                                                             'to '
                                                                                                                             'attacker '
                                                                                                                             'emond '
                                                                                                                             'plist '
                                                                                                                             'file',
                                                                                                              'type': 'path'}},
                                                                                'name': 'Persistance '
                                                                                        'with '
                                                                                        'Event '
                                                                                        'Monitor '
                                                                                        '- '
                                                                                        'emond',
                                                                                'supported_platforms': ['macos']}],
                                                              'attack_technique': 'T1546.014',
                                                              'display_name': 'Event '
                                                                              'Triggered '
                                                                              'Execution: '
                                                                              'Emond'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)


# Actors

None
