
# Clear Linux or Mac System Logs

## Description

### MITRE Description

> Adversaries may clear system logs to hide evidence of an intrusion. macOS and Linux both keep track of system or user-initiated actions via system logs. The majority of native system logging is stored under the <code>/var/log/</code> directory. Subfolders in this directory categorize logs by their related functions, such as:(Citation: Linux Logs)

* <code>/var/log/messages:</code>: General and system-related messages
* <code>/var/log/secure</code> or <code>/var/log/auth.log</code>: Authentication logs
* <code>/var/log/utmp</code> or <code>/var/log/wtmp</code>: Login records
* <code>/var/log/kern.log</code>: Kernel logs
* <code>/var/log/cron.log</code>: Crond logs
* <code>/var/log/maillog</code>: Mail server logs
* <code>/var/log/httpd/</code>: Web server access and error logs


## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1070/002

## Potential Commands

```
echo 0> /var/spool/mail/root
sudo rm -rf /private/var/log/system.log*
sudo rm -rf /private/var/audit/*
echo 0> /var/log/secure
```

## Commands Dataset

```
[{'command': 'sudo rm -rf /private/var/log/system.log*\n'
             'sudo rm -rf /private/var/audit/*\n',
  'name': None,
  'source': 'atomics/T1070.002/T1070.002.yaml'},
 {'command': 'echo 0> /var/spool/mail/root\n',
  'name': None,
  'source': 'atomics/T1070.002/T1070.002.yaml'},
 {'command': 'echo 0> /var/log/secure\n',
  'name': None,
  'source': 'atomics/T1070.002/T1070.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Indicator Removal on Host: Clear Linux or Mac System Logs': {'atomic_tests': [{'auto_generated_guid': '989cc1b1-3642-4260-a809-54f9dd559683',
                                                                                                         'description': 'Delete '
                                                                                                                        'system '
                                                                                                                        'and '
                                                                                                                        'audit '
                                                                                                                        'logs\n',
                                                                                                         'executor': {'command': 'sudo '
                                                                                                                                 'rm '
                                                                                                                                 '-rf '
                                                                                                                                 '/private/var/log/system.log*\n'
                                                                                                                                 'sudo '
                                                                                                                                 'rm '
                                                                                                                                 '-rf '
                                                                                                                                 '/private/var/audit/*\n',
                                                                                                                      'elevation_required': True,
                                                                                                                      'name': 'sh'},
                                                                                                         'name': 'rm '
                                                                                                                 '-rf',
                                                                                                         'supported_platforms': ['macos',
                                                                                                                                 'linux']},
                                                                                                        {'auto_generated_guid': '1602ff76-ed7f-4c94-b550-2f727b4782d4',
                                                                                                         'description': 'This '
                                                                                                                        'test '
                                                                                                                        'overwrites '
                                                                                                                        'the '
                                                                                                                        'Linux '
                                                                                                                        'mail '
                                                                                                                        'spool '
                                                                                                                        'of '
                                                                                                                        'a '
                                                                                                                        'specified '
                                                                                                                        'user. '
                                                                                                                        'This '
                                                                                                                        'technique '
                                                                                                                        'was '
                                                                                                                        'used '
                                                                                                                        'by '
                                                                                                                        'threat '
                                                                                                                        'actor '
                                                                                                                        'Rocke '
                                                                                                                        'during '
                                                                                                                        'the '
                                                                                                                        'exploitation '
                                                                                                                        'of '
                                                                                                                        'Linux '
                                                                                                                        'web '
                                                                                                                        'servers.\n',
                                                                                                         'executor': {'command': 'echo '
                                                                                                                                 '0> '
                                                                                                                                 '/var/spool/mail/#{username}\n',
                                                                                                                      'name': 'bash'},
                                                                                                         'input_arguments': {'username': {'default': 'root',
                                                                                                                                          'description': 'Username '
                                                                                                                                                         'of '
                                                                                                                                                         'mail '
                                                                                                                                                         'spool',
                                                                                                                                          'type': 'String'}},
                                                                                                         'name': 'Overwrite '
                                                                                                                 'Linux '
                                                                                                                 'Mail '
                                                                                                                 'Spool',
                                                                                                         'supported_platforms': ['linux']},
                                                                                                        {'auto_generated_guid': 'd304b2dc-90b4-4465-a650-16ddd503f7b5',
                                                                                                         'description': 'This '
                                                                                                                        'test '
                                                                                                                        'overwrites '
                                                                                                                        'the '
                                                                                                                        'specified '
                                                                                                                        'log. '
                                                                                                                        'This '
                                                                                                                        'technique '
                                                                                                                        'was '
                                                                                                                        'used '
                                                                                                                        'by '
                                                                                                                        'threat '
                                                                                                                        'actor '
                                                                                                                        'Rocke '
                                                                                                                        'during '
                                                                                                                        'the '
                                                                                                                        'exploitation '
                                                                                                                        'of '
                                                                                                                        'Linux '
                                                                                                                        'web '
                                                                                                                        'servers.\n',
                                                                                                         'executor': {'command': 'echo '
                                                                                                                                 '0> '
                                                                                                                                 '#{log_path}\n',
                                                                                                                      'name': 'bash'},
                                                                                                         'input_arguments': {'log_path': {'default': '/var/log/secure',
                                                                                                                                          'description': 'Path '
                                                                                                                                                         'of '
                                                                                                                                                         'specified '
                                                                                                                                                         'log',
                                                                                                                                          'type': 'Path'}},
                                                                                                         'name': 'Overwrite '
                                                                                                                 'Linux '
                                                                                                                 'Log',
                                                                                                         'supported_platforms': ['linux']}],
                                                                                       'attack_technique': 'T1070.002',
                                                                                       'display_name': 'Indicator '
                                                                                                       'Removal '
                                                                                                       'on '
                                                                                                       'Host: '
                                                                                                       'Clear '
                                                                                                       'Linux '
                                                                                                       'or '
                                                                                                       'Mac '
                                                                                                       'System '
                                                                                                       'Logs'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)

* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    
* [Remote Data Storage](../mitigations/Remote-Data-Storage.md)
    
* [Indicator Removal on Host Mitigation](../mitigations/Indicator-Removal-on-Host-Mitigation.md)
    

# Actors


* [Rocke](../actors/Rocke.md)

