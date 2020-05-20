
# Security Support Provider

## Description

### MITRE Description

> Windows Security Support Provider (SSP) DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.
 (Citation: Graeber 2014)

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
* Wiki: https://attack.mitre.org/techniques/T1101

## Potential Commands

```
# run these in sequence
$SecurityPackages = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name 'Security Packages' | Select-Object -ExpandProperty 'Security Packages'
$SecurityPackagesUpdated = $SecurityPackages
$SecurityPackagesUpdated += "not-a-ssp"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'Security Packages' -Value $SecurityPackagesUpdated

# revert (before reboot)
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'Security Packages' -Value $SecurityPackages

caspol.exe -s off
SYSTEM\CurrentControlSet\Control\Lsa\Security Packages|SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
SYSTEM\CurrentControlSet\Control\Lsa\Security Packages|SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
powershell/persistence/misc/get_ssps
powershell/persistence/misc/get_ssps
powershell/persistence/misc/install_ssp
powershell/persistence/misc/install_ssp
powershell/persistence/misc/memssp
powershell/persistence/misc/memssp
```

## Commands Dataset

```
[{'command': '# run these in sequence\n'
             '$SecurityPackages = Get-ItemProperty '
             "HKLM:\\System\\CurrentControlSet\\Control\\Lsa -Name 'Security "
             "Packages' | Select-Object -ExpandProperty 'Security Packages'\n"
             '$SecurityPackagesUpdated = $SecurityPackages\n'
             '$SecurityPackagesUpdated += "not-a-ssp"\n'
             'Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa '
             "-Name 'Security Packages' -Value $SecurityPackagesUpdated\n"
             '\n'
             '# revert (before reboot)\n'
             'Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa '
             "-Name 'Security Packages' -Value $SecurityPackages\n",
  'name': None,
  'source': 'atomics/T1101/T1101.yaml'},
 {'command': 'caspol.exe -s off',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security '
             'Packages|SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security '
             'Packages',
  'name': None,
  'source': 'SysmonHunter - Security Support Provider'},
 {'command': 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security '
             'Packages|SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security '
             'Packages',
  'name': None,
  'source': 'SysmonHunter - Security Support Provider'},
 {'command': 'powershell/persistence/misc/get_ssps',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/get_ssps',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/install_ssp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/install_ssp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/memssp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/memssp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Loaded DLLs']},
 {'data_source': ['DLL monitoring']},
 {'data_source': ['Sysmon ID 7', 'DLL monitoring']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Sysmon ID 7', 'Loaded DLLs']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Security Support Provider': {'atomic_tests': [{'auto_generated_guid': 'afdfd7e3-8a0b-409f-85f7-886fdf249c9e',
                                                                         'description': 'Add '
                                                                                        'a '
                                                                                        'value '
                                                                                        'to '
                                                                                        'a '
                                                                                        'Windows '
                                                                                        'registry '
                                                                                        'SSP '
                                                                                        'key, '
                                                                                        'simulating '
                                                                                        'an '
                                                                                        'adversarial '
                                                                                        'modification '
                                                                                        'of '
                                                                                        'those '
                                                                                        'keys.',
                                                                         'executor': {'command': '# '
                                                                                                 'run '
                                                                                                 'these '
                                                                                                 'in '
                                                                                                 'sequence\n'
                                                                                                 '$SecurityPackages '
                                                                                                 '= '
                                                                                                 'Get-ItemProperty '
                                                                                                 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa '
                                                                                                 '-Name '
                                                                                                 "'Security "
                                                                                                 "Packages' "
                                                                                                 '| '
                                                                                                 'Select-Object '
                                                                                                 '-ExpandProperty '
                                                                                                 "'Security "
                                                                                                 "Packages'\n"
                                                                                                 '$SecurityPackagesUpdated '
                                                                                                 '= '
                                                                                                 '$SecurityPackages\n'
                                                                                                 '$SecurityPackagesUpdated '
                                                                                                 '+= '
                                                                                                 '"#{fake_ssp_dll}"\n'
                                                                                                 'Set-ItemProperty '
                                                                                                 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa '
                                                                                                 '-Name '
                                                                                                 "'Security "
                                                                                                 "Packages' "
                                                                                                 '-Value '
                                                                                                 '$SecurityPackagesUpdated\n'
                                                                                                 '\n'
                                                                                                 '# '
                                                                                                 'revert '
                                                                                                 '(before '
                                                                                                 'reboot)\n'
                                                                                                 'Set-ItemProperty '
                                                                                                 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa '
                                                                                                 '-Name '
                                                                                                 "'Security "
                                                                                                 "Packages' "
                                                                                                 '-Value '
                                                                                                 '$SecurityPackages\n',
                                                                                      'elevation_required': True,
                                                                                      'name': 'powershell'},
                                                                         'input_arguments': {'fake_ssp_dll': {'default': 'not-a-ssp',
                                                                                                              'description': 'Value '
                                                                                                                             'added '
                                                                                                                             'to '
                                                                                                                             'registry '
                                                                                                                             'key. '
                                                                                                                             'Normally '
                                                                                                                             'refers '
                                                                                                                             'to '
                                                                                                                             'a '
                                                                                                                             'DLL '
                                                                                                                             'name '
                                                                                                                             'in '
                                                                                                                             'C:\\Windows\\System32.',
                                                                                                              'type': 'String'}},
                                                                         'name': 'Modify '
                                                                                 'SSP '
                                                                                 'configuration '
                                                                                 'in '
                                                                                 'registry',
                                                                         'supported_platforms': ['windows']}],
                                                       'attack_technique': 'T1101',
                                                       'display_name': 'Security '
                                                                       'Support '
                                                                       'Provider'}},
 {'Threat Hunting Tables': {'chain_id': '100212',
                            'commandline_string': '-s off',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': 'https://github.com/api0cradle/LOLBAS/blob/master/OSBinaries/Ieexec.md',
                            'loaded_dll': '',
                            'mitre_attack': 'T1101',
                            'mitre_caption': 'web_shell',
                            'os': 'windows',
                            'parent_process': 'caspol.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1101': {'description': None,
                           'level': 'medium',
                           'name': 'Security Support Provider',
                           'phase': 'Persistence',
                           'query': [{'reg': {'path': {'pattern': 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security '
                                                                  'Packages|SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security '
                                                                  'Packages'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security '
                                                                         'Packages|SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security '
                                                                         'Packages'}},
                                      'type': 'process'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1101',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/misc/get_ssps":  '
                                                                                 '["T1101"],',
                                            'Empire Module': 'powershell/persistence/misc/get_ssps',
                                            'Technique': 'Security Support '
                                                         'Provider'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1101',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/misc/install_ssp":  '
                                                                                 '["T1101"],',
                                            'Empire Module': 'powershell/persistence/misc/install_ssp',
                                            'Technique': 'Security Support '
                                                         'Provider'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1101',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/misc/memssp":  '
                                                                                 '["T1101"],',
                                            'Empire Module': 'powershell/persistence/misc/memssp',
                                            'Technique': 'Security Support '
                                                         'Provider'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors

None
