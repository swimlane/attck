
# Security Support Provider

## Description

### MITRE Description

> Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.

The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)

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
* Wiki: https://attack.mitre.org/techniques/T1547/005

## Potential Commands

```
# run these in sequence
$SecurityPackages = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name 'Security Packages' | Select-Object -ExpandProperty 'Security Packages'
$SecurityPackagesUpdated = $SecurityPackages
$SecurityPackagesUpdated += "not-a-ssp"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'Security Packages' -Value $SecurityPackagesUpdated

# revert (before reboot)
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'Security Packages' -Value $SecurityPackages
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
  'source': 'atomics/T1547.005/T1547.005.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Boot or Logon Autostart Execution: Security Support Provider': {'atomic_tests': [{'auto_generated_guid': 'afdfd7e3-8a0b-409f-85f7-886fdf249c9e',
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
                                                                                          'attack_technique': 'T1547.005',
                                                                                          'display_name': 'Boot '
                                                                                                          'or '
                                                                                                          'Logon '
                                                                                                          'Autostart '
                                                                                                          'Execution: '
                                                                                                          'Security '
                                                                                                          'Support '
                                                                                                          'Provider'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Privileged Process Integrity](../mitigations/Privileged-Process-Integrity.md)


# Actors

None
