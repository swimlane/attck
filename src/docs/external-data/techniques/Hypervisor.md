
# Hypervisor

## Description

### MITRE Description

> A type-1 hypervisor is a software layer that sits between the guest operating systems and system's hardware. (Citation: Wikipedia Hypervisor) It presents a virtual running environment to an operating system. An example of a common hypervisor is Xen. (Citation: Wikipedia Xen) A type-1 hypervisor operates at a level below the operating system and could be designed with [Rootkit](https://attack.mitre.org/techniques/T1014) functionality to hide its existence from the guest operating system. (Citation: Myers 2007) A malicious hypervisor of this nature could be used to persist on systems through interruption.

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
* Wiki: https://attack.mitre.org/techniques/T1062

## Potential Commands

```
Get-WindowsFeature -Name Hyper-V -ComputerName test-vm
Install-WindowsFeature -Name Hyper-V -ComputerName test-vm -IncludeManagementTools
New-VM -Name #{vm_name} -MemoryStartupBytes 1GB -NewVHDPath #{file_location} -NewVHDSizeBytes 21474836480

Get-WindowsFeature -Name Hyper-V -ComputerName #{hostname}
Install-WindowsFeature -Name Hyper-V -ComputerName #{hostname} -IncludeManagementTools
New-VM -Name testvm -MemoryStartupBytes 1GB -NewVHDPath #{file_location} -NewVHDSizeBytes 21474836480

Get-WindowsFeature -Name Hyper-V -ComputerName #{hostname}
Install-WindowsFeature -Name Hyper-V -ComputerName #{hostname} -IncludeManagementTools
New-VM -Name #{vm_name} -MemoryStartupBytes 1GB -NewVHDPath C:\Temp\test.vhdx -NewVHDSizeBytes 21474836480

```

## Commands Dataset

```
[{'command': 'Get-WindowsFeature -Name Hyper-V -ComputerName test-vm\n'
             'Install-WindowsFeature -Name Hyper-V -ComputerName test-vm '
             '-IncludeManagementTools\n'
             'New-VM -Name #{vm_name} -MemoryStartupBytes 1GB -NewVHDPath '
             '#{file_location} -NewVHDSizeBytes 21474836480\n',
  'name': None,
  'source': 'atomics/T1062/T1062.yaml'},
 {'command': 'Get-WindowsFeature -Name Hyper-V -ComputerName #{hostname}\n'
             'Install-WindowsFeature -Name Hyper-V -ComputerName #{hostname} '
             '-IncludeManagementTools\n'
             'New-VM -Name testvm -MemoryStartupBytes 1GB -NewVHDPath '
             '#{file_location} -NewVHDSizeBytes 21474836480\n',
  'name': None,
  'source': 'atomics/T1062/T1062.yaml'},
 {'command': 'Get-WindowsFeature -Name Hyper-V -ComputerName #{hostname}\n'
             'Install-WindowsFeature -Name Hyper-V -ComputerName #{hostname} '
             '-IncludeManagementTools\n'
             'New-VM -Name #{vm_name} -MemoryStartupBytes 1GB -NewVHDPath '
             'C:\\Temp\\test.vhdx -NewVHDSizeBytes 21474836480\n',
  'name': None,
  'source': 'atomics/T1062/T1062.yaml'}]
```

## Potential Detections

```json
[{'data_source': ['System calls']}, {'data_source': ['System calls']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Hypervisor': {'atomic_tests': [{'auto_generated_guid': '90b4a49c-815a-4fbe-8863-da5acd5ac1a5',
                                                          'description': 'PowerShell '
                                                                         'command '
                                                                         'to '
                                                                         'check '
                                                                         'if '
                                                                         'Hyper-v '
                                                                         'is '
                                                                         'installed.\n'
                                                                         'Install '
                                                                         'Hyper-V '
                                                                         'feature.\n'
                                                                         'Create '
                                                                         'a '
                                                                         'New-VM\n'
                                                                         '\n'
                                                                         'Upon '
                                                                         'successful '
                                                                         'execution, '
                                                                         'powershell '
                                                                         'will '
                                                                         'check '
                                                                         'if '
                                                                         'Hyper-V '
                                                                         'is '
                                                                         'installed, '
                                                                         'if '
                                                                         'not, '
                                                                         'install '
                                                                         'it '
                                                                         'and '
                                                                         'create '
                                                                         'a '
                                                                         'base '
                                                                         'vm. '
                                                                         'Output '
                                                                         'will '
                                                                         'be '
                                                                         'via '
                                                                         'stdout.\n',
                                                          'executor': {'command': 'Get-WindowsFeature '
                                                                                  '-Name '
                                                                                  'Hyper-V '
                                                                                  '-ComputerName '
                                                                                  '#{hostname}\n'
                                                                                  'Install-WindowsFeature '
                                                                                  '-Name '
                                                                                  'Hyper-V '
                                                                                  '-ComputerName '
                                                                                  '#{hostname} '
                                                                                  '-IncludeManagementTools\n'
                                                                                  'New-VM '
                                                                                  '-Name '
                                                                                  '#{vm_name} '
                                                                                  '-MemoryStartupBytes '
                                                                                  '1GB '
                                                                                  '-NewVHDPath '
                                                                                  '#{file_location} '
                                                                                  '-NewVHDSizeBytes '
                                                                                  '21474836480\n',
                                                                       'name': 'powershell'},
                                                          'input_arguments': {'file_location': {'default': 'C:\\Temp\\test.vhdx',
                                                                                                'description': 'Location '
                                                                                                               'of '
                                                                                                               'new '
                                                                                                               'VHDX '
                                                                                                               'file',
                                                                                                'type': 'string'},
                                                                              'hostname': {'default': 'test-vm',
                                                                                           'description': 'Host '
                                                                                                          'to '
                                                                                                          'query '
                                                                                                          'to '
                                                                                                          'see '
                                                                                                          'if '
                                                                                                          'Hyper-V '
                                                                                                          'feature '
                                                                                                          'is '
                                                                                                          'installed.',
                                                                                           'type': 'string'},
                                                                              'vm_name': {'default': 'testvm',
                                                                                          'description': 'Create '
                                                                                                         'a '
                                                                                                         'new '
                                                                                                         'VM.',
                                                                                          'type': 'string'}},
                                                          'name': 'Installing '
                                                                  'Hyper-V '
                                                                  'Feature',
                                                          'supported_platforms': ['windows']}],
                                        'attack_technique': 'T1062',
                                        'display_name': 'Hypervisor'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors

None
