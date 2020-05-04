
# Server Software Component

## Description

### MITRE Description

> Adversaries may abuse legitimate extensible development features of server applications to establish persistent access to systems. Enterprise server applications may include features that allow application developers to write and install software to extend the functionality of the main application. Adversaries may install malicious software components to maliciously extend and abuse server applications.

###Transport Agent
Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, filtering malicious attachments, journaling, or adding a corporate signature to the end of all outgoing emails.(Citation: Microsoft TransportAgent Jun 2016)(Citation: ESET LightNeuron May 2019) Transport agents can be written by application developers and then compiled to .NET assemblies that are subsequently registered with the Exchange server. Transport agents will be invoked during a specified stage of email processing and carry out developer defined tasks.

Adversaries may register a malicious transport agent to provide a persistence mechanism in Exchange Server that can be triggered by adversary-specified email events.(Citation: ESET LightNeuron May 2019) Though a malicious transport agent may be invoked for all emails passing through the Exchange transport pipeline, the agent can be configured to only carry out specific tasks in response to adversary defined criteria. For example, the transport agent may only carry out an action like copying in-transit attachments and saving them for later exfiltration if the recipient email address matches an entry on a list provided by the adversary.

###SQL Stored Procedures
SQL stored procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries. Stored procedures can be invoked via SQL statements to the database using the procedure name or via defined events (e.g. when a SQL server application is started/restarted). Adversaries may craft malicious stored procedures that can provide a persistence mechanism in SQL database servers.(Citation: NetSPI Startup Stored Procedures)(Citation: Kaspersky MSSQL Aug 2019) To execute operating system commands through SQL syntax the adversary may have to enable additional functionality, such as <code>xp_cmdshell</code> for MSSQL Server.(Citation: NetSPI Startup Stored Procedures)(Citation: Kaspersky MSSQL Aug 2019)(Citation: Microsoft xp_cmdshell 2017)

Microsoft SQL Server can enable common language runtime (CLR) integration. With CLR integration enabled, application developers can write stored procedures using any .NET framework language (e.g. VB .NET, C#, etc.).(Citation: Microsoft CLR Integration 2017) Adversaries may craft or modify CLR assemblies that are linked to stored procedures, these CLR assemblies can be made to execute arbitrary commands.(Citation: NetSPI SQL Server CLR)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM', 'root']
* Platforms: ['Windows', 'Linux']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1505

## Potential Commands

```
Install-TransportAgent -Name Security Interop Agent -TransportAgentFactory #{class_factory} -AssemblyPath #{dll_path}
Enable-TransportAgent Security Interop Agent
Get-TransportAgent | Format-List Name,Enabled

Install-TransportAgent -Name #{transport_agent_identity} -TransportAgentFactory #{class_factory} -AssemblyPath c:\program files\microsoft\Exchange Server\v15\bin\Microsoft.Exchange.Security.Interop.dll
Enable-TransportAgent #{transport_agent_identity}
Get-TransportAgent | Format-List Name,Enabled

Install-TransportAgent -Name #{transport_agent_identity} -TransportAgentFactory Microsoft.Exchange.Security.Interop.SecurityInteropAgentFactory -AssemblyPath #{dll_path}
Enable-TransportAgent #{transport_agent_identity}
Get-TransportAgent | Format-List Name,Enabled

```

## Commands Dataset

```
[{'command': 'Install-TransportAgent -Name Security Interop Agent '
             '-TransportAgentFactory #{class_factory} -AssemblyPath '
             '#{dll_path}\n'
             'Enable-TransportAgent Security Interop Agent\n'
             'Get-TransportAgent | Format-List Name,Enabled\n',
  'name': None,
  'source': 'atomics/T1505/T1505.yaml'},
 {'command': 'Install-TransportAgent -Name #{transport_agent_identity} '
             '-TransportAgentFactory #{class_factory} -AssemblyPath '
             'c:\\program files\\microsoft\\Exchange '
             'Server\\v15\\bin\\Microsoft.Exchange.Security.Interop.dll\n'
             'Enable-TransportAgent #{transport_agent_identity}\n'
             'Get-TransportAgent | Format-List Name,Enabled\n',
  'name': None,
  'source': 'atomics/T1505/T1505.yaml'},
 {'command': 'Install-TransportAgent -Name #{transport_agent_identity} '
             '-TransportAgentFactory '
             'Microsoft.Exchange.Security.Interop.SecurityInteropAgentFactory '
             '-AssemblyPath #{dll_path}\n'
             'Enable-TransportAgent #{transport_agent_identity}\n'
             'Get-TransportAgent | Format-List Name,Enabled\n',
  'name': None,
  'source': 'atomics/T1505/T1505.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Server Software Component': {'atomic_tests': [{'dependencies': [{'description': 'Microsoft '
                                                                                                          'Exchange '
                                                                                                          'SnapIn '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'installed\n',
                                                                                           'get_prereq_command': 'Add-PSSnapin '
                                                                                                                 'Microsoft.Exchange.Management.PowerShell.SnapIn\n',
                                                                                           'prereq_command': 'Get-TransportAgent '
                                                                                                             '-TransportService '
                                                                                                             'FrontEnd\n'}],
                                                                         'description': 'Install '
                                                                                        'a '
                                                                                        'Microsoft '
                                                                                        'Exchange '
                                                                                        'Transport '
                                                                                        'Agent '
                                                                                        'for '
                                                                                        'persistence. '
                                                                                        'This '
                                                                                        'requires '
                                                                                        'execution '
                                                                                        'from '
                                                                                        'an '
                                                                                        'Exchange '
                                                                                        'Client '
                                                                                        'Access '
                                                                                        'Server '
                                                                                        'and '
                                                                                        'the '
                                                                                        'creation '
                                                                                        'of '
                                                                                        'a '
                                                                                        'DLL '
                                                                                        'with '
                                                                                        'specific '
                                                                                        'exports. '
                                                                                        'Seen '
                                                                                        'in '
                                                                                        'use '
                                                                                        'by '
                                                                                        'Turla.\n'
                                                                                        'More '
                                                                                        'details- '
                                                                                        'https://docs.microsoft.com/en-us/exchange/transport-agents-exchange-2013-help\n',
                                                                         'executor': {'cleanup_command': 'Disable-TransportAgent '
                                                                                                         '#{transport_agent_identity}\n'
                                                                                                         'Uninstall-TransportAgent '
                                                                                                         '#{transport_agent_identity}\n'
                                                                                                         'Get-TransportAgent\n',
                                                                                      'command': 'Install-TransportAgent '
                                                                                                 '-Name '
                                                                                                 '#{transport_agent_identity} '
                                                                                                 '-TransportAgentFactory '
                                                                                                 '#{class_factory} '
                                                                                                 '-AssemblyPath '
                                                                                                 '#{dll_path}\n'
                                                                                                 'Enable-TransportAgent '
                                                                                                 '#{transport_agent_identity}\n'
                                                                                                 'Get-TransportAgent '
                                                                                                 '| '
                                                                                                 'Format-List '
                                                                                                 'Name,Enabled\n',
                                                                                      'elevation_required': True,
                                                                                      'name': 'powershell'},
                                                                         'input_arguments': {'class_factory': {'default': 'Microsoft.Exchange.Security.Interop.SecurityInteropAgentFactory',
                                                                                                               'description': 'Class '
                                                                                                                              'factory '
                                                                                                                              'of '
                                                                                                                              'transport '
                                                                                                                              'agent.',
                                                                                                               'type': 'string'},
                                                                                             'dll_path': {'default': 'c:\\program '
                                                                                                                     'files\\microsoft\\Exchange '
                                                                                                                     'Server\\v15\\bin\\Microsoft.Exchange.Security.Interop.dll',
                                                                                                          'description': 'Path '
                                                                                                                         'of '
                                                                                                                         'DLL '
                                                                                                                         'to '
                                                                                                                         'use '
                                                                                                                         'as '
                                                                                                                         'transport '
                                                                                                                         'agent.',
                                                                                                          'type': 'path'},
                                                                                             'transport_agent_identity': {'default': 'Security '
                                                                                                                                     'Interop '
                                                                                                                                     'Agent',
                                                                                                                          'description': 'Friendly '
                                                                                                                                         'name '
                                                                                                                                         'of '
                                                                                                                                         'transport '
                                                                                                                                         'agent '
                                                                                                                                         'once '
                                                                                                                                         'installed.',
                                                                                                                          'type': 'string'}},
                                                                         'name': 'Install '
                                                                                 'MS '
                                                                                 'Exchange '
                                                                                 'Transport '
                                                                                 'Agent '
                                                                                 'Persistence',
                                                                         'supported_platforms': ['windows']}],
                                                       'attack_technique': 'T1505',
                                                       'display_name': 'Server '
                                                                       'Software '
                                                                       'Component'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors

None
