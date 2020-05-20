
# Virtualization/Sandbox Evasion

## Description

### MITRE Description

> Adversaries may check for the presence of a virtual machine environment (VME) or sandbox to avoid potential detection of tools and activities. If the adversary detects a VME, they may alter their malware to conceal the core functions of the implant or disengage from the victim. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information from learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors.

Adversaries may use several methods including [Security Software Discovery](https://attack.mitre.org/techniques/T1063) to accomplish [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) by searching for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) to help determine if it is an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandboxes. (Citation: Unit 42 Pirpi July 2015)

###Virtual Machine Environment Artifacts Discovery###

Adversaries may use utilities such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047), [PowerShell](https://attack.mitre.org/techniques/T1086), [Systeminfo](https://attack.mitre.org/software/S0096), and the [Query Registry](https://attack.mitre.org/techniques/T1012) to obtain system information and search for VME artifacts. Adversaries may search for VME artifacts in memory, processes, file system, and/or the Registry. Adversaries may use [Scripting](https://attack.mitre.org/techniques/T1064) to combine these checks into one script and then have the program exit if it determines the system to be a virtual environment. Also, in applications like VMWare, adversaries can use a special I/O port to send commands and receive output. Adversaries may also check the drive size. For example, this can be done using the Win32 DeviceIOControl function. 

Example VME Artifacts in the Registry(Citation: McAfee Virtual Jan 2017)

* <code>HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions</code>
* <code>HKLM\HARDWARE\Description\System\”SystemBiosVersion”;”VMWARE”</code>
* <code>HKLM\HARDWARE\ACPI\DSDT\BOX_</code>

Example VME files and DLLs on the system(Citation: McAfee Virtual Jan 2017)

* <code>WINDOWS\system32\drivers\vmmouse.sys</code> 
* <code>WINDOWS\system32\vboxhook.dll</code>
* <code>Windows\system32\vboxdisp.dll</code>

Common checks may enumerate services running that are unique to these applications, installed programs on the system, manufacturer/product fields for strings relating to virtual machine applications, and VME-specific hardware/processor instructions.(Citation: McAfee Virtual Jan 2017)

###User Activity Discovery###

Adversaries may search for user activity on the host (e.g., browser history, cache, bookmarks, number of files in the home directories, etc.) for reassurance of an authentic environment. They might detect this type of information via user interaction and digital signatures. They may have malware check the speed and frequency of mouse clicks to determine if it’s a sandboxed environment.(Citation: Sans Virtual Jan 2016) Other methods may rely on specific user interaction with the system before the malicious code is activated. Examples include waiting for a document to close before activating a macro (Citation: Unit 42 Sofacy Nov 2018) and waiting for a user to double click on an embedded image to activate (Citation: FireEye FIN7 April 2017).

###Virtual Hardware Fingerprinting Discovery###

Adversaries may check the fan and temperature of the system to gather evidence that can be indicative a virtual environment. An adversary may perform a CPU check using a WMI query <code>$q = “Select * from Win32_Fan” Get-WmiObject -Query $q</code>. If the results of the WMI query return more than zero elements, this might tell them that the machine is a physical one. (Citation: Unit 42 OilRig Sept 2018)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Host forensic analysis', 'Signature-based detection', 'Static File Analysis']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1497

## Potential Commands

```
{'windows': {'psh': {'command': 'get-wmiobject win32_computersystem | fl model\n'}}}
```

## Commands Dataset

```
[{'command': {'windows': {'psh': {'command': 'get-wmiobject '
                                             'win32_computersystem | fl '
                                             'model\n'}}},
  'name': 'Determine if the system is virtualized or physical',
  'source': 'data/abilities/discovery/5dc841fd-28ad-40e2-b10e-fb007fe09e81.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Determine if the system is virtualized or physical': {'description': 'Determine '
                                                                                          'if '
                                                                                          'the '
                                                                                          'system '
                                                                                          'is '
                                                                                          'virtualized '
                                                                                          'or '
                                                                                          'physical',
                                                                           'id': '5dc841fd-28ad-40e2-b10e-fb007fe09e81',
                                                                           'name': 'Virtual '
                                                                                   'or '
                                                                                   'Real',
                                                                           'platforms': {'windows': {'psh': {'command': 'get-wmiobject '
                                                                                                                        'win32_computersystem '
                                                                                                                        '| '
                                                                                                                        'fl '
                                                                                                                        'model\n'}}},
                                                                           'tactic': 'discovery',
                                                                           'technique': {'attack_id': 'T1497',
                                                                                         'name': 'Virtualization '
                                                                                                 'Sandbox '
                                                                                                 'Evasion'}}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Discovery](../tactics/Discovery.md)
    

# Mitigations

None

# Actors


* [FIN7](../actors/FIN7.md)

* [The White Company](../actors/The-White-Company.md)
    
