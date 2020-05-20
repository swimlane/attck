
# menuPass

```
                                                        
  _____   ____   ____  __ _____________    ______ ______
 /     \_/ __ \ /    \|  |  \____ \__  \  /  ___//  ___/
|  Y Y  \  ___/|   |  \  |  /  |_> > __ \_\___ \ \___ \ 
|__|_|  /\___  >___|  /____/|   __(____  /____  >____  >
      \/     \/     \/      |__|       \/     \/     \/ 

```

## Description

### MITRE Description

> [menuPass](https://attack.mitre.org/groups/G0045) is a threat group that appears to originate from China and has been active since approximately 2009. The group has targeted healthcare, defense, aerospace, and government sectors, and has targeted Japanese victims since at least 2014. In 2016 and 2017, the group targeted managed IT service providers, manufacturing and mining companies, and a university. (Citation: Palo Alto menuPass Feb 2017) (Citation: Crowdstrike CrowdCast Oct 2013) (Citation: FireEye Poison Ivy) (Citation: PWC Cloud Hopper April 2017) (Citation: FireEye APT10 April 2017) (Citation: DOJ APT10 Dec 2018)

### External Description

> Data exfil over common TCP services (RDP, HTTPS)

## Aliases

```
menuPass
Stone Panda
APT10
Red Apollo
CVNX
HOGFISH
```

## Known Tools

```
Poison Ivy
EvilGrab
IEChecker
ChChes
PlugX
RedLeaves
Quasar
CobaltStrike
Trochilus
UPPERCUT (aka ANEL)
StoneNetLoader
```

## Operations

```
Dust Storm
Cloud Hopper
ChessMaster
```

## Targets

```
Healthcare; Pharma, Defense, Aerospace, Government, MSP, 
```

## Attribution Links

```
http://www.slideshare.net/CrowdStrike/crowd-casts-monthly-you-have-an-adversary-problem
http://researchcenter.paloaltonetworks.com/2017/02/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/
https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-poison-ivy.pdf
https://www.cylance.com/hubfs/2015_cylance_website/assets/operation-dust-storm/Op_Dust_Storm_Report.pdf
https://www.isightpartners.com/2016/02/threatscape-media-highlights-update-week-february-24th/
https://threatpost.com/poison-ivy-rat-spotted-in-three-new-attacks/102022/
https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html
http://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/
https://www.us-cert.gov/ncas/alerts/TA17-117A
https://www.accenture.com/t20180423T055005Z__w__/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf
https://www.lac.co.jp/lacwatch/people/20180521_001638.html
https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html
https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
https://blog.ensilo.com/uncovering-new-activity-by-apt10
```

## Country

```
china
```

## Comments

```
Profile slide 13 & 14
```

# Techniques


* [Windows Management Instrumentation](../techniques/Windows-Management-Instrumentation.md)

* [Credential Dumping](../techniques/Credential-Dumping.md)
    
* [Valid Accounts](../techniques/Valid-Accounts.md)
    
* [System Network Configuration Discovery](../techniques/System-Network-Configuration-Discovery.md)
    
* [Data from Network Shared Drive](../techniques/Data-from-Network-Shared-Drive.md)
    
* [Account Discovery](../techniques/Account-Discovery.md)
    
* [Obfuscated Files or Information](../techniques/Obfuscated-Files-or-Information.md)
    
* [Scripting](../techniques/Scripting.md)
    
* [System Network Connections Discovery](../techniques/System-Network-Connections-Discovery.md)
    
* [User Execution](../techniques/User-Execution.md)
    
* [Connection Proxy](../techniques/Connection-Proxy.md)
    
* [Scheduled Task](../techniques/Scheduled-Task.md)
    
* [Trusted Relationship](../techniques/Trusted-Relationship.md)
    
* [Command-Line Interface](../techniques/Command-Line-Interface.md)
    
* [DLL Search Order Hijacking](../techniques/DLL-Search-Order-Hijacking.md)
    
* [Process Hollowing](../techniques/Process-Hollowing.md)
    
* [Deobfuscate/Decode Files or Information](../techniques/Deobfuscate-Decode-Files-or-Information.md)
    
* [Spearphishing Attachment](../techniques/Spearphishing-Attachment.md)
    
* [Data Staged](../techniques/Data-Staged.md)
    
* [Remote Desktop Protocol](../techniques/Remote-Desktop-Protocol.md)
    
* [DLL Side-Loading](../techniques/DLL-Side-Loading.md)
    
* [Remote System Discovery](../techniques/Remote-System-Discovery.md)
    
* [File Deletion](../techniques/File-Deletion.md)
    
* [Remote File Copy](../techniques/Remote-File-Copy.md)
    
* [Remote Services](../techniques/Remote-Services.md)
    
* [PowerShell](../techniques/PowerShell.md)
    
* [Data Compressed](../techniques/Data-Compressed.md)
    
* [Network Service Scanning](../techniques/Network-Service-Scanning.md)
    
* [Masquerading](../techniques/Masquerading.md)
    
* [Data Encrypted](../techniques/Data-Encrypted.md)
    
* [Data from Local System](../techniques/Data-from-Local-System.md)
    
* [Input Capture](../techniques/Input-Capture.md)
    

# Malwares


* [PoisonIvy](../malwares/PoisonIvy.md)

* [SNUGRIDE](../malwares/SNUGRIDE.md)
    
* [UPPERCUT](../malwares/UPPERCUT.md)
    
* [PlugX](../malwares/PlugX.md)
    
* [ChChes](../malwares/ChChes.md)
    
* [RedLeaves](../malwares/RedLeaves.md)
    
* [EvilGrab](../malwares/EvilGrab.md)
    

# Tools


* [Net](../tools/Net.md)

* [PowerSploit](../tools/PowerSploit.md)
    
* [Mimikatz](../tools/Mimikatz.md)
    
* [certutil](../tools/certutil.md)
    
* [pwdump](../tools/pwdump.md)
    
* [Ping](../tools/Ping.md)
    
* [cmd](../tools/cmd.md)
    
* [Impacket](../tools/Impacket.md)
    
* [PsExec](../tools/PsExec.md)
    
* [QuasarRAT](../tools/QuasarRAT.md)
    
* [esentutl](../tools/esentutl.md)
    
