
# OilRig

```
       .__.__        .__        
  ____ |__|  |_______|__| ____  
 /  _ \|  |  |\_  __ \  |/ ___\ 
(  <_> )  |  |_|  | \/  / /_/  >
 \____/|__|____/__|  |__\___  / 
                       /_____/  

```

## Description

### MITRE Description

> [OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.

### External Description

> 

## Aliases

```
intentionally left blank
OilRig
IRN2
HELIX KITTEN
APT34
```

## Known Tools

```
Helminth
ISMDoor
Clayslide
QUADAGENT
OopsIE
ALMA Communicator
customized Mimikatz
Invoke-Obfuscation
POWBAT
POWRUNER (PS Backdoor)
BONDUPDATER
malicious RTF files CVE-2017-0199 and CVE-2017-11882
ELVENDOOR
PLink
PsExec
SSH Tunnels to Windows Servers
Webshells (TwoFace
DarkSeaGreenShell
LittleFace)
PowDesk
```

## Operations

```

```

## Targets

```

```

## Attribution Links

```
https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html
http://researchcenter.paloaltonetworks.com/2016/10/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/
http://researchcenter.paloaltonetworks.com/2016/05/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/
http://www.clearskysec.com/oilrig/
https://cert.gov.il/Updates/Alerts/SiteAssets/CERT-IL-ALERT-W-120.pdf
http://researchcenter.paloaltonetworks.com/2017/04/unit42-oilrig-actors-provide-glimpse-development-testing-efforts/
http://blog.morphisec.com/iranian-fileless-cyberattack-on-israel-word-vulnerability%20
https://www.forbes.com/sites/thomasbrewster/2017/02/15/oilrig-iran-hackers-cyberespionage-us-turkey-saudi-arabia/#56749aa2468a
https://researchcenter.paloaltonetworks.com/2017/07/unit42-twoface-webshell-persistent-access-point-lateral-movement/
https://researchcenter.paloaltonetworks.com/2017/07/unit42-oilrig-uses-ismdoor-variant-possibly-linked-greenbug-threat-group/
https://researchcenter.paloaltonetworks.com/2017/09/unit42-striking-oil-closer-look-adversary-infrastructure/
https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html
https://researchcenter.paloaltonetworks.com/2017/12/unit42-introducing-the-adversary-playbook-first-up-oilrig/
https://www.dragos.com/blog/20180517Chrysene.html
https://www.fireeye.com/content/dam/collateral/en/mtrends-2018.pdf
https://sec0wn.blogspot.com/2018/05/prb-backdoor-fully-loaded-powershell.html
https://www.ncsc.gov.uk/news/turla-group-exploits-iran-apt-to-expand-coverage-of-victims
https://securityintelligence.com/posts/new-destructive-wiper-zerocleare-targets-energy-sector-in-the-middle-east/
https://www.clearskysec.com/powdesk-apt34/
```

## Country

```
iran
```

## Comments

```
Uses the same C2 infrastructure as Chafer - which caused a major mixup of OilRig campaigns falsely attributed to Chafer. Also note that Turla used OilRigs implants
```

# Techniques


* [Process Discovery](../techniques/Process-Discovery.md)

* [Deobfuscate/Decode Files or Information](../techniques/Deobfuscate-Decode-Files-or-Information.md)
    
* [Custom Command and Control Protocol](../techniques/Custom-Command-and-Control-Protocol.md)
    
* [Automated Collection](../techniques/Automated-Collection.md)
    
* [File Deletion](../techniques/File-Deletion.md)
    
* [Redundant Access](../techniques/Redundant-Access.md)
    
* [Screen Capture](../techniques/Screen-Capture.md)
    
* [Remote Services](../techniques/Remote-Services.md)
    
* [Permission Groups Discovery](../techniques/Permission-Groups-Discovery.md)
    
* [Network Service Scanning](../techniques/Network-Service-Scanning.md)
    
* [Scripting](../techniques/Scripting.md)
    
* [External Remote Services](../techniques/External-Remote-Services.md)
    
* [Remote Desktop Protocol](../techniques/Remote-Desktop-Protocol.md)
    
* [Windows Management Instrumentation](../techniques/Windows-Management-Instrumentation.md)
    
* [Scheduled Task](../techniques/Scheduled-Task.md)
    
* [System Network Connections Discovery](../techniques/System-Network-Connections-Discovery.md)
    
* [System Service Discovery](../techniques/System-Service-Discovery.md)
    
* [System Network Configuration Discovery](../techniques/System-Network-Configuration-Discovery.md)
    
* [Query Registry](../techniques/Query-Registry.md)
    
* [Input Capture](../techniques/Input-Capture.md)
    
* [Command-Line Interface](../techniques/Command-Line-Interface.md)
    
* [System Information Discovery](../techniques/System-Information-Discovery.md)
    
* [Account Discovery](../techniques/Account-Discovery.md)
    
* [Brute Force](../techniques/Brute-Force.md)
    
* [Exfiltration Over Alternative Protocol](../techniques/Exfiltration-Over-Alternative-Protocol.md)
    
* [Spearphishing Attachment](../techniques/Spearphishing-Attachment.md)
    
* [User Execution](../techniques/User-Execution.md)
    
* [Obfuscated Files or Information](../techniques/Obfuscated-Files-or-Information.md)
    
* [PowerShell](../techniques/PowerShell.md)
    
* [Standard Application Layer Protocol](../techniques/Standard-Application-Layer-Protocol.md)
    
* [Web Shell](../techniques/Web-Shell.md)
    
* [Indicator Removal from Tools](../techniques/Indicator-Removal-from-Tools.md)
    
* [System Owner/User Discovery](../techniques/System-Owner-User-Discovery.md)
    
* [Credential Dumping](../techniques/Credential-Dumping.md)
    
* [Spearphishing Link](../techniques/Spearphishing-Link.md)
    
* [Fallback Channels](../techniques/Fallback-Channels.md)
    
* [Password Policy Discovery](../techniques/Password-Policy-Discovery.md)
    
* [Compiled HTML File](../techniques/Compiled-HTML-File.md)
    
* [Valid Accounts](../techniques/Valid-Accounts.md)
    
* [Remote File Copy](../techniques/Remote-File-Copy.md)
    
* [Standard Cryptographic Protocol](../techniques/Standard-Cryptographic-Protocol.md)
    
* [Credentials in Files](../techniques/Credentials-in-Files.md)
    
* [Commonly Used Port](../techniques/Commonly-Used-Port.md)
    
* [Spearphishing via Service](../techniques/Spearphishing-via-Service.md)
    

# Malwares


* [RGDoor](../malwares/RGDoor.md)

* [SEASHARPEE](../malwares/SEASHARPEE.md)
    
* [OopsIE](../malwares/OopsIE.md)
    
* [POWRUNER](../malwares/POWRUNER.md)
    
* [Helminth](../malwares/Helminth.md)
    
* [ISMInjector](../malwares/ISMInjector.md)
    
* [QUADAGENT](../malwares/QUADAGENT.md)
    
* [BONDUPDATER](../malwares/BONDUPDATER.md)
    

# Tools


* [Mimikatz](../tools/Mimikatz.md)

* [netstat](../tools/netstat.md)
    
* [Tasklist](../tools/Tasklist.md)
    
* [Reg](../tools/Reg.md)
    
* [PsExec](../tools/PsExec.md)
    
* [certutil](../tools/certutil.md)
    
* [LaZagne](../tools/LaZagne.md)
    
* [Systeminfo](../tools/Systeminfo.md)
    
* [ipconfig](../tools/ipconfig.md)
    
* [Net](../tools/Net.md)
    
* [FTP](../tools/FTP.md)
    
