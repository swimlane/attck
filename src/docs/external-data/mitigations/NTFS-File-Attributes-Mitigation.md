
# NTFS File Attributes Mitigation

## Description

### MITRE Description

> It may be difficult or inadvisable to block access to EA and ADSs. (Citation: Microsoft ADS Mar 2014) (Citation: Symantec ADS May 2009) Efforts should be focused on preventing potentially malicious software from running. Identify and block potentially malicious software that may contain functionality to hide information in EA and ADSs by using whitelisting (Citation: Beechey 2010) tools like AppLocker (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) or Software Restriction Policies (Citation: Corio 2008) where appropriate. (Citation: TechNet Applocker vs SRP)

Consider adjusting read and write permissions for NTFS EA, though this should be tested to ensure routine OS operations are not impeded. (Citation: InsiderThreat NTFS EA Oct 2017)


# Techniques


* [NTFS File Attributes](../techniques/NTFS-File-Attributes.md)

