
# Dynamic Data Exchange Mitigation

## Description

### MITRE Description

> Registry keys specific to Microsoft Office feature control security can be set to disable automatic DDE/OLE execution. (Citation: Microsoft DDE Advisory Nov 2017) (Citation: BleepingComputer DDE Disabled in Word Dec 2017) (Citation: GitHub Disable DDEAUTO Oct 2017) Microsoft also created, and enabled by default, Registry keys to completely disable DDE execution in Word and Excel. (Citation: Microsoft ADV170021 Dec 2017)

Ensure Protected View is enabled (Citation: Microsoft Protected View) and consider disabling embedded files in Office programs, such as OneNote, not enrolled in Protected View. (Citation: Enigma Reviving DDE Jan 2018) (Citation: GitHub Disable DDEAUTO Oct 2017)

On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent DDE attacks and spawning of child processes from Office programs. (Citation: Microsoft ASR Nov 2017) (Citation: Enigma Reviving DDE Jan 2018)


# Techniques


* [Dynamic Data Exchange](../techniques/Dynamic-Data-Exchange.md)

