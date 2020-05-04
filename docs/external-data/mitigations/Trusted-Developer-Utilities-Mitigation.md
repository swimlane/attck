
# Trusted Developer Utilities Mitigation

## Description

### MITRE Description

> MSBuild.exe, dnx.exe, rcsi.exe, WinDbg.exe, cdb.exe, and tracker.exe may not be necessary within a given environment and should be removed if not used.

Use application whitelisting configured to block execution of MSBuild.exe, dnx.exe, rcsi.exe, WinDbg.exe, and cdb.exe if they are not required for a given system or network to prevent potential misuse by adversaries. (Citation: Microsoft GitHub Device Guard CI Policies) (Citation: Exploit Monday Mitigate Device Guard Bypases) (Citation: GitHub mattifestation DeviceGuardBypass) (Citation: SubTee MSBuild)


# Techniques


* [Trusted Developer Utilities](../techniques/Trusted-Developer-Utilities.md)

