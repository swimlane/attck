
# LSASS Driver Mitigation

## Description

### MITRE Description

> On Windows 8.1 and Server 2012 R2, enable LSA Protection by setting the Registry key <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL</code> to <code>dword:00000001</code>. (Citation: Microsoft LSA Protection Mar 2014) LSA Protection ensures that LSA plug-ins and drivers are only loaded if they are digitally signed with a Microsoft signature and adhere to the Microsoft Security Development Lifecycle (SDL) process guidance.

On Windows 10 and Server 2016, enable Windows Defender Credential Guard (Citation: Microsoft Enable Cred Guard April 2017) to run lsass.exe in an isolated virtualized environment without any device drivers. (Citation: Microsoft Credential Guard April 2017)

Ensure safe DLL search mode is enabled <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode</code> to mitigate risk that lsass.exe loads a malicious code library. (Citation: Microsoft DLL Security)


# Techniques


* [LSASS Driver](../techniques/LSASS-Driver.md)

