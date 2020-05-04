
# Distributed Component Object Model Mitigation

## Description

### MITRE Description

> Modify Registry settings (directly or using Dcomcnfg.exe) in <code>HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{AppID_GUID}</code> associated with the process-wide security of individual COM applications. (Citation: Microsoft Process Wide Com Keys)

Modify Registry settings (directly or using Dcomcnfg.exe) in <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole</code> associated with system-wide security defaults for all COM applications that do no set their own process-wide security. (Citation: Microsoft System Wide Com Keys) (Citation: Microsoft COM ACL)

Consider disabling DCOM through Dcomcnfg.exe. (Citation: Microsoft Disable DCOM)

Enable Windows firewall, which prevents DCOM instantiation by default.

Ensure all COM alerts and Protected View are enabled. (Citation: Microsoft Protected View)


# Techniques


* [Component Object Model and Distributed COM](../techniques/Component-Object-Model-and-Distributed-COM.md)

