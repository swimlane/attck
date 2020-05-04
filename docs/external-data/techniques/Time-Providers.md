
# Time Providers

## Description

### MITRE Description

> The Windows Time service (W32Time) enables time synchronization across and within domains. (Citation: Microsoft W32Time Feb 2018) W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients. (Citation: Microsoft TimeProvider)

Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of  <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\</code>. (Citation: Microsoft TimeProvider) The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed. (Citation: Microsoft TimeProvider)

Adversaries may abuse this architecture to establish Persistence, specifically by registering and enabling a malicious DLL as a time provider. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account. (Citation: Github W32Time Oct 2017)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1209

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Time Providers',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           'registry_key_path contains '
           '"\\\\System\\\\CurrentControlSet\\\\Services\\\\W32Time\\\\TimeProviders\\\\"'}]
```

## Raw Dataset

```json

```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors

None
