
# Man in the Browser

## Description

### MITRE Description

> Adversaries can take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify behavior, and intercept information as part of various man in the browser techniques. (Citation: Wikipedia Man in the Browser)

A specific example is when an adversary injects software into a browser that allows an them to inherit cookies, HTTP sessions, and SSL client certificates of a user and use the browser as a way to pivot into an authenticated intranet. (Citation: Cobalt Strike Browser Pivot) (Citation: ICEBRG Chrome Extensions)

Browser pivoting requires the SeDebugPrivilege and a high-integrity process to execute. Browser traffic is pivoted from the adversary's browser through the user's browser by setting up an HTTP proxy which will redirect any HTTP and HTTPS traffic. This does not alter the user's traffic in any way. The proxy connection is severed as soon as the browser is closed. Whichever browser process the proxy is injected into, the adversary assumes the security context of that process. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly. With these permissions, an adversary could browse to any resource on an intranet that is accessible through the browser and which the browser has sufficient permissions, such as Sharepoint or webmail. Browser pivoting also eliminates the security provided by 2-factor authentication. (Citation: cobaltstrike manual)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1185

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Packet capture']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Packet capture']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations

None

# Actors

None
