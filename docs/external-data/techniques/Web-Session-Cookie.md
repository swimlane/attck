
# Web Session Cookie

## Description

### MITRE Description

> Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated.(Citation: Pass The Cookie)

Authentication cookies are commonly used in web applications, including cloud-based services, after a user has authenticated to the service so credentials are not passed and re-authentication does not need to occur as frequently. Cookies are often valid for an extended period of time, even if the web application is not actively used. After the cookie is obtained through [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539), the adversary then imports the cookie into a browser they control and is able to use the site or application as the user for as long as the session cookie is active. Once logged into the site, an adversary can access sensitive information, read email, or perform actions that the victim account has permissions to perform.

There have been examples of malware targeting session cookies to bypass multi-factor authentication systems.(Citation: Unit 42 Mac Crypto Cookies January 2019) 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Logon Credentials', 'Multi-Factor Authentication']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Office 365', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1506

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

```

## Raw Dataset

```json

```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Lateral Movement](../tactics/Lateral-Movement.md)
    

# Mitigations

None

# Actors

None
