
# Privilege Escalation

> privilege-escalation

## Description

### MITRE Description

> The adversary is trying to gain higher-level permissions.

Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities. Examples of elevated access include: 
•	SYSTEM/root level
•	local administrator
•	user account with admin-like access 
•	user accounts with access to specific system or perform specific function
These techniques often overlap with Persistence techniques, as OS features that let an adversary persist can execute in an elevated context.  


# Techniques


* [.bash_profile and .bashrc](../techniques/.bash_profile-and-.bashrc.md)

* [Abuse Elevation Control Mechanism](../techniques/Abuse-Elevation-Control-Mechanism.md)
    
* [Access Token Manipulation](../techniques/Access-Token-Manipulation.md)
    
* [Accessibility Features](../techniques/Accessibility-Features.md)
    
* [AppCert DLLs](../techniques/AppCert-DLLs.md)
    
* [AppInit DLLs](../techniques/AppInit-DLLs.md)
    
* [Application Shimming](../techniques/Application-Shimming.md)
    
* [Asynchronous Procedure Call](../techniques/Asynchronous-Procedure-Call.md)
    
* [At (Linux)](../techniques/At-(Linux).md)
    
* [At (Windows)](../techniques/At-(Windows).md)
    
* [Authentication Package](../techniques/Authentication-Package.md)
    
* [Boot or Logon Autostart Execution](../techniques/Boot-or-Logon-Autostart-Execution.md)
    
* [Boot or Logon Initialization Scripts](../techniques/Boot-or-Logon-Initialization-Scripts.md)
    
* [Bypass User Access Control](../techniques/Bypass-User-Access-Control.md)
    
* [COR_PROFILER](../techniques/COR_PROFILER.md)
    
* [Change Default File Association](../techniques/Change-Default-File-Association.md)
    
* [Cloud Accounts](../techniques/Cloud-Accounts.md)
    
* [Component Object Model Hijacking](../techniques/Component-Object-Model-Hijacking.md)
    
* [Create Process with Token](../techniques/Create-Process-with-Token.md)
    
* [Create or Modify System Process](../techniques/Create-or-Modify-System-Process.md)
    
* [Cron](../techniques/Cron.md)
    
* [DLL Search Order Hijacking](../techniques/DLL-Search-Order-Hijacking.md)
    
* [DLL Side-Loading](../techniques/DLL-Side-Loading.md)
    
* [Default Accounts](../techniques/Default-Accounts.md)
    
* [Domain Accounts](../techniques/Domain-Accounts.md)
    
* [Dylib Hijacking](../techniques/Dylib-Hijacking.md)
    
* [Dynamic-link Library Injection](../techniques/Dynamic-link-Library-Injection.md)
    
* [Elevated Execution with Prompt](../techniques/Elevated-Execution-with-Prompt.md)
    
* [Emond](../techniques/Emond.md)
    
* [Event Triggered Execution](../techniques/Event-Triggered-Execution.md)
    
* [Executable Installer File Permissions Weakness](../techniques/Executable-Installer-File-Permissions-Weakness.md)
    
* [Exploitation for Privilege Escalation](../techniques/Exploitation-for-Privilege-Escalation.md)
    
* [Extra Window Memory Injection](../techniques/Extra-Window-Memory-Injection.md)
    
* [Group Policy Modification](../techniques/Group-Policy-Modification.md)
    
* [Hijack Execution Flow](../techniques/Hijack-Execution-Flow.md)
    
* [Image File Execution Options Injection](../techniques/Image-File-Execution-Options-Injection.md)
    
* [Kernel Modules and Extensions](../techniques/Kernel-Modules-and-Extensions.md)
    
* [LC_LOAD_DYLIB Addition](../techniques/LC_LOAD_DYLIB-Addition.md)
    
* [LD_PRELOAD](../techniques/LD_PRELOAD.md)
    
* [LSASS Driver](../techniques/LSASS-Driver.md)
    
* [Launch Agent](../techniques/Launch-Agent.md)
    
* [Launch Daemon](../techniques/Launch-Daemon.md)
    
* [Launchd](../techniques/Launchd.md)
    
* [Local Accounts](../techniques/Local-Accounts.md)
    
* [Logon Script (Mac)](../techniques/Logon-Script-(Mac).md)
    
* [Logon Script (Windows)](../techniques/Logon-Script-(Windows).md)
    
* [Make and Impersonate Token](../techniques/Make-and-Impersonate-Token.md)
    
* [Netsh Helper DLL](../techniques/Netsh-Helper-DLL.md)
    
* [Network Logon Script](../techniques/Network-Logon-Script.md)
    
* [Parent PID Spoofing](../techniques/Parent-PID-Spoofing.md)
    
* [Path Interception](../techniques/Path-Interception.md)
    
* [Path Interception by PATH Environment Variable](../techniques/Path-Interception-by-PATH-Environment-Variable.md)
    
* [Path Interception by Search Order Hijacking](../techniques/Path-Interception-by-Search-Order-Hijacking.md)
    
* [Path Interception by Unquoted Path](../techniques/Path-Interception-by-Unquoted-Path.md)
    
* [Plist Modification](../techniques/Plist-Modification.md)
    
* [Port Monitors](../techniques/Port-Monitors.md)
    
* [Portable Executable Injection](../techniques/Portable-Executable-Injection.md)
    
* [PowerShell Profile](../techniques/PowerShell-Profile.md)
    
* [Proc Memory](../techniques/Proc-Memory.md)
    
* [Process Doppelgänging](../techniques/Process-Doppelgänging.md)
    
* [Process Hollowing](../techniques/Process-Hollowing.md)
    
* [Process Injection](../techniques/Process-Injection.md)
    
* [Ptrace System Calls](../techniques/Ptrace-System-Calls.md)
    
* [Rc.common](../techniques/Rc.common.md)
    
* [Re-opened Applications](../techniques/Re-opened-Applications.md)
    
* [Registry Run Keys / Startup Folder](../techniques/Registry-Run-Keys---Startup-Folder.md)
    
* [SID-History Injection](../techniques/SID-History-Injection.md)
    
* [Scheduled Task](../techniques/Scheduled-Task.md)
    
* [Scheduled Task/Job](../techniques/Scheduled-Task-Job.md)
    
* [Screensaver](../techniques/Screensaver.md)
    
* [Security Support Provider](../techniques/Security-Support-Provider.md)
    
* [Services File Permissions Weakness](../techniques/Services-File-Permissions-Weakness.md)
    
* [Services Registry Permissions Weakness](../techniques/Services-Registry-Permissions-Weakness.md)
    
* [Setuid and Setgid](../techniques/Setuid-and-Setgid.md)
    
* [Shortcut Modification](../techniques/Shortcut-Modification.md)
    
* [Startup Items](../techniques/Startup-Items.md)
    
* [Sudo and Sudo Caching](../techniques/Sudo-and-Sudo-Caching.md)
    
* [Systemd Service](../techniques/Systemd-Service.md)
    
* [Thread Execution Hijacking](../techniques/Thread-Execution-Hijacking.md)
    
* [Thread Local Storage](../techniques/Thread-Local-Storage.md)
    
* [Time Providers](../techniques/Time-Providers.md)
    
* [Token Impersonation/Theft](../techniques/Token-Impersonation-Theft.md)
    
* [Trap](../techniques/Trap.md)
    
* [VDSO Hijacking](../techniques/VDSO-Hijacking.md)
    
* [Valid Accounts](../techniques/Valid-Accounts.md)
    
* [Windows Management Instrumentation Event Subscription](../techniques/Windows-Management-Instrumentation-Event-Subscription.md)
    
* [Windows Service](../techniques/Windows-Service.md)
    
* [Winlogon Helper DLL](../techniques/Winlogon-Helper-DLL.md)
    
