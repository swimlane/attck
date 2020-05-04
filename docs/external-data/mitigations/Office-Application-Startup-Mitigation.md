
# Office Application Startup Mitigation

## Description

### MITRE Description

> Follow Office macro security best practices suitable for your environment. Disable Office VBA macros from executing. Even setting to disable with notification could enable unsuspecting users to execute potentially malicious macros. (Citation: TechNet Office Macro Security)

For the Office Test method, create the Registry key used to execute it and set the permissions to "Read Control" to prevent easy access to the key without administrator permissions or requiring Privilege Escalation. (Citation: Palo Alto Office Test Sofacy)

Disable Office add-ins. If they are required, follow best practices for securing them by requiring them to be signed and disabling user notification for allowing add-ins. For some add-ins types (WLL, VBA) additional mitigation is likely required as disabling add-ins in the Office Trust Center does not disable WLL nor does it prevent VBA code from executing. (Citation: MRWLabs Office Persistence Add-ins)

For the Outlook methods, blocking macros may be ineffective as the Visual Basic engine used for these features is separate from the macro scripting engine.(Citation: SensePost Outlook Forms) Microsoft has released patches to try to address each issue. Ensure KB3191938 which blocks Outlook Visual Basic and displays a malicious code warning, KB4011091 which disables custom forms by default, and KB4011162 which removes the legacy Home Page feature, are applied to systems.(Citation: SensePost Outlook Home Page)


# Techniques


* [Office Application Startup](../techniques/Office-Application-Startup.md)

