
# Path Interception Mitigation

## Description

### MITRE Description

> Eliminate path interception weaknesses in program configuration files, scripts, the PATH environment variable, services, and in shortcuts by surrounding PATH variables with quotation marks when functions allow for them (Citation: Microsoft CreateProcess). Be aware of the search order Windows uses for executing or loading binaries and use fully qualified paths wherever appropriate (Citation: MSDN DLL Security). Clean up old Windows Registry keys when software is uninstalled to avoid keys with no associated legitimate binaries.

Periodically search for and correct or report path interception weaknesses on systems that may have been introduced using custom or available tools that report software using insecure path configurations (Citation: Kanthak Sentinel). 

Require that all executables be placed in write-protected directories. Ensure that proper permissions and directory access control are set to deny users the ability to write files to the top-level directory <code>C:</code> and system directories, such as <code>C:\Windows\</code>, to reduce places where malicious files could be placed for execution.

Identify and block potentially malicious software that may be executed through the path interception by using whitelisting (Citation: Beechey 2010) tools, like AppLocker (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) or Software Restriction Policies, (Citation: Corio 2008) that are capable of auditing and/or blocking unknown executables.


# Techniques


* [Path Interception](../techniques/Path-Interception.md)

