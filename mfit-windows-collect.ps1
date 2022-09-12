$ErrorActionPreference = "Stop"

$HTTP_REQUEST_TIMEOUT_MILLISECONDS = 1000
$HTTP_REQUEST_RETRIES = 3
$AWS_IMDS_BASE_URL = "http://169.254.169.254/latest"
$GCP_IMDS_BASE_URL = "http://169.254.169.254/computeMetadata/v1/instance"

$SCRIPT_GIT_HASH = "SCRIPT_GIT_HASH_PLACEHOLDER"

if ($PsVersionTable.psversion.major -eq 2) {
  # Workaround for http://www.leeholmes.com/blog/2008/07/30/workaround-the-os-handles-position-is-not-what-filestream-expected/
  $externalHostRef = $host.GetType().GetField("externalHostRef", [Reflection.BindingFlags]"NonPublic, Instance").GetValue($host)
  $externalHost = $externalHostRef.GetType().GetProperty("Value", [Reflection.BindingFlags]"NonPublic, Instance").GetValue($externalHostRef, @())
  # We need to call this even though we don't use it as it changes some internal state.
  $externalHost.GetType().GetProperty("IsStandardOutputRedirected", [Reflection.BindingFlags]"NonPublic, Instance").GetValue($externalHost, @()) > $null
  $externalHost.GetType().GetField("standardOutputWriter", [Reflection.BindingFlags]"NonPublic, Instance").SetValue($externalHost, [Console]::Out)
  $externalHost.GetType().GetField("standardErrorWriter", [Reflection.BindingFlags]"NonPublic, Instance").SetValue($externalHost, [Console]::Error)
}

# '#Requires -RunAsAdministrator' only works in pwsh 4.0 and higher.
function Test-Administrator {
  [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
  return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
}

function Test-SupportedPowershellVersion {
  return $PsVersionTable -and $psVersionTable.PSVersion -and ($psVersionTable.PSVersion.Major -ge 2)
}

function Test-SupportedWindowsVersion {
  return $PsVersionTable -and $psVersionTable.BuildVersion -and ($psVersionTable.BuildVersion.Major -gt 6) -or
      (($psVersionTable.BuildVersion.Major -eq 6) -and ($psVersionTable.BuildVersion.Minor -ge 1))
}

function Test-PowershellCore {
  return $PsVersionTable -and $psVersionTable.PsEdition -eq "Core"
}

# if (-not(Test-Administrator)) {
#   throw "This script must be executed as Administrator.";
# }

if (-not(Test-SupportedPowershellVersion)) {
  throw "This script must be run on powershell version >= 2.0.";
}

if (-not(Test-SupportedWindowsVersion)) {
  throw "This script must be run on windows version >= 6.1 (Windows Server 2008r2 / Windows Desktop 7).";
}

if (Test-PowershellCore) {
  throw "This script is running from PowerShell Core (pwsh.exe). Please run it from Powershell (powershell.exe).";
}

# Used for testing purposes.
$ForceImdsv1 = $args -contains "--force-imdsv1"
$Minimal = $args -contains "--minimal"
$OutputPath = $args | Where-Object {($_ -ne "--minimal") -and ($_ -ne "--force-imdsv1")} | Select-Object -First 1
if ($null -eq $OutputPath) {
  $name = ""
  try {
    $name = hostname
    if ($LASTEXITCODE -ne 0) {
      $name = ""
    }
  }
  catch{}
  $date = Get-Date -Format "yyyy-MM-dd-HH-mm"
  $OutputPath = "m4a-collect-$name-$date"
}

#region utility functions

function Out-Error($message) {
  # If Error Action is set to Stop, Write-Error throws by default, which is not what we want.
  Write-Error $message -ErrorAction Continue
}

function New-TemporaryDirectory($path) {
  $parent = [System.IO.Path]::GetTempPath()
  [string]$name = [System.Guid]::NewGuid()
  return New-Item -ItemType Directory -Path (Join-Path $parent $name)
}

function ArchiveFiles($src, $dest) {
  $zipPath = ($dest + ".zip")
  $tarPath = ($dest + ".tar")
  if ( Test-Path -Path $zipPath ) {
    Remove-Item -Path $zipPath
  }
  if ( Test-Path -Path $tarPath ) {
    Remove-Item -Path $tarPath
  }

  if (-Not(TryZipFiles $src $zipPath)) {
    if ( Test-Path -Path $zipPath ){
      Remove-Item -Path $zipPath
    }
    Write-Host "Could not zip files. Attempting to tar files."
    TarFiles $src $tarPath
  }
}

function TryZipFiles($src, $dest) {
  Write-Host "Zipping folder '$( $src.FullName )' to '$( $dest )'"
  try {
    return TryZipFilesUsingDotNet $src $dest
  }
  catch {
    Out-Error "Failed zipping files: $_"
    return $false
  }
}

function TryZipFilesUsingDotNet($src, $dest) {
  try {
    Add-Type -Assembly System.IO.Compression.FileSystem
  }
  catch {
    return $false
  }

  [System.IO.Compression.ZipFile]::CreateFromDirectory($src.FullName, $dest)
  return $true
}

function TarFiles($src, $dest) {
  # When all else fails, tar is a simple file format that's practical to implement in pure powershell.
  # This doesn't support compression, and isn't natively openable on windows,
  # so it's a fallback mechanism only.

  Write-Host "Tarring folder '$( $src )' to '$( $dest )'"

  # See https://en.wikipedia.org/wiki/Tar_(computing)#File_format for information on the format,
  # and https://github.com/Keruspe/tar-parser.rs/blob/master/tar.specs for a more detailed specification.
  # We use the ustar format to support long file names.

  New-Item -ItemType file $dest > $null
  Get-ChildItem -Path $src -Name -Recurse | ForEach-Object {
    $relativeName = $_
    $fullName = join-Path $src $relativeName

    if ((Get-Item $fullName) -is [System.IO.DirectoryInfo]) {
      return
    }
    try {
      WriteTarFile $fullName $relativeName $dest
    }
    catch [System.IO.IOException] {
      Out-Error "Could not tar file '$fullName', skipping: $_"
    }
  }

  # End Tar marker.
  [System.IO.File]::AppendAllText($dest, "".PadRight(1024, [char]0), [System.Text.Encoding]::ASCII)
}

function WriteTarFile($fullName, $relativeName, $dest) {
  # Ustar tar format allows storing paths up to 256 chars long.
  # A 100 char suffix is stored at the beginning of the header, and a 155 char prefix towards the end.
  # The two are joined with a '/' character when extracting.
  $nameSuffix = $relativeName
  $namePrefix = ""
  if ($nameSuffix.Length -gt 100) {
    # Path is too long to fit entirely into suffix. Look for a suitable location to split the path.
    # This location is the first "\" character in the final 100 chars of the path.
    $splitIndex = $relativeName.SubString($relativeName.Length - 100, 100).IndexOf("\")
    if ($splitIndex -eq -1) {
      throw "$relativeName is too long a name to be stored in a tar"
    }
    $nameSuffix = $relativeName.SubString($relativeName.Length - 100 + $splitIndex + 1, 100 - $splitIndex - 1)
    $namePrefix = $relativeName.SubString(0, $relativeName.Length - 100 + $splitIndex)
    if ($namePrefix.Length -gt 155) {
      throw "$relativeName is too long a name to be stored in a tar"
    }
  }

  $bytes = [System.IO.File]::ReadAllBytes($fullName)
  $fileSize = $bytes.length

  $header = $nameSuffix.PadRight(100, [char]0) # File Name Suffix.
  $header += "000777".PadRight(8, [char]0) # File mode.
  $header += "0".PadRight(8, [char]0) # Owner ID (skipped).
  $header += "0".PadRight(8, [char]0) # Group ID (skipped).
  $header += [Convert]::ToString($fileSize, 8).PadRight(12, [char]0) # File Size in octal.
  $header += "0".PadRight(12, [char]0) # Last Modified Time (skipped).
  $header += "".PadRight(8, [char]32) # Checksum - leave as spaces for now.
  $header += "0" # Type Flag.
  $header += "".PadRight(100, [char]0) # Linked file name (skipped).
  $header += "ustar".PadRight(6, [char]0) # Ustar format indicator.
  $header += "00" # Ustar version.
  $header += "".PadRight(32, [char]0) # Owner user name (skipped).
  $header += "".PadRight(32, [char]0) # Owner group name (skipped).
  $header += "0".PadRight(8, [char]0) # Device major number (skipped).
  $header += "0".PadRight(8, [char]0) # Device minor number (skipped).
  $header += $namePrefix.PadRight(155, [char]0) # Filename prefix.

  $header = $header.PadRight(512, [char]0) # Padding.

  $checksum = 0
  [system.Text.Encoding]::ASCII.GetBytes($header) | foreach-Object { $checksum += $_ }

  # Format as 6 digit octal, with leading 0s, and two bytes of padding.
  $formattedCheckSum = [Convert]::ToString($checksum, 8).PadLeft(6, [char]48).PadRight(8, [char]0)

  # Replace checksum placeholder with actual checksum.
  $header = $header.Remove(148, 8).Insert(148, $formattedCheckSum)

  [System.IO.File]::AppendAllText($dest, $header, [System.Text.Encoding]::ASCII)

  $stream = New-Object IO.FileStream($dest, [System.IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
  $stream.Write($bytes, 0, $fileSize)
  $stream.Dispose()

  # Add padding.
  $numCharsToPad = 512 - ($fileSize % 512)
  if ($numCharsToPad -eq 512) {
    $numCharsToPad = 0
  }
  [System.IO.File]::AppendAllText($dest, "".PadRight($numCharsToPad, [char]0), [System.Text.Encoding]::ASCII)
}

function OutputToFile($dir, $file, $func) {
  $fullPath = Join-Path $dir $file
  try {
    & $func $fullPath
  }
  catch {
    Out-Error "Error while collecting info for '$( $file )': $_"
    $_ | Out-File -FilePath "$( $fullPath ).error"
  }
}

function OutputToDir($dir, $subDir, $func) {
  $fullPath = Join-Path $dir $subDir
  New-Item -ItemType Directory $fullPath
  try {
    & $func $fullPath
  }
  catch {
    Out-Error "Error while collecting info for '$( $subDir )': $_"
    $_ | Out-File -FilePath "$( $fullPath ).error"
  }
}

$StartProcessTimeout = 3 * 60

function RunProcessWithTimeout([string] $cmd, [string]$argsString, [string]$dir, [string]$file, [bool]$captureOut) {
  OutputToFile $dir $file {
    param($outPath);

    $args = @($argsString)
    $errOutPath = "$outPath.error"

    $startProcessArgs = @{}
    if ($captureOut) {
      $startProcessArgs["RedirectStandardOutput"] = $outPath
    }
    if ($args) {
      $startProcessArgs["ArgumentList"] = $args
    }
    $proc = Start-Process -filePath $cmd -PassThru -RedirectStandardError $errOutPath @startProcessArgs

    $timeouted = $null
    try {
      # https://stackoverflow.com/questions/44057728/start-process-system-diagnostics-process-exitcode-is-null-with-nonewwindow
      $proc.Handle > $null
      $proc | Wait-Process -Timeout $StartProcessTimeout -ErrorAction SilentlyContinue -ErrorVariable timeouted
    }
    catch [System.InvalidOperationException] {
      if (-not $_.Exception.Message.Contains("Process has exited, so the requested information is not available")) {
        throw
      }
    }
    if ($timeouted) {
      $proc | kill
      # Wait for process to hopefully actually die, and the errOutPath to unlock.
      Start-Sleep -Seconds 5
      $message = "$cmd timed out, killing"
      Write-Host $message
      Add-Content -Path $errOutPath -Value $message
    }
    elseif (
      # https://stackoverflow.com/questions/44057728/start-process-system-diagnostics-process-exitcode-is-null-with-nonewwindow
      ($proc.ExitCode -ne $null) -and ($proc.ExitCode -ne 0)
    ) {
      $strCode = $proc.ExitCode.ToString()
      $message = "$cmd exited with $strCode"
      Add-Content -Path $errOutPath -Value $message
      Write-Host $message
    }
    if ((Get-Item $errOutPath).Length -eq 0) {
      Remove-Item -Force -ErrorAction SilentlyContinue -Path $errOutPath
    }
  }
}

function EscapeYamlString($str) {
  return "'" + ($str -replace "'", "''")  + "'"
}

# Writes info about a set of paths to a yaml file.
function DirList($paths, $outFile) {
  Add-Content -Path $outFile -Value "paths:"
  $paths | ForEach-Object {
      $path = $_
      $expandedPath = [System.Environment]::ExpandEnvironmentVariables($path)
      Add-Content -Path $outFile -Value "  $(EscapeYamlString($path)):"
      Add-Content -Path $outFile -Value "    expandedPath: '$expandedPath'"
      $exists = Test-Path $expandedPath
      Add-Content -Path $outFile -Value "    exists: $exists"
      $isUNC = if (([System.Uri]$expandedPath).IsUnc) {$true } else {$false } #This forces null to false
      Add-Content -Path $outFile -Value "    isUNC: $isUNC"
      if ($exists -and (-not$isUNC))
      {
          $childPaths = Get-ChildItem -Path $expandedPath -Name -Recurse | ForEach-Object {
              "      - $(EscapeYamlString($_))"
          }
          Add-Content -Path $outFile -Value "    files:"
          Add-Content -Path $outFile -Value $childPaths
      }
  }
}

function SanitizeFileName($name) {
  return [RegEx]::Replace($name, "[$([RegEx]::Escape([String][System.IO.Path]::GetInvalidFileNameChars()))]", '')
}

#endregion utility functions

#region registry Functions

$REG_SZ                = 1
$REG_EXPAND_SZ         = 2
$REG_BINARY            = 3
$REG_DWORD             = 4
$REG_DWORD_BIG_ENDIAN  = 5
$REG_MULTI_SZ          = 7
$REG_QWORD             = 11

function Escape-JSONString($str) {
	if ($str -eq $null) {return ""}
	$str = $str.ToString().Replace('"', '\"').Replace('\', '\\').Replace("`n", '\n').Replace("`r", '\r').Replace("`t", '\t')
	return "`"$str`"";
}

Function ByteArrayToString($ba) {
  $result = @()
  Foreach ($b in $ba) {
    $result += $b.ToString()
  }
  return '"' + ($result -Join " ") + '"'
}

Function MultiStringAsJsonString($ms) {
  $escaped = @()
  foreach ($s in $ms) {
    $escaped += (Escape-JSONString $s)
  }
  return "[" +($escaped -Join ",") + "]"
}

Function RegValueToJsonString($valKind, $value) {
  switch ($valKind.value__) {
    $REG_SZ { return (Escape-JSONString $value) }
    $REG_EXPAND_SZ { return (Escape-JSONString $value) }
    $REG_MULTI_SZ { return (MultiStringAsJsonString $value) }#(Escape-JSONString ($value -Join "\n")) }
    $REG_DWORD { return $value.ToString() }
    $REG_QWORD { return $value.ToString() }
    $REG_BINARY { return (ByteArrayToString $value) }
    default { return "na" }
  }
}

Function Export-RegistryKeys($keys, $exportPath) {
  $data = @()
  Foreach ($key in $keys) {
    $values = @()

    $properties= $key.Property
    if ($properties) {
      foreach ($property in $properties) {
        if ($property -eq "(default)") {
          $prop = ""
        } else {
          $prop = $property
        }
        $val = $key.GetValue($prop, $null, "DoNotExpandEnvironmentNames")
        $valKind = $key.GetValueKind($prop)
        $valString = RegValueToJsonString $valKind $val
        $values += "{ `"Name`": `"$property`", `"Value`":$valString, `"ValueType`":`"$valKind`" }"
      }
    }
    $allValues = ($values -Join ",")
    $data += "{ `"Path`" : `"$key.PSPath`", `"Values`" : [ $allValues ] }"
  }

  "[" + ($data -Join ",") + "]" | Out-File -FilePath $exportPath
}

function SafelyGetSubkeys($key) {
	return Get-ChildItem $key -Recurse -ErrorAction SilentlyContinue
}
#endregion registry Functions

#region compiled C#

$csharpCompilationError = $nil
function CompileCSharpSource() {
    $source = '
 using System;
 using System.ComponentModel;
 using System.Runtime.InteropServices;

 public static class FirmwareTables
 {
     public static byte[] GetRSMBTable()
     {
         return GetFirmwareTable(0x52534D42, 0);
     }

     private static byte[] GetFirmwareTable(uint firmwareTableProviderSignature, uint firmwareTableID)
     {
         uint tableLength = GetSystemFirmwareTable(firmwareTableProviderSignature, firmwareTableID, IntPtr.Zero, 0);
         if (tableLength == 0)
         {
             throw new Win32Exception();
         }

         IntPtr buffer = Marshal.AllocHGlobal((int)tableLength);
         uint result = GetSystemFirmwareTable(firmwareTableProviderSignature, firmwareTableID, buffer, tableLength);
         if (result != tableLength)
         {
             // `new Win32Exception()` populates error code and message automatically from WIN32 APIs.
             throw new Win32Exception();
         }

         byte[] bytes = new byte[tableLength];
         Marshal.Copy(buffer, bytes, 0, (int)tableLength);
         return bytes;
     }

     [DllImport("kernel32.dll", SetLastError = true)]
     private static extern uint GetSystemFirmwareTable(
         uint firmwareTableProviderSignature,
         uint firmwareTableID,
         IntPtr pFirmwareTableBuffer,
         uint bufferSize
     );
 }

 [StructLayout(LayoutKind.Sequential)]
 public struct MEMORYSTATUSEX {
     // The length field must be set to the size of this data structure.
     public int Length;
     public int MemoryLoad;
     public ulong TotalPhys;
     public ulong AvailPhys;
     public ulong TotalPageFile;
     public ulong AvailPageFile;
     public ulong TotalVirtual;
     public ulong AvailVirtual;
     public ulong AvailExtendedVirtual;
 }

 public static class Memory
 {
     public static MEMORYSTATUSEX GetMemoryStatus() {
         MEMORYSTATUSEX memory = new MEMORYSTATUSEX();
         memory.Length = Marshal.SizeOf(memory);
         if (!GlobalMemoryStatusEx(ref memory)) {
             throw new Win32Exception();
         }
         return memory;
     }

     [DllImport("kernel32.dll", SetLastError=true, EntryPoint="GlobalMemoryStatusEx")]
     private static extern bool GlobalMemoryStatusEx([In, Out] ref MEMORYSTATUSEX buffer);
 }
    '

    try {
        Add-Type -TypeDefinition $source
    }
    catch {
        Out-Error $_
        $Global:csharpCompilationError = $_
    }
}

function ThrowIfCSharpCompilationError() {
    if ($csharpCompilationError -ne $nil) {
        throw $csharpCompilationError
    }
}

#endregion compiled C#

#region collector Functions

function CollectIIS($dir) {
  Write-Host "Collecting IIS Info"

  $iisInstalled = Test-Path -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\InetStp

  if ($iisInstalled) {
    New-Item -ItemType file (Join-Path $dir "installed")
    OutputToDir $dir "configs" $function:CollectIISConfigs
    OutputToDir $dir "sites" $function:CollectIISSites
  }
}

function CollectIISConfigs($dir) {
  $iisConfigSourceDir = "$( $ENV:WinDir )\System32\Inetsrv\Config\*"
  Write-Host "Copying '$iisConfigSourceDir' to '$dir'"
  Copy-Item -Path $iisConfigSourceDir -Destination $dir -Recurse
}

function CollectIISSites($dir) {
  Write-Host "Collecting IIS Sites Info"
  $configPath = "$( $ENV:WinDir )\System32\Inetsrv\Config\applicationHost.config"
  if (Test-Path -Path $configPath) {
    $virtDirs = @()
    $configMap = @{}
    $sites = Select-Xml -Path $configPath -XPath 'configuration/system.applicationHost/sites/site'
    if ($sites) {
      $sites | Foreach-Object { $siteIndex = 0 } {
        $site = $_.Node
        $application = $site.application
        if ($application) {
          $application | Foreach-Object { $appIndex = 0 } {
            $virtualDirectory = $_.virtualDirectory
            if ($virtualDirectory) {
              $_.virtualDirectory | Foreach-Object { $dirIndex = 0 } {
                $physicalPath = $_.physicalPath
                if ($physicalPath) {
                  $virtDirs += $physicalPath
                  if (Test-Path -Path $physicalPath) {
                    $webConfigPath = Join-Path $physicalPath "web.config"
                    if (Test-Path -Path $webConfigPath) {
                      $name = "$($site.name).$($application.path).$($virtualDirectory.path).$($siteIndex)_$($appIndex)_$($dirIndex).web.config"
                      $name = SanitizeFileName($name)
                      $MAX_TAR_NAME_LENGTH = 100
                      if ($name.length -gt $MAX_TAR_NAME_LENGTH) {
                        $name = "$($siteIndex)_$($appIndex)_$($dirIndex).web.config"
                      }
                      OutputToFile $dir $name { param($path);  Copy-Item -Path $webConfigPath -Destination $path }
                      $configMap[$physicalPath] = $name
                    }
                  }
                }
                $dirIndex++
              }
            }
            $appIndex++
          }
        }
        $siteIndex++
      }
    }
    OutputToFile $dir "virtualDirectories.yml" { param($path); DirList $virtDirs $path }
    OutputToFile $dir "virtualDirectoryConfigMap.yml" {
      param($path);
      New-Item -ItemType file -Path $path
      $configMap.Keys | ForEach-Object {
        $key = $_
        Add-Content -Path $path -Value "'$( $key )': '$( $configMap[$key] )'"
      }
    }
  }
}

function CollectPathInfo($path, $outPath) {
  $exists = Test-Path -Path $path
  $isUnc = ([System.Uri]$path).IsUnc

  "Path=$path
Exists=$exists
IsUNC=$isUnc" | Out-File $outPath
}

function CollectCmds($dir) {
  Write-Host "Collecting command outputs"
  RunProcessWithTimeout "hostname.exe" "" $dir "hostname.txt" $true
  if (-not $Minimal) {
    RunProcessWithTimeout "ipconfig.exe" "/all" $dir "ipconfig.txt" $true
    RunProcessWithTimeout "netstat.exe" "-r" $dir "netstat_all.txt" $true
    RunProcessWithTimeout "netstat.exe" "-a -b -n" $dir "netstat_routes.txt" $true
    RunProcessWithTimeout "schtasks.exe" "/query /V /FO CSV" $dir "schtasks.txt" $true
    $svcRegPath = Join-Path $dir "services.reg"
    RunProcessWithTimeout "reg.exe" "export hklm\system\CurrentControlSet\services $svcRegPath /y" $dir "services.reg" $false
  }
}

function CollectWMI($dir) {
  Write-Host "Collecting WMI Info"
  OutputToFile $dir "os.csv" { param($path); (Get-WmiObject Win32_OperatingSystem) | Export-Csv -NoTypeInformation $path }
  OutputToFile $dir "networkAdapter.csv" { param($path); (Get-WmiObject Win32_NetworkAdapter) | Export-Csv -NoTypeInformation $path }
  OutputToFile $dir "computerSystem.csv" { param($path); (Get-WmiObject Win32_ComputerSystem) | Export-Csv -NoTypeInformation $path }
  OutputToFile $dir "computerSystemProduct.csv" { param($path); (Get-WmiObject Win32_ComputerSystemProduct) | Export-Csv -NoTypeInformation $path }
  OutputToFile $dir "diskDrives.csv" { param($path); (Get-WmiObject Win32_DiskDrive) | Export-Csv -NoTypeInformation $path }
  OutputToFile $dir "processors.csv" { param($path); (Get-WmiObject Win32_Processor) | Export-Csv -NoTypeInformation $path }
  OutputToFile $dir "memory.csv" { param($path); (Get-WmiObject Win32_PhysicalMemory) | Export-Csv -NoTypeInformation $path }
}

function CollectSelfVersion($dir) {
  Write-Host "Collecting self version info"
  OutputToFile $dir "version.txt" { param($path); $SCRIPT_GIT_HASH | Out-File -FilePath $path }
}

function CollectPS($dir) {
  Write-Host "Collecting Info from PowerShell primitives"
  OutputToFile $dir "psversiontable.csv" { param($path); New-Object PSObject -property $PSVersionTable | Export-Csv -NoTypeInformation $path }
}

function CollectRegistryByKeys($keyPath, $dir, $fileName) {
  $keys = SafelyGetSubkeys $keyPath
  OutputToFile $dir $fileName { param($path); Export-RegistryKeys $keys $path }
}

function CollectRegistry($dir) {
  Write-Host "Collecting items from registry"
  $uninstallFile = "uninstall.json"
  CollectRegistryByKeys HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall $dir $uninstallFile
  CollectRegistryByKeys HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall $dir $uninstallFile

  $odbcFile = "odbc.json"
  CollectRegistryByKeys HKLM:\SOFTWARE\Microsoft\ODBC $dir $odbcFile
  CollectRegistryByKeys HKLM:\SOFTWARE\Wow6432Node\Microsoft\ODBC $dir $odbcFile
}

function CollectFrameworkConfigs($dir) {
  $sourceDir = "$( $ENV:WinDir )\Microsoft.NET"
  $searchPath = "$sourceDir\Framework*\v*\Config\*"
  Get-ChildItem $searchPath | Foreach-Object {
    if( -not $_.PsIsContainer ) {
      $targetFile = $dir + $_.FullName.SubString($sourceDir.Length);
      New-Item -ItemType File -Path $targetFile -Force;
      Copy-Item $_.FullName -destination $targetFile
    }
  }
}

function CollectFiles($dir) {
  Write-Host "Collecting various configuration files"
  OutputToDir $dir "framework-configs" $function:CollectFrameworkConfigs
}

function CollectFrameworkTables($dir) {
  Write-Host "Collecting framework tables"
  OutputToFile $dir "rsmb" { param($path); ThrowIfCSharpCompilationError; [System.IO.File]::WriteAllBytes($path, [FirmwareTables]::GetRSMBTable()) }
}

function CollectCSharpInfo($dir) {
  Write-Host "Collecting Data Using CSharp APIs"
  OutputToFile $dir "osVersion.csv" { param($path); [System.Environment]::OSVersion | Export-Csv -NoTypeInformation $path }
  OutputToFile $dir "processorCount.txt" { param($path); [System.Environment]::ProcessorCount | Out-File -FilePath $path }
  OutputToFile $dir "memoryStatus.csv" { param($path); ThrowIfCSharpCompilationError; [Memory]::GetMemoryStatus() | Export-Csv -NoTypeInformation $path }
  OutputToFile $dir "drives.csv" { param($path); [System.IO.DriveInfo]::GetDrives() | Export-Csv -NoTypeInformation $path }
}

#endregion collector Functions

#platform collector Functions

function ReadWebResponseIfSuccessful($url, $method, $headers) {
  # Create HTTP request.
  $request = [System.Net.WebRequest]::Create($url)
  $request.Method = $method
  foreach ($header in $headers.GetEnumerator()) {
    $request.Headers[$header.Name] = $header.Value
  }
  $request.Timeout = $HTTP_REQUEST_TIMEOUT_MILLISECONDS

  try {
    [System.Net.HttpWebResponse]$response = $request.GetResponse()
    if ($response.StatusCode -ne 200) {
      return $null
    }
    # Read HTTP response content.
    [System.IO.Stream]$stream = $response.GetResponseStream()
    [System.Text.Encoding]$encode = [System.Text.Encoding]::GetEncoding("utf-8")
    [System.IO.StreamReader]$reader = New-Object -TypeName System.IO.StreamReader -ArgumentList $stream, $encode
    return $reader.ReadToEnd()
  } catch {
    return $null
  } finally {
    if ($response -ne $null) {
      $response.Close()
    }
  }
}

function RetryReadWebResponseIfSuccessful($url, $method, $headers) {
  $retries = 1
  do {
    $response = ReadWebResponseIfSuccessful $url $method $headers
    if ($response -ne $null) {
      return $response
    }
    $retries++
  } while ($retries -le $HTTP_REQUEST_RETRIES)
  return $null
}

function CheckAWSIMDSv2() {
  $token = ReadWebResponseIfSuccessful "$AWS_IMDS_BASE_URL/api/token" "PUT" @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"}
  if ($token -eq $null) {
    return $null
  }
  $identity = ReadWebResponseIfSuccessful "$AWS_IMDS_BASE_URL/dynamic/instance-identity/document" "GET" @{"X-aws-ec2-metadata-token" = $token}
  if ($identity -eq $null) {
    return $null
  } else {
    return $token
  }
}

function CheckAWSIMDSv1() {
  return ReadWebResponseIfSuccessful "$AWS_IMDS_BASE_URL/dynamic/instance-identity/document" "GET" @{}
}

function GetAWSInstanceMetadata($token, $category) {
  Write-Host "Collecting metadata $category"
  if ($token -ne $null) {
    Write-Host "Using IMDSv2"
    $headers = @{"X-aws-ec2-metadata-token" = $token}
  } else {
    Write-Host "Using IMDSv1"
    $headers = @{}
  }
  return ReadWebResponseIfSuccessful "$AWS_IMDS_BASE_URL/meta-data/$category" "GET" $headers
}

# Tries collecting AWS metadata using HTTP requests to AWS IMDS.
# If not run on EC2 instance with IMDS enabled, it will timeout after two seconds.
# If run on EC2 instance with IMDS enabled, it will output metadata content to `aws` folder.
function CollectAWSMetadata($dir) {
  # Checks different IMDS versions.
  $token = CheckAWSIMDSv2
  if (($token -eq $null) -and ($(CheckAWSIMDSv1) -eq $null)) {
    # None of the AWS IMDS versions are supported.
    Remove-Item $dir
    return
  }
  if ($ForceImdsv1) {
    $token = $null
  }

  Write-Host "Collecting AWS metadata"
  OutputToFile $dir "instance-id" {
    param($path)
    GetAWSInstanceMetadata $token "instance-id" | Out-File -FilePath $path
  }
}

function CheckGCPMetadata() {
  return RetryReadWebResponseIfSuccessful "$GCP_IMDS_BASE_URL/" "GET" @{"Metadata-Flavor" = "Google"}
}

function GetGCPInstanceMetadata($key) {
  return RetryReadWebResponseIfSuccessful "$GCP_IMDS_BASE_URL/$key" "GET" @{"Metadata-Flavor" = "Google"}
}

# Tries collecting GCP metadata using HTTP requests to metadata server.
# If not run on GCP instance with metadata access enabled, it will timeout after one second.
# If run on GCP instance with metadata access enabled, it will output metadata content to `gce` folder.
function CollectGCPMetadata($dir) {
  if ($(CheckGCPMetadata) -eq $null) {
    Remove-Item $dir
    return
  }

  Write-Host "Collecting Google Cloud metadata"
  OutputToFile $dir "id" {
    param($path)
    GetGCPInstanceMetadata "id" | Out-File -FilePath $path
  }
  OutputToFile $dir "name" {
    param($path)
    GetGCPInstanceMetadata "name" | Out-File -FilePath $path
  }
}
#endplatform collector Functions

# On powershell 2.0 this has to be called before setting Environment.CurrentDirectory.
CompileCSharpSource

[Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath

$dir = New-TemporaryDirectory

$collectors = @{
  version = $function:CollectSelfVersion
  iis = $function:CollectIIS
  cmds = $function:CollectCmds
  wmi = $function:CollectWMI
  ps = $function:CollectPS
  framework_tables = $function:CollectFrameworkTables
  csharp = $function:CollectCSharpInfo
}

if (-not $Minimal) {
  $collectors += @{
    reg = $function:CollectRegistry
    files = $function:CollectFiles
    aws = $function:CollectAWSMetadata
    gce = $function:CollectGCPMetadata
  }
}

New-Item -ItemType file (Join-Path $dir "windows") > $null

$collectors.Keys | ForEach-Object {
  $key = $_
  OutputToDir $dir $key $collectors[$key]
} > $null

ArchiveFiles $dir $OutputPath

Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
