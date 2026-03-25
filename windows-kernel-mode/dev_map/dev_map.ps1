# Author: Julian Horoszkiewicz

# This PowerShell script enumerates all device objects in the Windows kernel namespace (\Device\) and maps them to their corresponding user-mode symbolic links in \GLOBAL??\. For each device, it retrieves the security descriptor (SDDL) and
# determines whether the device is accessible only to administrators (SYSTEM, Builtin Administrators, Local Administrator) or also to non-privileged users, outputting the results to a CSV file for attack surface analysis.

# NOTE on driver identification:
# - Added dev_map_kldbg.exe (loads and utilizes the kldbgdrv.sys kernel mode driver) as the preferred method of obtaining driver information for device objects
# - PnP devices: Driver info obtained via Win32_PnPSignedDriver (PDO field) and
#   Win32_PnPSignedDriverCIMDataFile association class for .sys file paths.
# - Non-PnP devices: Fallback method searches loaded driver .sys files for device name strings.
#   This is heuristic and may have false positives/negatives. Auto-generated hex device names
#   (e.g., \Device\00000001) are skipped to avoid false matches.

# Requires NtObjectManager module
# Install-Module NtObjectManager

param(
    [string]$OutputFile = "devices.csv"
)

Import-Module NtObjectManager

# Step 0: Build PnP driver lookup tables
Write-Host "Building PnP driver lookup tables..." -ForegroundColor Cyan

# Step 0a: Build DeviceID -> SysFile(s) map from association class
$deviceIdToSys = @{}
Get-CimInstance Win32_PnPSignedDriverCIMDataFile |
    Where-Object { $_.Dependent.Name -like "*.sys" } |
    ForEach-Object {
        $devId = $_.Antecedent.CimInstanceProperties["DeviceID"].Value
        $sysFile = $_.Dependent.Name
        if (-not $deviceIdToSys.ContainsKey($devId)) {
            $deviceIdToSys[$devId] = @()
        }
        $deviceIdToSys[$devId] += $sysFile
    }
Write-Host "Found $($deviceIdToSys.Count) DeviceID -> SysFile mappings" -ForegroundColor Green

# Step 0b: Build PDO -> driver info map, including SysFile from Step 0a
$pnpDriverMap = @{}
Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.PDO } | ForEach-Object {
    $sysFiles = ""
    if ($deviceIdToSys.ContainsKey($_.DeviceID)) {
        $sysFiles = $deviceIdToSys[$_.DeviceID] -join "`n"
    }
    $pnpDriverMap[$_.PDO] = [PSCustomObject]@{
        InfName      = $_.InfName
        DeviceName   = $_.DeviceName
        HardwareID   = $_.HardWareID
        Manufacturer = $_.Manufacturer
        SysFiles     = $sysFiles
    }
}
Write-Host "Found $($pnpDriverMap.Count) PnP devices with driver info" -ForegroundColor Green

# Step 0c: Get all loaded driver .sys paths for fallback matching
Write-Host "Getting loaded driver paths for fallback matching..." -ForegroundColor Cyan
$allSysFiles = @()
$serviceToSysPath = @{}
Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName } | ForEach-Object {
    # Normalize path (some have \??\ prefix)
    $path = $_.PathName -replace '^\\\?\?\\', ''
    if (Test-Path $path -PathType Leaf -ErrorAction SilentlyContinue) {
        $allSysFiles += $path
        $serviceToSysPath[$_.Name] = $path
    }
}

# Identify .sys files already matched via PnP (flatten arrays and get unique)
$pnpMatchedSysFiles = @($deviceIdToSys.Values | ForEach-Object { $_ } | Select-Object -Unique)

# Build prioritized list: unmatched .sys files first, then PnP-matched ones
$unmatchedSysFiles = @($allSysFiles | Where-Object { $_ -notin $pnpMatchedSysFiles })
$matchedSysFiles = @($allSysFiles | Where-Object { $_ -in $pnpMatchedSysFiles })
$prioritizedSysFiles = $unmatchedSysFiles + $matchedSysFiles

Write-Host "Found $($allSysFiles.Count) loaded drivers, $($unmatchedSysFiles.Count) not yet matched via PnP" -ForegroundColor Green

# Function to determine if SDDL grants access only to admin entities
function Test-AdminOnlyAccess {
    param([string]$Sddl)

    # If SDDL is an error message, return unknown
    if ($Sddl.Contains("[Error:")) {
        return "UNKNOWN"
    }

    # Admin-only SIDs: BA (Builtin Admins), SY (System), LA (Local Admin)
    $adminSids = @('BA', 'SY', 'LA')

    # Find all Allow ACEs - pattern matches (A;flags;rights;guid;guid;SID)
    # ACE format: (ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid)
    $acePattern = '\(A;[^)]*\)'
    $matches = [regex]::Matches($Sddl, $acePattern)

    foreach ($match in $matches) {
        $ace = $match.Value
        # Split ACE into components
        $parts = $ace.Trim('()') -split ';'
        if ($parts.Count -ge 6) {
            $sid = $parts[5]
            # Check if SID is NOT one of the admin SIDs
            if ($sid -notin $adminSids) {
                return "NO"
            }
        }
    }

    return "YES"
}

# kldbg interactive session management functions
function Start-KldbgSession {
    param(
        [string]$ExePath,
        [string]$DriverPath
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExePath
    $psi.Arguments = "-driver `"$DriverPath`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $proc.EnableRaisingEvents = $true

    $queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

    $job = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action {
        if ($null -ne $EventArgs.Data) {
            $Event.MessageData.Enqueue($EventArgs.Data)
        }
    } -MessageData $queue

    # Drain stderr to prevent blocking (no-op handler)
    $proc.add_ErrorDataReceived({ })

    try {
        $proc.Start() | Out-Null
    } catch {
        Unregister-Event -SourceIdentifier $job.Name -ErrorAction SilentlyContinue
        Remove-Job -Id $job.Id -Force -ErrorAction SilentlyContinue
        return $null
    }

    $proc.BeginOutputReadLine()
    $proc.BeginErrorReadLine()

    # Wait for initialization
    $deadline = [DateTime]::Now.AddSeconds(15)
    $initialized = $false

    while ([DateTime]::Now -lt $deadline -and -not $proc.HasExited) {
        $line = $null
        if ($queue.TryDequeue([ref]$line)) {
            if ($line -match 'Driver connection established') {
                $initialized = $true
                Start-Sleep -Milliseconds 500
                while ($queue.TryDequeue([ref]$line)) { }
                break
            }
            if ($line -match 'Failed to initialize|Failed to load') {
                break
            }
        } else {
            Start-Sleep -Milliseconds 100
        }
    }

    if (-not $initialized) {
        try { if (-not $proc.HasExited) { $proc.Kill() } } catch { }
        Unregister-Event -SourceIdentifier $job.Name -ErrorAction SilentlyContinue
        Remove-Job -Id $job.Id -Force -ErrorAction SilentlyContinue
        $proc.Dispose()
        return $null
    }

    return @{
        Process = $proc
        Queue   = $queue
        Job     = $job
    }
}

function Send-KldbgQuery {
    param(
        [hashtable]$Session,
        [string]$DevicePath
    )

    if ($Session.Process.HasExited) { return $null }

    # Drain stale output
    $dummy = $null
    while ($Session.Queue.TryDequeue([ref]$dummy)) { }

    $Session.Process.StandardInput.WriteLine($DevicePath)
    $Session.Process.StandardInput.Flush()

    $deadline = [DateTime]::Now.AddSeconds(5)
    $idleLimit = [DateTime]::Now.AddMilliseconds(500)
    $gotOutput = $false

    while ([DateTime]::Now -lt $deadline) {
        if ($Session.Process.HasExited) { return $null }

        $line = $null
        if ($Session.Queue.TryDequeue([ref]$line)) {
            $idleLimit = [DateTime]::Now.AddMilliseconds(500)
            if ($line -match '^\[RESULT\] Driver Name:\s*(.+)$') {
                return $Matches[1].Trim()
            }
            if ($line -ne '') {
                $gotOutput = $true
            } elseif ($gotOutput) {
                # Empty line after output = end of response (prompt follows)
                return $null
            }
        } else {
            if ($gotOutput -and [DateTime]::Now -gt $idleLimit) {
                return $null
            }
            Start-Sleep -Milliseconds 10
        }
    }

    return $null
}

function Stop-KldbgSession {
    param([hashtable]$Session)

    if (-not $Session) { return }

    try {
        if (-not $Session.Process.HasExited) {
            $Session.Process.StandardInput.WriteLine("quit")
            $Session.Process.StandardInput.Flush()
        }
    } catch { }

    # Close stdin to ensure child gets EOF and exits
    try { $Session.Process.StandardInput.Close() } catch { }

    # Wait for process to exit
    try {
        if (-not $Session.Process.HasExited) {
            if (-not $Session.Process.WaitForExit(5000)) {
                $Session.Process.Kill()
            }
        }
    } catch { }

    # Cancel async reads before unregistering events / disposing,
    # otherwise Dispose can fire a final event on the dead object
    # and crash the PowerShell host process.
    try { $Session.Process.CancelOutputRead() } catch { }
    try { $Session.Process.CancelErrorRead() } catch { }

    Unregister-Event -SourceIdentifier $Session.Job.Name -ErrorAction SilentlyContinue
    Remove-Job -Id $Session.Job.Id -Force -ErrorAction SilentlyContinue

    try { $Session.Process.Dispose() } catch { }
}

# Step 0d: Try to initialize kldbg interactive session for kernel-level driver mapping
$kldbgSession = $null
$kldbgDriverHits = 0
$kldbgSysHits = 0

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$kldbgExe = Join-Path $scriptDir "dev_map_kldbg.exe"
$kldbgDriverFile = Join-Path $scriptDir "kldbgdrv.sys"

if ((Test-Path $kldbgExe) -and (Test-Path $kldbgDriverFile)) {
    Write-Host "Starting kldbg interactive session..." -ForegroundColor Cyan
    $kldbgSession = Start-KldbgSession -ExePath $kldbgExe -DriverPath $kldbgDriverFile

    if ($kldbgSession) {
        $testResult = Send-KldbgQuery -Session $kldbgSession -DevicePath "\Device\Null"
        if ($testResult -and $testResult -match '\\Driver\\') {
            Write-Host "kldbg session verified (\Device\Null -> $testResult)" -ForegroundColor Green
        } else {
            Write-Host "kldbg test query failed, disabling kldbg" -ForegroundColor Yellow
            Stop-KldbgSession -Session $kldbgSession
            $kldbgSession = $null
        }
    } else {
        Write-Host "Failed to start kldbg session (driver may not be available)" -ForegroundColor Yellow
    }
} else {
    Write-Host "kldbg binaries not found, skipping kernel-level driver mapping" -ForegroundColor DarkGray
}

# Step 1: Get all elements from \GLOBAL??\ directory
Write-Host "Enumerating \GLOBAL??\ directory..." -ForegroundColor Cyan
$globalDir = Get-NtDirectory -Path "\GLOBAL??"
$globalEntries = Get-NtDirectoryEntry -Directory $globalDir
$globalDir.Close()

# Step 2: Filter for symbolic links only
$symlinks = $globalEntries | Where-Object { $_.NtTypeName -eq "SymbolicLink" }
Write-Host "Found $($symlinks.Count) symbolic links in \GLOBAL??\" -ForegroundColor Green

# Step 3: Get all items from \Device\ directory
Write-Host "Enumerating \Device\ directory..." -ForegroundColor Cyan
$deviceDir = Get-NtDirectory -Path "\Device"
$deviceEntries = Get-NtDirectoryEntry -Directory $deviceDir
$deviceDir.Close()

# Filter for actual device objects only (exclude symbolic links and other object types)
$deviceObjects = $deviceEntries | Where-Object { $_.NtTypeName -eq "Device" }
$nonDeviceObjects = $deviceEntries | Where-Object { $_.NtTypeName -ne "Device" }

$allDevices = $deviceObjects | ForEach-Object { "\Device\$($_.Name)" }
Write-Host "Found $($deviceObjects.Count) device objects in \Device\" -ForegroundColor Green
if ($nonDeviceObjects.Count -gt 0) {
    Write-Host "Skipped $($nonDeviceObjects.Count) non-device objects (symlinks, etc.)" -ForegroundColor DarkGray
}

# Step 4: Build a hashtable mapping device targets to their symlinks
Write-Host "Resolving symbolic link targets..." -ForegroundColor Cyan
$deviceToSymlinks = @{}

foreach ($symlink in $symlinks) {
    try {
        $symlinkPath = "\GLOBAL??\$($symlink.Name)"
        $target = Get-NtSymbolicLinkTarget -Path $symlinkPath

        # Check if target is in \Device\ namespace
        if ($target -like "\Device\*") {
            if (-not $deviceToSymlinks.ContainsKey($target)) {
                $deviceToSymlinks[$target] = @()
            }
            $deviceToSymlinks[$target] += $symlinkPath
        }
    }
    catch {
        # Some symlinks may not be accessible, skip them
    }
}

$devicesWithSymlinks = $deviceToSymlinks.Keys.Count
$devicesWithoutSymlinks = $allDevices.Count - $devicesWithSymlinks
Write-Host "Found $devicesWithSymlinks devices with symlinks" -ForegroundColor Green
Write-Host "Found $devicesWithoutSymlinks devices without symlinks" -ForegroundColor Yellow

# Step 5: Build results for all devices
Write-Host "`nBuilding device list with SDDLs..." -ForegroundColor Cyan
if ($kldbgSession) {
    Write-Host "(using kldbg for kernel-level driver identification)" -ForegroundColor Cyan
}
$results = @()
$deviceIndex = 0

foreach ($device in $allDevices) {
    $deviceIndex++
    if ($deviceIndex % 25 -eq 0) {
        Write-Host "  Processing device $deviceIndex / $($allDevices.Count)..." -ForegroundColor DarkGray
    }

    # Get symlinks for this device (joined with spaces), or empty string
    $symlinkList = ""
    if ($deviceToSymlinks.ContainsKey($device)) {
        $symlinkList = $deviceToSymlinks[$device] -join "`n"
    }

    # Get SDDL
    $sddl = ""
    try {
        $sddl = (Get-NtSecurityDescriptor -Path $device).ToSddl()
    }
    catch {
        $sddl = "[Error: $($_.Exception.Message)]"
    }

    # Determine if access is admin-only
    $adminOnly = Test-AdminOnlyAccess -Sddl $sddl

    # Driver identification - try kldbg first (preferred), then PnP
    $driverObjectName = ""
    $driverInf = ""
    $driverDeviceName = ""
    $driverHardwareID = ""
    $driverManufacturer = ""
    $driverSysFiles = ""

    # Preferred method: kldbg kernel-level lookup (\Device\X -> \Driver\Y)
    if ($kldbgSession) {
        $kldbgResult = Send-KldbgQuery -Session $kldbgSession -DevicePath $device
        if ($kldbgResult) {
            $driverObjectName = $kldbgResult
            $kldbgDriverHits++
            $serviceName = $kldbgResult -replace '^\\Driver\\', ''
            if ($serviceToSysPath.ContainsKey($serviceName)) {
                $driverSysFiles = $serviceToSysPath[$serviceName]
                $kldbgSysHits++
            }
        }
    }

    # PnP lookup (supplements with metadata; provides SysFiles if kldbg didn't)
    if ($pnpDriverMap.ContainsKey($device)) {
        $driverInfo = $pnpDriverMap[$device]
        $driverInf = $driverInfo.InfName
        $driverDeviceName = $driverInfo.DeviceName
        $driverHardwareID = $driverInfo.HardwareID
        $driverManufacturer = $driverInfo.Manufacturer
        if (-not $driverSysFiles) {
            $driverSysFiles = $driverInfo.SysFiles
        }
    }

    $results += [PSCustomObject]@{
        DevicePath         = $device
        Symlinks           = $symlinkList
        AdminOnly          = $adminOnly
        DriverSysFiles     = $driverSysFiles
        DriverObjectName   = $driverObjectName
        DriverInf          = $driverInf
        DriverDeviceName   = $driverDeviceName
        DriverHardwareID   = $driverHardwareID
        DriverManufacturer = $driverManufacturer
        SDDL               = $sddl
    }
}

# Step 6: Fallback matching - search .sys files for device name strings (read-only)
Write-Host "`nPerforming fallback .sys file matching for remaining devices..." -ForegroundColor Cyan
$fallbackMatches = 0
$devicesToMatch = $results | Where-Object { $_.DriverSysFiles -eq "" }
$totalToMatch = ($devicesToMatch | Measure-Object).Count
$processed = 0

foreach ($result in $devicesToMatch) {
    $processed++

    # Progress indicator (every 10 devices)
    if ($processed % 10 -eq 0) {
        Write-Host "  Processed $processed / $totalToMatch devices..." -ForegroundColor DarkGray
    }
	
    # Extract device name (remove \Device\ prefix)
    $deviceName = $result.DevicePath -replace '^\\Device\\', ''

    # Skip numeric-only or hex-only names (auto-generated, would cause false positives)
    if ($deviceName -match '^[0-9a-fA-F]+$') {
        continue
    }

    # Search .sys files for device name string (read-only, case-insensitive)
    foreach ($sysFile in $prioritizedSysFiles) {
        try {
            # Select-String is read-only; -Quiet returns boolean for efficiency
            $match = Select-String -Path $sysFile -Pattern $deviceName -SimpleMatch -Quiet -ErrorAction SilentlyContinue
            if ($match) {
                $result.DriverSysFiles = $sysFile
                $fallbackMatches++
                break
            }
        }
        catch {
            # Skip files we can't read
        }
    }
}

Write-Host "Fallback matching found $fallbackMatches additional .sys file matches" -ForegroundColor Green

# Cleanup kldbg session
if ($kldbgSession) {
    Write-Host "`nClosing kldbg session..." -ForegroundColor Cyan
    Stop-KldbgSession -Session $kldbgSession
}

# Step 7: Export to CSV
$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

# Summary
$adminOnlyCount = ($results | Where-Object { $_.AdminOnly -eq "YES" }).Count
$nonAdminCount = ($results | Where-Object { $_.AdminOnly -eq "NO" }).Count
$unknownCount = ($results | Where-Object { $_.AdminOnly -eq "UNKNOWN" }).Count
$withDriverInfo = ($results | Where-Object { $_.DriverInf -ne "" }).Count
$withSysFiles = ($results | Where-Object { $_.DriverSysFiles -ne "" }).Count

Write-Host "`nExported $($results.Count) devices to $OutputFile" -ForegroundColor Green
Write-Host "  Admin-only devices: $adminOnlyCount" -ForegroundColor Cyan
Write-Host "  Non-admin accessible: $nonAdminCount" -ForegroundColor Yellow
Write-Host "  Unknown (errors): $unknownCount" -ForegroundColor DarkGray
Write-Host "  With PnP driver info: $withDriverInfo" -ForegroundColor Magenta
$withDriverObjectName = ($results | Where-Object { $_.DriverObjectName -ne "" }).Count
Write-Host "  With driver object name (kldbg): $withDriverObjectName ($kldbgSysHits resolved to .sys)" -ForegroundColor Magenta
Write-Host "  With SYS file paths: $withSysFiles (kldbg: $kldbgSysHits, PnP: $($withSysFiles - $fallbackMatches - $kldbgSysHits), fallback: $fallbackMatches)" -ForegroundColor Magenta
