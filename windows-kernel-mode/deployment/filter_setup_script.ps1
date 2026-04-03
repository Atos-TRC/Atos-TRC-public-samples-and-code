# The script requires an already existing VHD file named "empty.vhd". 
# Use craft_vhd_empty.py to create one prior to using this script.
param(
    [string] $DriverPath
)
$usage = "@
# ============================================================================
# $DriverPath Proper PnP Upper Disk Filter Setup Script
# Run as Administrator on the target VM
# 
# Takes .sys file, installs a service for it
# Appends the service name to disk UpperFilters
# Mounts VHD using diskpart (triggers device node creation)
# Restores UpperFilters
# ============================================================================

Usage: filter_setup_script.ps1 DriverPath
@"
$log_file="status.txt"
function log_msg
{
    param (
        [string]$log_msg
    )
	$line = "$(Get-Date) - $log_msg"
	$line | Add-Content -Path $log_file
	Write-Host $line
}

if($DriverPath -eq "")
{
	Write-Host $usage
	Exit
}
$DriverName = [System.IO.Path]::GetFileNameWithoutExtension($DriverPath)
log_msg "[*] Setting up $DriverName as a PnP upper disk filter..."

# Step 1: Ensure the driver binary is in the proper location
log_msg "[1] Checking driver binary location..."

if (Test-Path $Env:SystemRoot"\System32\drivers\$DriverName.sys")
{
	log_msg "OK: Driver binary found."
}
else
{
	log_msg "$DriverName.sys not found in $Env:SystemRoot\System32\drivers\. Copying from $DriverPath"
	if(Test-Path $DriverPath)
	{
		Copy-Item "$DriverPath" $Env:SystemRoot"\System32\drivers\$DriverName.sys"
	}
	else
	{
		log_msg "Cannot proceed without $DriverPath."
		Exit
	}
}
# Step 2: Deploy service
log_msg "[2] Creating proper service entry (boot-start, kernel driver)..."
sc.exe create $DriverName type= kernel start= boot error= normal group= Filter binPath= System32\drivers\$DriverName.sys
if ($LASTEXITCODE -ne 0) {
    log_msg "ERROR: Failed to create service entry."
    Exit
}
log_msg "OK: Service entry created."

# Step 3: Start the service
log_msg "[3] Starting $DriverName"
sc.exe start $DriverName

# Step 4: Add $DriverName to the DiskDrive class UpperFilters
# DiskDrive class GUID: {4d36e967-e325-11ce-bfc1-08002be10318}
# UpperFilters is a REG_MULTI_SZ value
log_msg "[5] Registering as disk class upper filter..."

# We need to append $DriverPath to the existing list, not replace it
# Using reg.exe to query first, then add

$path='HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}';

$cur=(Get-ItemProperty -Path $path -Name UpperFilters -ErrorAction SilentlyContinue).UpperFilters;
if($cur -and ($cur -contains $DriverName)){
  log_msg "$DriverName is already in UpperFilters. Skipping." # if there's another entry earlier on that list, starting the same way, would false positive and cause the isntallation to fail
}elseif($cur){
  $cur_extended=$cur+$DriverName;
  Set-ItemProperty -Path $path -Name UpperFilters -Value $cur_extended -Type MultiString;
  log_msg "OK: $DriverName appended to UpperFilters."
}else{
  Set-ItemProperty -Path $path -Name UpperFilters -Value @('partmgr',$DriverPath) -Type MultiString;
  log_msg "OK: UpperFilters created with partmgr + $DriverPath."
}

# Step 5: Invoke VHD mount (empty.vhd)
# First, ensure the drive isn't mounted already (if so, disconnect it first), then mount it
$f=Get-Disk | Where-Object { $_.Location -like "*empty.vhd*" }
if($f) # It is already mounted, we need to get rid of it first
{
	log_msg "empty.vhd already mounted, disconnecting first."
	"select vdisk file=`"$pwd\empty.vhd`"`ndetach vdisk" | Set-Content dp.txt; diskpart /s dp.txt; Remove-Item dp.txt
	log_msg "Done"
}
log_msg "Mounting empty.vhd using diskpart..."
"select vdisk file=`"$pwd\empty.vhd`"`nattach vdisk" | Set-Content dp.txt; diskpart /s dp.txt; Remove-Item dp.txt

# Step 6: Cleanup - restore UpperFilters to the original value
log_msg "Restore: removing $DriverName from UpperFilters (restore original value $cur)."
Set-ItemProperty -Path $path -Name UpperFilters -Value $cur -Type MultiString;
log_msg "Done. To dispose of the stack, just detach the disk."