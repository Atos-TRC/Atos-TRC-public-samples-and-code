param(
	[Parameter(Mandatory=$true)]
    [string]$INFPATH,
    [Parameter(Mandatory=$true)]
    [string]$HWID
)

Import-Module NtObjectManager

function find_symlink_for_device
{
	param (
		[string]$device_path
	)
	$items = ls NtObject:\GLOBAL??\
	foreach ($item in $items) {
		if ($item.IsSymbolicLink) {
			try {
				$target = Get-NtSymbolicLinkTarget "\GLOBAL??\$($item.Name)"
				if ($target -eq $device_path) {
					return $item.Name
				}
			} catch {
				# Skip items we can't read
			}
		}
	}
	return ""
}
function get_devices
{
	$curr_list = ls NtObject:\Device\
	Write-Host "Returning device list ($($curr_list.Length) elements)."
	return $curr_list
}
function Get-ItemsOnlyInB { # list-diff helper
    param (
        [string[]]$ListA,
        [string[]]$ListB,
        [switch]$CaseSensitive
    )
    if ($CaseSensitive) {
        $ListB | Where-Object { $ListA -cnotcontains $_ }
    } else {
        $ListB | Where-Object { $ListA -notcontains $_ }
    }
}

# Get the current list of \Device\ objects
$device_list_before = get_devices

# Deploy driver package
pnputil.exe /add-driver $INFPATH /install
# Create software device
.\devcon.exe install $INFPATH $HWID

# Get the current list of \Device\ objects again
$device_list_after = get_devices
# Compare with previous to report new devices only
$new_devices = Get-ItemsOnlyInB -ListA $device_list_before -ListB $device_list_after

if ($new_devices.Count -gt 0)
{
	$new_devices | ForEach-Object { # checking newly discovered devices
		$device_name = $_
		$device_path = "\Device\$device_name"
		$new_dev = find_symlink_for_device -device_path $device_path
		$SDDL = ""
		try {
			$SDDL = (Get-NtSecurityDescriptor $device_path).ToSddl()
		} catch {
			Write-Host "[WARNING] Could not retrieve SDDL for $device_path" # this will happen frequently
		}
		Write-Host "New device found for $INFPATH $HWID`n $device_path (symlink: $new_dev) $SDDL"
	}
}
