<#

.SYNOPSIS
This is a simple Powershell script to discover Microsoft Windows based machines within an IP address range and generate a simple yet useful serverlist.

.DESCRIPTION
This is a simple Powershell script to discover Microsoft Windows based machines within an IP address range and generate a simple yet useful serverlist.

Created by Tamas Gocza
Email: Tamas.Gocza@hu.ibm.com

.EXAMPLE
./Gen-ServerList.ps1
Start IP: -First IP of the range.
End IP: -Last IP of the range.
.NOTES
Requirement - Powershell 3.0
The script must be run from a central machine which is able to reach server in the IP range specified by you.
Found.csv is appended. Please delete the file before running the script to avoid duplicated information.
Installed software list gathering works only if the WINRM is configured on the remote Windows servers.

#>

#get server info
function Get-OS {
    [CmdletBinding()]
    [Alias()]
    Param
    (
        [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    ValuefromPipeline=$true,
                    Position=0)]
        [string[]]$ComputerName
    )

    Begin
    {
    }
    Process
    {
        
        foreach ($Computer in $ComputerName) {
		$error.clear()
		try{
			$compinfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computer
			$RemBiosInfo = Get-WmiObject -Class win32_bios -ComputerName $Computer
			$RemoteMacAddress = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $Computer 
			$InstalledSW = Invoke-Command -cn $Computer -ScriptBlock {Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*}
			$ActualList = ""
			foreach ($DisplayedName in $InstalledSW.DisplayName){$ActualList = ("$ActualList" + "$DisplayedName" + "; ") -join "`n"}
            $OSInfo = Get-WmiObject win32_OperatingSystem -ComputerName $Computer
            $findings = $OSInfo | Select-Object -Property @{Name="ComputerName";expression={$_.__SERVER}},@{Name="IP Address";expression={$ip}},@{Name="MACAddress";expression={($RemoteMacAddress | where { $_.IpAddress -eq $ip}).MACAddress}},@{Name="FQDN";expression={([System.Net.Dns]::GetHostByName("$Computer").Hostname)}},@{Name="OS Name";expression={$_.Caption}},@{Name="ServicePack";expression={$_.ServicePackMajorVersion}},@{Name="Architecture";expression={$_.OSArchitecture}},Version,OperatingSystemSKU,@{Name='InstallDate';expression={$_.ConvertToDateTime($_.InstallDate)}},@{Name="Domain";expression={$Compinfo.Domain}},@{Name="Manufacturer";expression={$Compinfo.Manufacturer}},@{Name="Model";expression={$Compinfo.Model}},@{Name="Serialnumber";expression={$RemBiosInfo.Serialnumber}},@{Name="TotalPhysicalMemory (GB)";expression={([math]::round($Compinfo.TotalPhysicalMemory /1GB, 3))}},@{Name="InstalledSW";expression={$ActualList}}
			$findings | export-csv ./found.csv -useculture -NoTypeInformation -Append
			
			}
			catch{""}
			}
			
    }
    End
    {
    }
    }
	

#ip address module part
$start = read-host "Start IP"
$finish = read-host "End IP"
$ip1 = ([System.Net.IPAddress]$start).GetAddressBytes()
[Array]::Reverse($ip1)
$ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address

$ip2 = ([System.Net.IPAddress]$finish).GetAddressBytes()
[Array]::Reverse($ip2)
$ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

for ($x=$ip1; $x -le $ip2; $x++) {
$ip_ = ([System.Net.IPAddress]$x).GetAddressBytes()
[Array]::Reverse($ip_)
$iprange = $ip_ -join '.'

foreach ($ip in $iprange){
$error.clear()
try { 
if (Test-Connection -comp $ip -count 1 -quiet){
$result = [System.Net.Dns]::GetHostEntry($ip)
$hostname = [String]$result.HostName
Get-OS -ComputerName $hostname
}
}
catch { ""}
}
}


