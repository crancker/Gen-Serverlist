This is a simple Powershell script to discover Microsoft Windows based machines within an IP address range and generate a simple yet useful serverlist.

Usage:

./Gen-ServerList.ps1  
Start IP: -First IP of the range.  
End IP: -Last IP of the range.  


Requirement - Powershell 3.0  
The script must be run from a central machine which is able to reach server in the IP range specified by you.  
Found.csv is appended. Please delete the file before running the script to avoid duplicated information.  
Installed software list gathering works only if the WINRM is configured on the remote Windows servers.  
