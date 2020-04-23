$HealthCheckPath = "\\CM01\HealthCheck$"
$BCMonResultPath = "$HealthCheckPath\BCMonResults"
$ProbeType = "/ProbeMatch"
$ProbeLogfile = "C:\Windows\temp\BCMon-ProbeTest.txt"

#Check Architecture for BCMon
if ([System.Environment]::Is64BitProcess){
    $Architecture = "x64"
} else {
    $Architecture = "x86"
}
$BCMonPath = "$HealthCheckPath\BCMon\$Architecture\bcmon.exe"

If(test-path C:\Windows\temp\BCMon-ProbeTest.txt){
    remove-item C:\Windows\temp\BCMon-ProbeTest.txt -force
}

$Process = Get-Process bcmon -ErrorAction SilentlyContinue
If($Process){
    stop-process -name bcmon -force
}

# Get IPv4 address only
$IPv4 = Get-WmiObject win32_networkadapterconfiguration | Where-Object { $_.IPEnabled -eq $true } | Select -ExpandProperty ipaddress | Select -First 1

# Copy the BCMon.exe utility
Copy-Item -Path $BCMonPath -Destination "C:\Windows\Temp"

# Delete any existing Firewall rule for BCMon 
netsh advfirewall firewall delete rule name="2Pint Software BCMon"

# Create Firewall rule to allow BCMon to run
netsh advfirewall firewall add rule name="2Pint Software BCMon" dir=in action=allow program="C:\Windows\Temp\BCMon.exe" enable=yes

$Cmd = "C:\Windows\System32\cmd.exe"

If(Test-path -Path $ProbeLogfile){Remove-Item $ProbeLogfile -Force }
$Arglist = "/C C:\Windows\temp\BCMon.exe $ProbeType $IPv4 >> $ProbeLogfile"
Start-Process -Filepath $Cmd -Argumentlist $Arglist -NoNewWindow

# Allow probes 10 minutes to connect
start-sleep 600

xcopy $ProbeLogfile "$BCMonResultPath\$IPv4\" /y/i
$Process = Get-Process bcmon -ErrorAction SilentlyContinue
If($Process)
{
stop-process -name bcmon -force
}