$HealthCheckPath = "\\CM01\HealthCheck$"
$BCMonResultsPath = "$HealthCheckPath\BCMonResults"
$Files = Get-ChildItem -Path $BCMonResultsPath -Filter "*.txt" -Recurse | Select-Object -ExpandProperty FullName

$Result = foreach ($File in $Files) { 
    $FileContent = Get-Content -Path $File 

    $ConnectionType = $FileContent | Select-String -SimpleMatch -Pattern "Connection Type"
    $ConnectionType = $ConnectionType -split (":",2) | select -last 1
    
    $SearchString2 = "Unicast BranchCache"
    if ($FileContent -match $SearchString2 ) { 
        $IP = Split-Path (Split-Path "$File" -Parent) -Leaf
        $SEP = $IP.lastindexof(".") 
        $subnet = "$($ip.substring(0,$sep)).0"
        Write-Output "$subnet, $IP, OK, $SearchString2,$ConnectionType"
    }
    Else{
        $SearchString3 = "Incoming 2Pint PeerDist"
        if ($FileContent -match $SearchString3 ){
        $IP = Split-Path (Split-Path "$File" -Parent) -Leaf
        $SEP = $IP.lastindexof(".") 
        $subnet = "$($ip.substring(0,$sep)).0"
        Write-Output "$subnet, $IP, OK, $SearchString3,$ConnectionType"
        }
        Else{
            $SEP = $IP.lastindexof(".") 
            $subnet = "$($ip.substring(0,$sep)).0"
            Write-Output "$subnet, $IP, NOT OK, NA,$ConnectionType"
        }
            
    }
} 

$Result | Out-File "$HealthCheckPath\BCMonSummaryReport.csv"

