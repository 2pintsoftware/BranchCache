$SiteServer= "CM01"
$DatabaseServer= "CM01"
$Database = "CM_PS1"
$Query= $("with T1 as(SELECT (PARSENAME(b.IPAddress,4)+'.'+PARSENAME(b.IPAddress,3)+'.'+PARSENAME(b.IPAddress,2)) as subnet, s.Netbios_Name0, b.IPAddress FROM vSMS_R_System as s INNER JOIN BGB_ResStatus as b on b.ResourceID = s.ItemKey WHERE b.OnlineStatus = '1'), limit as(select COUNT(SUBNET) as TOTAL, SUBNET from T1 group by subnet ),t2 as(select T1.Subnet, t1.IPAddress, t1.Netbios_Name0, ROW_NUMBER() OVER (Partition by T1.Subnet ORDER BY T1.IPaddress DESC) as rn from T1 ) Select T2.Subnet , T2.IPAddress , t2.Netbios_Name0 from t2    left outer join limit on limit.subnet = t2.subnet where rn <= 4 and limit.TOTAL >= 4 ")

# Run SQL Query
$Datatable = New-Object System.Data.DataTable
$Connection = New-Object System.Data.SQLClient.SQLConnection
$Connection.ConnectionString = "server='$DatabaseServer';database='$Database';trusted_connection=true;"
$Connection.Open()
$Command = New-Object System.Data.SQLClient.SQLCommand
$Command.Connection = $Connection
$Command.CommandText = $Query
$Reader = $Command.ExecuteReader()
$Datatable.Load($Reader)
$Connection.Close()

#Region helperfunctions
function Get-CMModule
#This function gets the configMgr module
{
    [CmdletBinding()]
    param()
    Try
    {
        Write-Verbose "Attempting to import SCCM Module"
        #Retrieves the fcnction from ConfigMgr installation path. 
        Import-Module (Join-Path $(Split-Path $ENV:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1) -Verbose:$false
        Write-Verbose "Succesfully imported the SCCM Module"
    }
    Catch
    {
        Throw "Failure to import SCCM Cmdlets."
    } 
}

function Test-ConfigMgrAvailable
#Tests if ConfigMgr is availble so that the SMSProvider and configmgr cmdlets can help. 
{
    [CMdletbinding()]
    Param
    (
        [Parameter(Mandatory = $false)]
        [bool]$Remediate
    )
        try
        {
            if((Test-Module -ModuleName ConfigurationManager -Remediate:$true) -eq $false)
            #Checks to see if the Configuration Manager module is loaded or not and then since the remediate flag is set automatically imports it.
            { 
                throw "You have not loaded the configuration manager module please load the appropriate module and try again."
                #Throws this error if even after the remediation or if the remediation fails. 
            }
            write-Verbose "ConfigurationManager Module is loaded"
            Write-Verbose "Checking if current drive is a CMDrive"
            if((Get-location -Verbose:$false).Path -ne (Get-location -PSProvider 'CmSite' -Verbose:$false).Path)
            #Checks if the current location is the - PS provider for the CMSite server. 
            {
                Write-Verbose -Message "The location is NOT currently the CMDrive"
                if($Remediate)
                #If the remediation field is set then it attempts to set the current location of the path to the CMSite server path. 
                    {
                        Write-Verbose -Message "Remediation was requested now attempting to set location to the the CM PSDrive"
                        Set-Location -Path (((Get-PSDrive -PSProvider CMSite -Verbose:$false).Name) + ":") -Verbose:$false
                        Write-Verbose -Message "Succesfully connected to the CMDrive"
                        #Sets the location properly to the PSDrive.
                    }

                else
                {
                    throw "You are not currently connected to a CMSite Provider Please Connect and try again"
                }
            }
            write-Verbose "Succesfully validated connection to a CMProvider"
            return $true
        }
        catch
        {
            $errorMessage = $_.Exception.Message
            write-error -Exception CMPatching -Message $errorMessage
            return $false
        }
}

function Test-Module
#Function that is designed to test a module if it is loaded or not. 
{
    [CMdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [String]$ModuleName,
        [Parameter(Mandatory = $false)]
        [bool]$Remediate
    )
    If(Get-Module -Name $ModuleName)
    #Checks if the module is currently loaded and if it is then return true.
    {
        Write-Verbose -Message "The module was already loaded return TRUE"
        return $true
    }
    If((Get-Module -Name $ModuleName) -ne $true)
    #Checks if the module is NOT loaded and if it's not loaded then check to see if remediation is requested. 
    {
        Write-Verbose -Message "The Module was not already loaded evaluate if remediation flag was set"
        if($Remediate -eq $true)
        #If the remediation flag is selected then attempt to import the module. 
        {
            try 
            {
                    if($ModuleName -eq "ConfigurationManager")
                    #If the module requested is the Configuration Manager module use the below method to try to import the ConfigMGr Module.
                    {
                        Write-Verbose -Message "Non-Standard module requested run pre-written function"
                        Get-CMModule
                        #Runs the command to get the COnfigMgr module if its needed. 
                        Write-Verbose -Message "Succesfully loaded the module"
                        return $true
                    }
                    else
                    {
                    Write-Verbose -Message "Remediation flag WAS set now attempting to import module $($ModuleName)"
                    Import-Module -Name $ModuleName
                    #Import  the other module as needed - if they have no custom requirements.
                    Write-Verbose -Message "Succesfully improted the module $ModuleName"
                    Return $true
                    }
            }
            catch 
            {
                Write-Error -Message "Failed to import the module $($ModuleName)"
                Set-Location $StartingLocation
                break
            }
        }
        else {
            #Else return the fact that it's not applicable and return false from the execution.
            {
                Return $false
            }
        }
    }
}
#endregion HelperFunctions

# Connect to the Site Server
if(!(Test-ConfigMgrAvailable -Remediate:$true)){
    Write-Log -Message "We were unable to load the ConfigMgr Cmdlets and unable to connect to the CM provider will now exit." -LogLevel 3
    break  
    }


# Run ProbeMatch Script on all ProbeMatch Clients (odd row numbers)
$ScriptName = "Run BCMon ProbeMatch"
$ScriptGuid = (Get-CMScript -ScriptName $ScriptName -Fast).ScriptGuid

$count = 0
Foreach ($Row in $Datatable){

    $count++
    
    if($count%2 -eq 0 ){ 
        # Do Nothing
    } 
    else { 
        write-host "$($ScriptName) on $($Row.Netbios_Name0) in subnet $($Row.subnet).0 "
        $CMDevice = Get-CMDevice -Name $Row.Netbios_Name0 -Fast

        Invoke-CMScript -Device $CMDevice -ScriptGuid $ScriptGuid
    } 

}

Write-Host ""
Write-Host "Waiting 60 seconds before starting ProbeV2..."
Write-Host ""
Start-Sleep -Seconds 60


# Run ProbeV2 Script on all ProbeV2 Clients (even row numbers)
$ScriptName = "Run BCMon ProbeV2"
$ScriptGuid = (Get-CMScript -ScriptName $ScriptName -Fast).ScriptGuid

$count = 0
Foreach ($Row in $Datatable){

    $count++
    
    if($count%2 -eq 0 ){ 
        write-host "$($ScriptName) on $($Row.Netbios_Name0) in subnet $($Row.subnet).0 "
        $CMDevice = Get-CMDevice -Name $Row.Netbios_Name0 -Fast

        Invoke-CMScript -Device $CMDevice -ScriptGuid $ScriptGuid

    } 
    else { 
        # Do Nothing
    } 

}






