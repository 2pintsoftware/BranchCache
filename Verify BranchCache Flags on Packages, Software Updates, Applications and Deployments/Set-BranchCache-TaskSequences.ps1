<#
.SYNOPSIS
    This script is used to enable, disable, and get BranchCache information about TaskSequences in the environment

    When run in Gather Mode - The script returns a count of the TaskSequence deployments that are NOT branchCache enabled.
    
    When run in Enable mode - The script enables TaskSequence deployments for BranchCache.

    When run in Disable mode the script disables TaskSequences deployments for BranchCachee.

.DESCRIPTION
    This script is used to enable, disable, and get BranchCache information about TaskSequences in the environment
     
.NOTES
    This script is used to enable, disable, and get BranchCache information about TaskSequences in the environment
    Just edit the Sitecode, mode, and optional application name (wild card is supported)

    This script was mostly 'stolen with pride' from examples all over the place but specific thanks to @NickolajA, @david_obrien and @merlin_with_a_j !
    
    Use at your own risk - and test it first!

    Be aware that updating deployments will trigger a policy update.

    FileName: Set-BranchCache-Packages.ps1
    Authors: Phil Wilcock, Jordan Benzing, and Johan Arwidmark ('Stolen with pride' by Maik Koster)
    Contact: @2PintSoftware
    Created: 2022-01-14
    Modified: 2022-01-14

    Version - 0.0.0 - (UNKNOWN)
    Version - 0.1.0 - (14-JANUARY-2022)
        COMPLETED: Converted copy of Set-BranchCachePackages to work with Task Sequences (Maik Koster)
    

.PARAMETER SiteServer
    This parameter is a string and is designed to only accept the name of the ConfigMgr site server. This information is
    then used to gather the other required information. 

.PARAMETER Mode
    This parameter is a string parameter and requires you to pick from a validation set. The available modes are:
        Gather - Only returns the information about the not BranchCache enabled TaskSequences
        Enable - Enables the TaskSequence deplyoments that are not using it.
        Disable - Disables all of them. 

.EXAMPLE
     .\Set-BranchCache-TaskSequences.PS1 -siteServer "ServerName" -Mode Gather

     This example would gather all of the TaskSequence deployments that are not currently BranchCache enabled. 

.EXAMPLE
    .\Set-BranchCache-TaskSequences.PS1 -siteServer "ServerName" -Mode Enable

    This example would gather all TaskSequences deployments that are not BranchCache enabled and then enable them. Caution enabling this.

.EXAMPLE
    .\Set-BranchCache-TaskSequences.PS1 -siteServer "ServerName"

    This example would gather all of the TaskSequence deployments that are not currently BranchCache enabled.

#>

[cmdletbinding()]
param(
    [Parameter(HelpMessage = "Please enter the name of your site server" , Mandatory = $true )]
    [string]$SiteServer,
    [Parameter(HelpMessage = "This option allows you to enable BranchCache for all task sequences. By Default we only return the BranchCache enabled task sequences.",Mandatory = $false)]
    [ValidateSet('Enable','Gather','Disable')]
    [string]$Mode = "Gather",
    [Parameter(HelpMessage = "This option allows you to enable BranchCache for a specific task sequence.",Mandatory = $false)]
    [Alias("TSName")]
    [string]$TaskSequenceName
)

begin{
#Region helperfunctions
    function Get-CMModule {
        #This function gets the configMgr module
        [CmdletBinding()]
        param()

        try {
            Write-Verbose "Attempting to import SCCM Module"
            Import-Module (Join-Path $(Split-Path $ENV:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1) -Verbose:$false
            Write-Verbose "Succesfully imported the SCCM Module"
        } catch {
            Throw "Failure to import SCCM Cmdlets."
        } 
    }
    
    function Test-ConfigMgrAvailable {
        #Tests if ConfigMgr is availble so that the SMSProvider and configmgr cmdlets can help. 
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $false)]
            [bool]$Remediate
        )

        try {
            #Check to see if the Configuration Manager module is loaded or not and then since the remediate flag is set automatically imports it.
            if ((Test-Module -ModuleName ConfigurationManager -Remediate:$true) -eq $false) {
                throw "You have not loaded the configuration manager module please load the appropriate module and try again."
                #Throws this error if even after the remediation or if the remediation fails. 
            }
            Write-Verbose "ConfigurationManager Module is loaded"
            Write-Verbose "Checking if current drive is a CMDrive"
            if ((Get-Location -Verbose:$false).Path -ne (Get-location -PSProvider 'CmSite' -Verbose:$false).Path) {
                #Checks if the current location is the - PS provider for the CMSite server. 
                Write-Verbose -Message "The location is NOT currently the CMDrive"
                if ($Remediate) {
                    Write-Verbose -Message "Remediation was requested now attempting to set location to the the CM PSDrive"
                    Set-Location -Path (((Get-PSDrive -PSProvider CMSite -Verbose:$false).Name) + ":") -Verbose:$false
                    Write-Verbose -Message "Succesfully connected to the CMDrive"
                } else {
                    throw "You are not currently connected to a CMSite Provider Please Connect and try again"
                }
            }
            Write-Verbose "Succesfully validated connection to a CMProvider"
            return $true
        } catch {
            $errorMessage = $_.Exception.Message
            Write-Error -Exception CMPatching -Message $errorMessage
            return $false
        }
    }
    
    function Test-Module {
        #Function that is designed to test a module if it is loaded or not. 
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [String]$ModuleName,
            [Parameter(Mandatory = $false)]
            [bool]$Remediate
        )

        if (Get-Module -Name $ModuleName) {
            Write-Verbose -Message "The module was already loaded return TRUE"
            return $true
        } else {
            Write-Verbose -Message "The Module was not already loaded evaluate if remediation flag was set"
            if($Remediate -eq $true) {
                try {
                    if($ModuleName -eq "ConfigurationManager") {
                        Write-Verbose -Message "Non-Standard module requested run pre-written function"
                        Get-CMModule
                        #Runs the command to get the COnfigMgr module if its needed. 
                        Write-Verbose -Message "Succesfully loaded the module"
                        return $true
                    } else {
                        Write-Verbose -Message "Remediation flag WAS set now attempting to import module $($ModuleName)"
                        Import-Module -Name $ModuleName
                        #Import  the other module as needed - if they have no custom requirements.
                        Write-Verbose -Message "Succesfully improted the module $ModuleName"
                        Return $true
                    }
                } catch {
                    Write-Error -Message "Failed to import the module $($ModuleName)"
                    Set-Location $StartingLocation
                    break
                }
            } else {
                Return $false
            }
        }
    }
    #endregion HelperFunctions

    #region LogFunctions

    Function Start-Log {
        #Set global variable for the write-log function in this session or script.
        [CmdletBinding()]
        param (
            #[ValidateScript({ Split-Path $_ -Parent | Test-Path })]
            [string]$FilePath
        )

        try {
            if (!(Split-Path $FilePath -Parent | Test-Path)) {
                New-Item (Split-Path $FilePath -Parent) -Type Directory | Out-Null
            }
            #Confirm the provided destination for logging exists if it doesn't then create it.
            if (!(Test-Path $FilePath)) {
                ## Create the log file destination if it doesn't exist.
                New-Item $FilePath -Type File | Out-Null
            }
            ## Set the global variable to be used as the FilePath for all subsequent write-log
            ## calls in this session
            $global:ScriptLogFilePath = $FilePath
        } catch {
            #In event of an error write an exception
            Write-Error $_.Exception.Message
        }
    }
     
    Function Write-Log {
        #Write the log file if the global variable is set
        param (
            [Parameter(Mandatory = $true)]
            [string]$Message,
            [Parameter()]
            [ValidateSet(1, 2, 3)]
            [string]$LogLevel=1,
            [Parameter(Mandatory = $false)]
            [bool]$writetoscreen = $true   
        )

        $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
        $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
        $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
        $Line = $Line -f $LineFormat
        [system.GC]::Collect()
        Add-Content -Value $Line -Path $global:ScriptLogFilePath
        if($writetoscreen) {
            switch ($LogLevel) {
                '1'{
                    Write-Verbose -Message $Message
                    }
                '2'{
                    Write-Warning -Message $Message
                    }
                '3'{
                    Write-Error -Message $Message
                    }
                Default {
                }
            }
        }

        if($writetolistbox -eq $true) {
            $result1.Items.Add("$Message")
        }
    }
     
    function set-DefaultLogPath {
        #Function to set the default log path if something is put in the field then it is sent somewhere else. 
        [CmdletBinding()]
        param (
            [parameter(Mandatory = $false)]
            [bool]$defaultLogLocation = $true,
            [parameter(Mandatory = $false)]
            [string]$LogLocation
        )

        if ($defaultLogLocation) {
            $LogPath = Split-Path $script:MyInvocation.MyCommand.Path
            $LogFile = "$($($script:MyInvocation.MyCommand.Name).Substring(0,$($script:MyInvocation.MyCommand.Name).Length-4)).log"		
            Start-Log -FilePath $($LogPath + "\" + $LogFile)
        } else  {
            $LogPath = $LogLocation
            $LogFile = "$($($script:MyInvocation.MyCommand.Name).Substring(0,$($script:MyInvocation.MyCommand.Name).Length-4)).log"		
            Start-Log -FilePath $($LogPath + "\" + $LogFile)
        }
    }
  
#endregion LogFunctions
}

process{
    Set-DefaultLogPath
    $StartingLocation = Get-Location
    # Set BitValue to detect BranchCache
    $BrachCacheBitValue = 65536 #0x00010000
    if (!(Test-ConfigMgrAvailable -Remediate:$true)) {
        Write-Log -Message "We were unable to load the ConfigMgr Cmdlets and unable to connect to the CM provider. Exiting ..." -LogLevel 3
        Set-Location -Path $StartingLocation
        break  
    }

    Write-Log -Message "The '$($Mode)' option was selected" -LogLevel 1
    Write-Log -Message "Now retrieving the task sequence deployments and analyzing them"
    if($TaskSequenceName){
        Write-Log -Message "You have selected to only process the task sequence '$($TaskSequenceName)' "
        $TaskSequences = Get-CMTaskSequence -Verbose:$False -Name $TaskSequenceName -Fast
        if($TaskSequences -eq $null){
            Write-Log -Message "The task sequence was not found. Exiting ..." -LogLevel 3
            Set-Location -Path $StartingLocation
            break
        }
        foreach ($object in $TaskSequences) {
            Write-Log -Message "Found $($Object.Name) with ID - $($Object.PackageID)"
        }
        $Advertisements = $TaskSequences | Foreach-Object {Get-CMTaskSequenceDeployment -Fast -Verbose:$false -TaskSequenceID $_.PackageID}
        if($Advertisements -eq $null){
            Write-Log -Message "You have selected a task sequence that does not have any applicable advertisements. Exiting..." -LogLevel 3
            Set-Location -Path $StartingLocation
            break
        }
    } else {
        Write-Log -Message "You have selected to process all task sequences with deployments" -LogLevel 1
        $TaskSequences = Get-CMTaskSequence -Verbose:$False -fast
        $Advertisements = Get-CMTaskSequenceDeployment -Fast -Verbose:$false | Sort-Object $_.PackageID
        if($Advertisements -eq $null){
            Write-Log -Message "There are no task sequences that have applicable advertisments. Exiting..." -LogLevel 3
            Set-Location -Path $StartingLocation
            break
        }
    }

    $BranchCacheInfo = New-Object System.Collections.ArrayList($null)
    ForEach ($Advertisement in $Advertisements) {
        [int]$currentItem = [array]::indexof($Advertisements,$Advertisement)
        $TaskSequence = $TaskSequences | Where-Object {$_.PackageID -eq $Advertisement.PackageID}
        Write-Log -Message "Now processing $($CurrentItem + 1)/$($Advertisements.Count) - '$($TaskSequence.Name)' ($($Advertisement.PackageID)) - DeploymentID:$($Advertisement.AdvertisementID)"
        $Info = [ordered]@{
            BranchCacheState = ($Advertisement.AdvertFlags -band $BrachCacheBitValue)/$BrachCacheBitValue
            DeploymentID = $Advertisement.AdvertisementID
            CollectionID = $Advertisement.CollectionID
            PackageID = $Advertisement.PackageID
            TaskSequenceName = $TaskSequence.Name
        }
        $NewBranchCacheInfo = New-Object PSObject -Property $Info
        $BranchCacheInfo.Add($NewBranchCacheInfo) | Out-Null
        
        if($NewBranchCacheInfo.BranchCacheState -eq '0'){
            if (($Mode -ieq "Gather") -or ($Mode -ieq "Disable")) {
                Write-Log -message "The deployment $($Advertisement.AdvertisementID) for task sequence '$($NewBranchCacheInfo.TaskSequenceName)' is not enabled for BranchCache"
            } elseif ($Mode -ieq "Enable") {
                Write-Log -message "Enabling the deployment $($Advertisement.AdvertisementID) for task sequence '$($NewBranchCacheInfo.TaskSequenceName)' for BranchCache"
                # Need to fall back to plain WMI and handling the flags ourselves, as the Set-CMTaskSequenceDeployment contains a bug 
                # where AllowSharedContent does not set the correct flag.
                # Make sure the Advertisement is still up-to-date
                $Advertisement.Get()
                # Set the new AdvertFlags
                $Advertisement.AdvertFlags = $Advertisement.AdvertFlags -bor $BrachCacheBitValue
                $Advertisement.Put()

                # Keep correct command in case the Bug gets fixed
                #Set-CMTaskSequenceDeployment -CollectionID $Advertisement.CollectionID -TaskSequencePackageId $Advertisement.PackageId -AllowSharedContent $true -Verbose:$false
            }
        } else {
            if (($Mode -ieq "Gather") -or ($Mode -ieq "Enable")) {
                Write-Log -message "The deployment $($Advertisement.AdvertisementID) for task sequence '$($NewBranchCacheInfo.TaskSequenceName)' is enabled for BranchCache"
            } elseif ($Mode -ieq "disable"){
                Write-Log -message "Disabling the deployment $($Advertisement.AdvertisementID) for task sequence '$($NewBranchCacheInfo.TaskSequenceName)' for BranchCache"
                # Need to fall back to plain WMI and handling the flags ourselves, as the Set-CMTaskSequenceDeployment contains a bug 
                # where AllowSharedContent does not set the correct flag.
                # Make sure the Advertisement is still up-to-date
                $Advertisement.Get()
                # Set the new AdvertFlags
                $Advertisement.AdvertFlags = $Advertisement.AdvertFlags -band -bnot $BrachCacheBitValue
                $Advertisement.Put()

                # Keep correct command in case the Bug gets fixed
                # Set-CMTaskSequenceDeployment -CollectionID $Advertisement.CollectionID -TaskSequencePackageId $Advertisement.PackageId -AllowSharedContent $false -Verbose:$false
            }
        }
    }

    if($Mode -ieq "Gather"){
        Write-Log -Message "Total of $($BranchCacheInfo.Count) Task Sequence Deployments" -LogLevel 1 
        write-log -Message "$($Count = ($BranchCacheInfo | Where-Object {$_.BranchCacheState -eq '0'}).Count; if($Count -eq $null){$Count = "1";$Count}else{$Count}) Deployments are NOT BranchCache enabled"
        Write-Log -Message "$($Count = ($BranchCacheInfo | Where-Object {$_.BranchCacheState -eq '1'}).Count; if($Count -eq $null){$Count = "1";$Count}else{$count}) Deployments ARE Enabled"
        Write-Log -Message "Finalized the information. Returning the task sequence deployments that need to be processed to the screen."
        Write-OutPut -InputObject $($BranchCacheInfo | Where-Object {$_.BranchCacheState -eq '0'} | ft )
    }

    Set-Location -Path $StartingLocation
}