<#
.SYNOPSIS
    This script is used to enable, disable, and get BranchCache information about the number of software update deployments in the environment.
    
    When run in Gather Mode - The script returns a count of the update deployments that are NOT BranchCache enabled.
    
    When run in ENABLE mode - The script enables ALL update deployments for BranchCache.

    When run in Disable mode the script DISABLES all update deployments for BranchCache.

.DESCRIPTION
    This script is used to enable, disable, and get BranchCache information about software update deployments in the environment.
    It enable BranchCache for all future deployments that are created by the currently existing ADRS. 

.NOTES
    This script is used to enable, disable, and get BranchCache information about software update deployments in the environment.
    
    This script was mostly 'stolen with pride' from examples all over the place but specific thanks to
    @NickolajA, @david_obrien and @merlin_with_a_j !
        
    Use at your own risk - and test it first!
    
    Be aware that updating deployments will trigger a policy update.

    FileName: Set-BranchCache-SoftwareUpdates.ps1
    Authors: Phil Wilcock, Jordan Benzing, and Johan Arwidmark
    Contact: @2PintSoftware
    Created: 2019-07-02
    Modified: 2019-07-02

    Version - 0.0.0 - (UNKNOWN)
    Version - 0.1.0 - (03-JULY-2019)
                      COMPLETED: Added in function and helper logic for all of the logging functions
                      COMPLETED: Added in switch logic for the Enable Disable and Gather steps
                      COMPLETED: Basic Functionality Check
                      COMPLETED: Create functional Progress Bars to track (Spends a LONG time on these steps where you don't know what its doing)
                      COMPLETED: Clean up script logging as we go along
                      COMPLETED: Updated the Parameter and example information
                      COMPLETED: Forgot to Add the Input object from the Loops.
                      COMPLETED: Add Warning Message before making changes

                      

.PARAMETER SiteServer
    This parameter is a string and is designed to only accept the name of the ConfigMgr site server. This information is
    then used to gather the other required information. 

.PARAMETER Mode
    This parameter is a string parameter and requires you to pick from a validation set. The available modes are:
        Gather - Only returns the information about the not BranchCache enabled software updates
        Enable - Enables the updates that are not using it.
        Disable - Disables all of them. 

.EXAMPLE
    .\Set-BranchCache-SoftwareUpdates.PS1 -siteServer "ServerName"

    This example would gather all deployments that are not BranchCache enabled for software updates 

.EXAMPLE
     .\Set-BranchCache-SoftwareUpdates.PS1 -siteServer "ServerName" -Mode Gather

     This example would gather all deployments that are not BranchCache enabled for software updates 

.EXAMPLE
    .\Set-BranchCache-SoftwareUpdates.PS1 -siteServer "ServerName" -Mode Enable

    This example would gather all deployments that are not BranchCache enabled for software updates and ENABLE them

.EXAMPLE
     .\Set-BranchCache-SoftwareUpdates.PS1 -siteServer "ServerName" -Mode Disable

     This example would gather all deployments that are not BranchCache enabled for software updates and DISABLE them
#>

[cmdletbinding()]
param(
    [Parameter(HelpMessage = "Please enter the name of your site server" , Mandatory = $true )]
    [string]$SiteServer,
    [Parameter(HelpMessage = "This option allows you to enable BranchCache for all packages. By Default we only return the BranchCache enabled packages.",Mandatory = $false)]
    [ValidateSet('Enable','Gather','Disable')]
    [string]$Mode = "Gather"
)

begin{
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

#region LogFunctions

Function Start-Log
#Set global variable for the write-log function in this session or script.
{
         [CmdletBinding()]
         param (
         #[ValidateScript({ Split-Path $_ -Parent | Test-Path })]
         [string]$FilePath
          )
         try
              {
                    if(!(Split-Path $FilePath -Parent | Test-Path))
                    {
                         New-Item (Split-Path $FilePath -Parent) -Type Directory | Out-Null
                    }
                    #Confirm the provided destination for logging exists if it doesn't then create it.
                    if (!(Test-Path $FilePath))
                         {
                             ## Create the log file destination if it doesn't exist.
                             New-Item $FilePath -Type File | Out-Null
                         }
                         ## Set the global variable to be used as the FilePath for all subsequent write-log
                         ## calls in this session
                         $global:ScriptLogFilePath = $FilePath
              }
         catch
         {
               #In event of an error write an exception
             Write-Error $_.Exception.Message
         }
}
     
Function Write-Log
#Write the log file if the global variable is set
{
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
          if($writetoscreen)
          {
             switch ($LogLevel)
             {
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
          if($writetolistbox -eq $true)
          {
             $result1.Items.Add("$Message")
         }
}
     
function set-DefaultLogPath
{
          #Function to set the default log path if something is put in the field then it is sent somewhere else. 
          [CmdletBinding()]
          param
          (
               [parameter(Mandatory = $false)]
               [bool]$defaultLogLocation = $true,
               [parameter(Mandatory = $false)]
               [string]$LogLocation
          )
          if($defaultLogLocation)
          {
               $LogPath = Split-Path $script:MyInvocation.MyCommand.Path
               $LogFile = "$($($script:MyInvocation.MyCommand.Name).Substring(0,$($script:MyInvocation.MyCommand.Name).Length-4)).log"		
               Start-Log -FilePath $($LogPath + "\" + $LogFile)
          }
          else 
          {
               $LogPath = $LogLocation
               $LogFile = "$($($script:MyInvocation.MyCommand.Name).Substring(0,$($script:MyInvocation.MyCommand.Name).Length-4)).log"		
               Start-Log -FilePath $($LogPath + "\" + $LogFile)
          }
}
  
#endregion LogFunctions
}

process{
    set-DefaultLogPath
    Write-Log -Message "Now starting all logs for the duration of the script" -LogLevel 1
    $StartingLocation = Get-Location
    Write-Log -Message "Set the starting location and stored it to return" -LogLevel 1
    Write-Log -Message "Now Confirming that ConfigMgr is available and if it's not we will error out" -LogLevel 1
    if(!(Test-ConfigMgrAvailable -Remediate:$true)){
    Write-Log -Message "We were unable to load the ConfigMgr Cmdlets and unable to connect to the CM provider will now exit." -LogLevel 3
    break  
    }
    #Deal with the fast warnings
    $CMPSSuppressFastNotUsedCheckStartState = $CMPSSuppressFastNotUsedCheck
    $CMPSSuppressFastNotUsedCheck = $true

    #Run if the Gather Option is called
    if($Mode -ieq "Gather"){
        Write-Log -Message "Now retrieving the BranchCache enabled deployments" -LogLevel 1
        $BCEnabledDeployments = Get-CMSoftwareUpdateDeployment -Verbose:$false | Where-Object { $_.UseBranchCache -eq $true }| Select-Object AssignmentName
        Write-Log -Message "Now retrieving the BranchCache disabled deployments"
        $BCDisabledDeployments = Get-CMSoftwareUpdateDeployment -Verbose:$false | Where-Object { $_.UseBranchCache -eq $false } | Select-Object AssignmentName
        Write-Log -Message "Total Software Updates Deployments:  $($BCEnabledDeployments.Count + $BCDisabledDeployments.count)"
        Write-Log -Message "BranchCache Enabled Software Updates Deployments: $($BCEnabledDeployments.Count)"
        Write-Log -Message "BranchCache Disabled Software Updates Deployments: $($BCDisabledDeployments.Count)"
        Set-Location -Path $StartingLocation
    }
    #Fun if the Enable Option is called
    if($Mode -ieq "Enable"){
        Write-Log -Message "Now preparing to ENABLE the software update groups for BranchCache deployment."
        $CMSUPDeployments = Get-CMSoftwareUpdateDeployment -Verbose:$false | Where-Object {$_.UseBranchCache -eq $false}
        $CMSUPADRS = Get-CMSoftwareUpdateAutoDeploymentRule -Verbose:$false
        $CMSUPADRDeployments = Get-CMSoftwareUpdateAutoDeploymentRuleDeployment -Verbose:$false 

        
        ForEach($Deployment in $CMSUPDeployments){
            [int]$currentItem = [array]::indexof($CMSUPDeployments,$Deployment)
            Write-Progress -Activity "Enabling Software Update Deplyoments for BranchCache" -Status "Currently Enabling - $($Deployment.AssignmentName) - ($($CurrentItem + 1) of $($CMSUPDeployments.Count)) $([math]::round((($currentItem + 1)/($CMSUPDeployments.Count + 1)),2) * 100)% " -PercentComplete $([float](($currentItem + 1)/($CMSUPDeployments.Count + 1)) * 100)
            Set-CMSoftwareUpdateDeployment -Verbose:$false -UseBranchCache $true -inputobject $Deployment
            Write-Log -Message "Enabled $($Deployment.AssignmentName) for BranchCache" -LogLevel 1
        }
        
        ForEach($ADR in $CMSUPADRS){
            [int]$currentItem = [array]::indexof($CMSUPADRS,$ADR)
            Write-Progress -Activity "Enabling Software Update ADR for BranchCache" -Status "Currently Enabling - $($ADR.Name) - ($($CurrentItem + 1) of $($CMSUPADRS.Count)) $([math]::round((($currentItem + 1)/($CMSUPADRS.Count + 1)),2) * 100)% " -PercentComplete $([float](($currentItem + 1)/($CMSUPADRS.Count + 1)) * 100)
            Set-CMSoftwareUpdateAutoDeploymentRule -Verbose:$false -UseBranchCache $true -inputobject $ADR
            Write-Log -Message "Enabled $($ADR.Name) for BranchCache" -LogLevel 1
        }
        
        
        ForEach($ADRDeployment in $CMSUPADRDeployments){
            [int]$currentItem = [array]::indexof($CMSUPADRDeployments,$ADRDeployment)
            Write-Progress -Activity "Enabling Software Update ADR DEPLOYMENT for BranchCache" -Status "Currently Enabling the deployment targeting - $($ADRADRDeployment.CollectionName) - ($($CurrentItem + 1) of $($CMSUPADRDeployments.Count)) $([math]::round((($currentItem + 1)/($CMSUPADRDeployments.Count + 1)),2) * 100)% " -PercentComplete $([float](($currentItem + 1)/($CMSUPADRDeployments.Count + 1)) * 100)
            Set-CMSoftwareUpdateAutoDeploymentRuleDeployment -Verbose:$false -UseBranchCache $true -inputobject $ADRDeployment
            Write-Log -Message "Enabled the ADR Deployment rule targeting collection $($ADRDeployment.CollectionName) for BranchCache" -LogLevel 1
        }
        Set-Location -Path $StartingLocation
    }
    #If the disable option is called.
    if($Mode -ieq "Disable"){
        Write-Log -Message "Now preparing to DISABLE the software update groups for BranchCache deployment."
        $CMSUPDeployments = Get-CMSoftwareUpdateDeployment -Verbose:$false | Where-Object {$_.UseBranchCache -eq $true}
        $CMSUPADRS = Get-CMSoftwareUpdateAutoDeploymentRule -Verbose:$false
        $CMSUPADRDeployments = Get-CMSoftwareUpdateAutoDeploymentRuleDeployment -Verbose:$false 
        
        ForEach($Deployment in $CMSUPDeployments){
            [int]$currentItem = [array]::indexof($CMSUPDeployments,$Deployment)
            Write-Progress -Activity "Disabling Software Update Deplyoments for BranchCache" -Status "Currently Disabling - $($Deployment.AssignmentName) - ($($CurrentItem + 1) of $($CMSUPDeployments.Count)) $([math]::round((($currentItem + 1)/($CMSUPDeployments.Count + 1)),2) * 100)% " -PercentComplete $([float](($currentItem + 1)/($CMSUPDeployments.Count + 1)) * 100)
            Set-CMSoftwareUpdateDeployment -Verbose:$false -UseBranchCache $false -inputobject $Deployment
            Write-Log -Message "DISABLED $($Deployment.AssignmentName) for BranchCache" -LogLevel 1
        }

        
        ForEach($ADR in $CMSUPADRS){
            [int]$currentItem = [array]::indexof($CMSUPADRS,$ADR)
            Write-Progress -Activity "Enabling Software Update ADR for BranchCache" -Status "Currently DISABLING - $($ADR.Name) - ($($CurrentItem + 1) of $($CMSUPADRS.Count)) $([math]::round((($currentItem + 1)/($CMSUPADRS.Count + 1)),2) * 100)% " -PercentComplete $([float](($currentItem + 1)/($CMSUPADRS.Count + 1)) * 100)
            Set-CMSoftwareUpdateAutoDeploymentRule -Verbose:$false -UseBranchCache $false -inputobject $ADR
            Write-Log -Message "DISABLED $($ADR.Name) for BranchCache" -LogLevel 1
        }
        
        ForEach($ADRDeployment in $CMSUPADRDeployments){
            [int]$currentItem = [array]::indexof($CMSUPADRDeployments,$ADRDeployment)
            Write-Progress -Activity "Enabling Software Update ADR DEPLOYMENT for BranchCache" -Status "Currently DISABLING the deployment targeting - $($ADRADRDeployment.CollectionName) - ($($CurrentItem + 1) of $($CMSUPADRDeployments.Count))) $([math]::round((($currentItem + 1)/($CMSUPADRDeployments.Count + 1)),2) * 100)% " -PercentComplete $([float](($currentItem + 1)/($CMSUPADRDeployments.Count + 1)) * 100)
            Set-CMSoftwareUpdateAutoDeploymentRuleDeployment -Verbose:$false -UseBranchCache $false -inputobject $ADRDeployment
            Write-Log -Message "DISABLED the ADR Deployment rule targeting collection $($ADRDeployment.CollectionName) for BranchCache" -LogLevel 1
        }

        Set-Location -Path $StartingLocation
    }
    #Reset the fast warnings.
    $CMPSSuppressFastNotUsedCheck = $CMPSSuppressFastNotUsedCheckStartState
}