<#
.SYNOPSIS
    This script is used to enable, disable, and get BranchCache information about applications in the environment

    When run in Gather Mode - The script returns a count of the applications/deployment types that are NOT BranchCache enabled.
    
    When run in Enable mode - The script enables ALL application deployment types for BranchCache.

    When run in Disable mode the script disables all application deployment types for BranchCache.

.DESCRIPTION
    This script is used to enable, disable, and get BranchCache information about applications in the environment
    This script leverages WMI to make these changes as the PowerShell Module does not have a good way to make the changes to the application XML. 
     
.NOTES
    This script is used to enable, disable, and get BranchCache information about applications in the environment
    Just edit the Sitecode, mode, and optional application name (wild card is supported)

    This script was mostly 'stolen with pride' from examples all over the place but specific thanks to @NickolajA, @david_obrien and @merlin_with_a_j !
    
    Use at your own risk - and test it first!

    Be aware that updating deployments will trigger a policy update.

    FileName: Set-BranchCache-Apps.ps1
    Authors: Phil Wilcock, Jordan Benzing, and Johan Arwidmark
    Contact: @2PintSoftware
    Created: 2019-07-02
    Modified: 2019-07-02

    Version - 0.0.0 - (UNKNOWN)
    Version - 0.1.0 - (03-JULY-19)
        COMPLETED: Add the proper help information
        COMPLETED: Add the proper notes and examples
        COMPLETED: Enable processing and Begin Blocks
        COMPLETED: Add Helper Functions to remove static variables
        COMPLETED: Correct all logging to use LOGGS instead
        COMPLETED: Enable Verbosity instead of Write-Host everywhere applicable
        COMPLETED: Create Progress bars as needed to display status
        BUGFIXED: When you only have ONE application the correct count isn't displayed in the progress bar. 
        COMPLETED: Log the number - of apps without Content - And The state of Cache enable/disable
        COMPLETED: Add capability to ONLY target a SINGLE app for enable/disbale/inquire/gather
    Version - 0.1.1 - (07-JULY-19)
        COMPLETED: - IGNORE apps that do not have content
        BUG: - DONT Enable content that's already enabled - To TEST this we have to retrieve all of the deployments for the app any way at that point might as well set it. 
        COMPLETED: - Allow the user to set the enable state for only ONE named application. 
        
        


.PARAMETER SiteServer
    This parameter is a string and is designed to only accept the name of the ConfigMgr site server. This information is
    thenused to gather the other required information. 

.PARAMETER Mode
    This parameter is a string parameter and requires you to pick from a validation set. The available modes are:
        Gather - Only returns the information about the not BranchCache enabled app deployment types
        Enable - Enables the updates that are not using it.
        Disable - Disables all of them. 

.EXAMPLE
    .\Set-BranchCache-Apps.PS1 -siteServer "ServerName" -Mode Enable

    This example would gather all application deployment types that are not BranchCache enabled and then enable them. 

.EXAMPLE
     .\Set-BranchCache-Apps.PS1 -siteServer "ServerName" -Mode Gather

     This example would gather all of the application deployment types that are not currently BranchCache enabled and display a count of them.

.EXAMPLE
     .\Set-BranchCache-Apps.PS1 -siteServer "ServerName" -Mode DISABLE

     This example would disable BranchCache on ALL application deployment types CAUTION enabling this. 

.EXAMPLE
    .\Set-BranchCache-Apps.PS1 -siteServer "ServerName"

    This example would gather all of the application deployment types that are not currently BranchCache enabled and display a count of them.

#>

[cmdletbinding()]
param(
    [Parameter(HelpMessage = "Please enter the name of your site server" , Mandatory = $true )]
    [string]$SiteServer,
    [Parameter(HelpMessage = "This option allows you to enable BranchCache for all packages. By Default we only return the BranchCache enabled packages.",Mandatory = $false)]
    [ValidateSet('Enable','Gather','Disable')]
    [string]$Mode = "Gather",
    [Parameter(HelpMessage = "This option allows you to enable BranchCache for a SPECIFIC package",Mandatory = $false)]
    [string]$AppName
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

#region ScriptFunctions

#EndRegion ScriptFunctions

}

process{
    set-DefaultLogPath
    Write-Log -Message "Now starting all logs for the duration of the script" -LogLevel 1
    $StartingLocation = Get-Location
    Write-Log -Message "Set the starting location and stored it to return" -LogLevel 1
    if(!(Test-ConfigMgrAvailable -Remediate:$true)){
        Write-Log -Message "We were unable to load the ConfigMgr Cmdlets and unable to connect to the CM provider will now exit." -LogLevel 3
        Set-Location -Path $StartingLocation
        break  
        }
    $Sitecode = (Get-PSDrive -PSProvider CMSite -Verbose:$false).Name

#--------------------------------------
# Load ConfigMgr application assemblies
#--------------------------------------
    try {
        Add-Type -Path (Join-Path -Path (Get-Item $env:SMS_ADMIN_UI_PATH).Parent.FullName -ChildPath "Microsoft.ConfigurationManagement.ApplicationManagement.dll") -ErrorAction Stop
        Add-Type -Path (Join-Path -Path (Get-Item $env:SMS_ADMIN_UI_PATH).Parent.FullName -ChildPath "AdminUI.WqlQueryEngine.dll") -ErrorAction Stop
        Add-Type -Path (Join-Path -Path (Get-Item $env:SMS_ADMIN_UI_PATH).Parent.FullName -ChildPath "AdminUI.DcmObjectWrapper.dll") -ErrorAction Stop
    }
    catch [System.UnauthorizedAccessException] {
	    Write-Warning -Message "Access was denied when attempting to load ApplicationManagement dll's" ; break
    }
    catch [System.Exception] {
	    Write-Warning -Message "Unable to load required ApplicationManagement dll's. Make sure that you're running this tool on system where the ConfigMgr console is installed and that you're running the tool elevated" ; break
    }

    if ($AppName) {
        Write-Log -Message "The option to only return an application with a specific name '$AppName' was selected. Retrieving that application..."
        $applications = Get-WmiObject SMS_Application -Computername $SiteServer -Namespace root\sms\site_$SiteCode | Where-Object {$_.IsLatest -and $_.LocalizedDisplayName -like $AppName -and $_.HasContent -eq $true}
        if ($Applications -eq $null) {
            Write-Log -Message "ERROR - NO application meets the criteria of HAVING content, and having this specific name. Script will exit" -LogLevel 3
            Set-Location -Path $StartingLocation
            break
        }
    } else {
        Write-Log -Message "The option to return all applications was selected. Retriving all application..."
        $Applications = Get-WmiObject SMS_Application -Computername $SiteServer -Namespace root\sms\site_$SiteCode | Where-Object {$_.IsLatest -and $_.HasContent -eq $true}
        if ($Applications -eq $null) {
            Write-Log -Message "ERROR - NO application meets the criteria of HAVING content. Script will exit" -LogLevel 3
            Set-Location -Path $StartingLocation
            break
        }
    }

    if ($Mode -eq "Enable") {
        ForEach ($Application in $Applications) {
            $Application.Get()
            [int]$CurrentItem = [array]::indexof($Applications,$Application)
            Write-Progress -Activity "ENABLING BranchCache App Deployment Types for Application ($($CurrentItem + 1) of $(($Applications | Measure-Object).Count)) - $([math]::round((($currentItem + 1)/($Applications.Count + 1)),2) * 100)% " -Status "Currently ENABLING Deployment Types for - $($Application.LocalizedDisplayName)" -PercentComplete $([float](($currentItem + 1)/($Applications.Count + 1)) * 100)
            $ApplicationName = $Application.LocalizedDisplayName
            $ApplicationXML = [Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::DeserializeFromString($application.SDMPackageXML)
            $UpdateApplication = $false
            if ($ApplicationXML.DeploymentTypes -ne $null) {
                foreach ($DeploymentType in $ApplicationXML.DeploymentTypes) {
                    if ($DeploymentType.Installer.Contents.Location -ne $null) {
                        if ($DeploymentType.Installer.Contents.PeerCache -eq $false) {
                            Write-Log -Message "$($DeploymentType.Title) : Enabling BranchCache" -LogLevel 1
                            $DeploymentType.Installer.Contents[0].PeerCache = $true # enable BranchCache
                            $UpdateApplication = $true
                        } else {
                            Write-Log -Message "$($DeploymentType.Title) : BranchCache is enabled" -LogLevel 1
                        }
                    }
                }
            }
            if ($UpdateApplication) {
                $NewApplicationXml = [Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::Serialize($ApplicationXML, $false)
                $Application.SDMPackageXML = $NewApplicationXml
                $Application.Put() | Out-Null
            }
        }
            write-log -message "Done! Happy BranchCache-ing" -LogLevel 1
    }

    if ($Mode -eq "Gather") {
        $NumberOfBCEnabledApplications = 0
        $NumberOfBCDisabledApplications = 0

        ForEach ($Application in $Applications) {
            $Application.Get()
            [int]$CurrentItem = [array]::indexof($Applications,$Application)
            Write-Progress -Activity "GATHERING BranchCache App Deployment Types for Application ($($CurrentItem + 1) of $(($Applications | Measure-Object).Count)) - $([math]::round((($currentItem + 1)/($Applications.Count + 1)),2) * 100)% " -Status "Currently GATHERING Deployment Types for - $($Application.LocalizedDisplayName)" -PercentComplete $([float](($currentItem + 1)/($Applications.Count + 1)) * 100)
            $DeploymentTypes = ([Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::DeserializeFromString($application.SDMPackageXML)).DeploymentTypes
            if ($DeploymentTypes -ne $null) {
                Foreach ($DeploymentType in $DeploymentTypes) {
                    if ($DeploymentType.Installer.Contents.Location -ne $null) {
                        if ($DeploymentType.Installer.Contents.PeerCache -eq $True) {
                            Write-Log -Message "$($DeploymentType.Title) : BranchCache is enabled" -LogLevel 1
                            $NumberOfBCEnabledApplications++
                        }

                        if ($DeploymentType.Installer.Contents.PeerCache -eq $False) {
                            Write-Log "$($DeploymentType.Title) : BranchCache is disabled"
                            $NumberOfBCDisabledApplications++
                        }
                    }
                }
            }
        }

        Write-Log -Message "Now evaluating Results" -LogLevel 1
        Write-Log -Message "Total number of applications: $($NumberOfBCEnabledApplications + $NumberOfBCDisabledApplications)" -LogLevel 1
        Write-Log -Message "Total number of applications with content: $($($Applications | Where-Object {$_.HasContent -eq $True} | Measure-Object).Count)"
        Write-Log -Message "Total number of applications without Content: $($($Applications | Where-Object {$_.HasContent -eq $False} | Measure-Object).Count)"
        Write-Log -Message "Number Of BranchCache Enabled applications: $($NumberOfBCEnabledApplications - $($Applications | Where-Object {$_.HasContent -eq $False} | Measure-Object).Count)" -LogLevel 1
        Write-Log -Message "Number Of BranchCache Disabled applications: $($NumberOfBCDisabledApplications)" -LogLevel 1
    }

    if ($Mode -eq "Disable") {
        ForEach ($Application in $Applications) {
            $Application.Get()
            [int]$CurrentItem = [array]::indexof($Applications,$Application)
            Write-Progress -Activity "DISABLING BranchCache App Deployment Types ($($CurrentItem + 1) of $(($Applications | Measure-Object).Count)) - $([math]::round((($currentItem + 1)/($Applications.Count + 1)),2) * 100)% " -Status "Currently DISABLING BranchCache on Deployment Types for - $($Application.LocalizedDisplayName)" -PercentComplete $([float](($currentItem + 1)/($Applications.Count + 1)) * 100)
            $ApplicationName = $Application.LocalizedDisplayName
            $ApplicationXML = [Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::DeserializeFromString($application.SDMPackageXML)
            $UpdateApplication = $false
            if ($ApplicationXML.DeploymentTypes -ne $null) {
                foreach ($DeploymentType in $ApplicationXML.DeploymentTypes) {
                    if ($DeploymentType.Installer.Contents.Location -ne $null) {
                        if ($DeploymentType.Installer.Contents.PeerCache -eq $true) {
                            Write-Log -Message "$($DeploymentType.Title) : Disabling BranchCache" -LogLevel 1
                            $DeploymentType.Installer.Contents[0].PeerCache = $false # disable BranchCache
                            $UpdateApplication = $true
                        } else {
                            Write-Log -Message "$($DeploymentType.Title) : BranchCache is disabled" -LogLevel 1
                        }
                    }
                }
            }
            if ($UpdateApplication) {
                $NewApplicationXml = [Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::Serialize($ApplicationXML, $false)
                $Application.SDMPackageXML = $NewApplicationXml
                $Application.Put() | Out-Null
            }
        }
        Write-Log -Message "Done! We are sad to see you stop caching"
    }

    Set-Location -Path $StartingLocation
}