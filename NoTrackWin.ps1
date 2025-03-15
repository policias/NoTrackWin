<#PSScriptInfo
.VERSION 1.1703.1
.GUID bd3a1ade-420c-4ac6-8558-b4f8df963aff
.AUTHOR Policias
.COMPANYNAME 
.COPYRIGHT 
.TAGS 
.LICENSEURI https://raw.githubusercontent.com/policias/NoTrackWin/main/LICENSE
.PROJECTURI https://github.com/c/NoTrackWin/tree/main
.ICONURI https://raw.githubusercontent.com/policias/NoTrackWin/main/icon.png
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
   1.0.1 - 10-Aug-2016 Fixed a bug on Version 1607 with handling registry paths
   1.1.0 - 13-Apr-2017 Added settings introduced by the Creator's Update (Vs.1703)
                       Fixed a bug enabling named features.
   1.1703.0 - 14-April-2017 Changed version number to reflect matching Windows
                            version and added more details to the readme file.
                            Removed SpyNet feature.
   1.1703.1 - 15-April-2017 Updated Icon and iconUri
#>
<#
.SYNOPSIS
    PowerShell script to batch-change privacy settings in Windows 10 and Server 2016+
.DESCRIPTION
    With numerous privacy settings in Windows 10, a script can simplify managing them.
.PARAMETER Strong
    Sets high privacy settings
.PARAMETER Default
    Restores Windows defaults 
.PARAMETER Balanced
    Disables most features without turning everything off.
.PARAMETER Admin
    Updates system-wide settings. Still requires Strong, Balanced, or Default switches. Needs elevated admin rights.
    If selected, no user settings are changed.
.PARAMETER Features
    A comma-separated list of features to disable or enable. Use Tab to show allowed values
.PARAMETER Disable
    Use with -Features to disable selected features
.PARAMETER Enable
    Use with -Features to enable selected features
.EXAMPLE       
    Set-Privacy -Strong
    Applies strong privacy settings for the current user
.EXAMPLE       
    Set-Privacy -Balanced
    Applies balanced privacy settings  
.EXAMPLE       
    Set-Privacy -Strong -Admin
    Applies strong settings at the system level. Covers Windows updates and WiFi Sense.   
.EXAMPLE       
    Set-Privacy -disable -Features WifiSense,ShareUpdates,Contacts 
    Disables specified features to enhance privacy   
.NOTES
    Requires Windows 10 or higher
    Author:  Pedro Ramirez
    Created: August 4th, 2015 
.LINK
    https://github.com/policias/NoTrackWin/tree/main   
#>
param(
    [parameter(Mandatory=$true,ParameterSetName = "Strong")]
    [switch]$Strong,
    [parameter(Mandatory=$true,ParameterSetName = "Default")]
    [switch]$Default,
    [parameter(Mandatory=$true,ParameterSetName = "Balanced")]
    [switch]$Balanced,
    [parameter(ParameterSetName = "Balanced")]
    [parameter(ParameterSetName = "Default")]
    [parameter(ParameterSetName = "Strong")]
    [switch]$Admin,
    [parameter(Mandatory=$true,ParameterSetName = "Disable")]
    [switch]$Disable,
    [parameter(Mandatory=$true,ParameterSetName = "Enable")]
    [switch]$Enable,
    [parameter(Mandatory=$true,ParameterSetName = "Enable")]
    [parameter(Mandatory=$true,ParameterSetName = "Disable")]
    [ValidateSet("AdvertisingId","ImproveTyping","Location","Camera","Microphone","SpeachInkingTyping",`
    "AccountInfo","Contacts","Calendar","Messaging","Radios","OtherDevices","FeedbackFrequency","ShareUpdates",`
    "WifiSense","Telemetry","SpyNet","DoNotTrack","SearchSuggestions","PagePrediction","PhishingFilter",`
    "StartTrackProgs","AppNotifications","CallHistory","Email","Tasks","AppDiagnostics","TailoredExperiences")]
    [string[]]$Feature
)           
Begin
{
#requires -version 3
    # ----------- Helper Functions -----------
    Function Test-Admin()
    {
        if (!($userIsAdmin))
        {
            Write-Warning "For -admin switch or system-level settings, run as elevated administrator"
            Exit 102
        }
    }
    Function Test-RegistryValue([String]$Path,[String]$Name){
      if (!(Test-Path $Path)) { return $false }
      $Key = Get-Item -LiteralPath $Path
      if ($Key.GetValue($Name, $null) -ne $null) {
          return $true
      } else {
          return $false
      }
    }
    Function Get-RegistryValue([String]$Path,[String]$Name){
      if (!(Test-Path $Path)) { return $null }
      $Key = Get-Item -LiteralPath $Path
      if ($Key.GetValue($Name, $null) -ne $null) {
          return $Key.GetValue($Name, $null)
      } else {
          return $null
      }
    }
    Function Remove-RegistryValue([String]$Path,[String]$Name){
        $old = Get-RegistryValue -Path $Path -Name $Name
        if ($old -ne $null)
        {
            Remove-ItemProperty -Path "$Path" -Name "$Name"
            Write-Host "$Path\$Name removed" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "$Path\$Name does not exist" -ForegroundColor Green
        }
    }
    Function Create-RegistryKey([string]$path)
    {        
        If (!(Test-Path $Path))
        {
            $parent = "$path\.."
            $grandParent = "$parent\.."
            If (!(Test-Path $grandParent))
            {
                New-item -Path $grandParent | Out-Null
            }
            If (!(Test-Path $parent))
            {
                New-item -Path $parent | Out-Null
            }
            New-item -Path $Path | Out-Null
        }
    }
    Function Add-RegistryDWord([String]$Path,[String]$Name,[int32]$value){
        $old = Get-RegistryValue -Path $Path -Name $Name
        if ($old -ne $null)
        {
            if ([int32]$old -eq $value)
            {
                Write-Host "$Path\$Name already set to $value" -ForegroundColor Green
                return
            }
        }
        If (Test-RegistryValue $Path $Name)
        {
            Set-ItemProperty -Path $Path -Name $Name -Value $value
        }
        else
        {
            Create-RegistryKey -path $path
            New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $value | Out-Null
        }
        Write-Host "$Path\$Name changed to $value" -ForegroundColor Yellow
    }
    Function Add-RegistryString([String]$Path,[String]$Name,[string]$value){
        $old = Get-RegistryValue -Path $Path -Name $Name
        if ($old -ne $null)
        {
            if ([string]$old -eq $value)
            {
                Write-Host "$Path\$Name already set to $value" -ForegroundColor Green
                return
            }
        }
        If (Test-RegistryValue $Path $Name)
        {
            Set-ItemProperty -Path $Path -Name $Name -Value $value
        }
        else
        {
            Create-RegistryKey -path $path
            New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $value |Out-Null
        }
        Write-Host "$Path\$Name changed to $value" -ForegroundColor Yellow
    }
    Function Get-AppSID(){
        Get-ChildItem "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings" | foreach {
        $key = $_.Name -replace "HKEY_CURRENT_USER","HKCU:"
        $val = Get-RegistryValue -Path $key -Name "Moniker" 
        if ($val -ne $null)
        {
            if ($val -match "^microsoft\.people_")
            {
                $script:sidPeople = $_.PsChildName
            }
            if ($val -match "^microsoft\.windows\.cortana")
            {
                $script:sidCortana = $_.PsChildName
            }
        }     
    }              
    }
    Function DeviceAccess([string]$guid,[string]$value){
        Add-RegistryString -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{$guid}" -Name Value -Value $value
    }
    Function DeviceAccessName([string]$name,[string]$value){
        Add-RegistryString -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\$name" -Name Value -Value $value
    }
    Function DeviceAccessApp([string]$app,[string]$guid,[string]$value){
        Add-RegistryString -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\$app\{$guid}" -Name Value -Value $value
    }
    Function Report(){
        Write-Host "Privacy settings updated"
        Exit 0
    }
    # ----------- User Privacy Functions -----------
    Function SmartScreen([int]$value){
        Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name EnableWebContentEvaluation -Value $value
    }
    Function ImproveTyping([int]$value){
        Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name Enabled -Value $value
    }
    Function AdvertisingId([int]$value){
        Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Value $value
    }
    Function LanguageList([int]$value){
        Add-RegistryDWord -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Value $value
    }
    Function SpeachInkingTyping([bool]$enable){
        if ($enable)
        {
            Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name AcceptedPrivacyPolicy -Value 1
            Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name RestrictImplicitTextCollection -Value 0
            Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name RestrictImplicitInkCollection -Value 0
            Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name HarvestContacts -Value 1
        }
        else
        {
            Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name AcceptedPrivacyPolicy -Value 0
            Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name RestrictImplicitTextCollection -Value 1
            Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name RestrictImplicitInkCollection -Value 1
            Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name HarvestContacts -Value 0    
        }
    }
    Function Location([string]$value){
        DeviceAccess -guid "BFA794E4-F964-4FDB-90F6-51056BFE4B44" -value $value
    }
    Function Camera([string]$value){
        DeviceAccess -guid "E5323777-F976-4f5b-9B55-B94699C46E44" -value $value
    }
    Function Microphone([string]$value){
        DeviceAccess -guid "2EEF81BE-33FA-4800-9670-1CD474972C3F" -value $value
    }
    Function CallHistory([string]$value){
        DeviceAccess -guid "8BC668CF-7728-45BD-93F8-CF2B3B41D7AB" -value $value
    }
    Function Email([string]$value){
        DeviceAccess -guid "9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5" -value $value
    }
    Function Tasks([string]$value){
        DeviceAccess -guid "E390DF20-07DF-446D-B962-F5C953062741" -value $value
    }
    Function Contacts([string]$value){
        $exclude = $script:sidCortana + "|" + $script:sidPeople
        DeviceAccess -guid "7D7E8402-7C54-4821-A34E-AEEFD62DED93" -value $value
        Get-ChildItem HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess | ForEach-Object{
            $app = $_.PSChildName
            if ($app -ne "Global")
            {
                $key = $_.Name -replace "HKEY_CURRENT_USER","HKCU:"
                $contactsGUID = "7D7E8402-7C54-4821-A34E-AEEFD62DED93"
                $key += "\{$contactsGUID}"
                if (Test-Path "$key")
                {
                    if ($app -notmatch $exclude)
                    {
                        DeviceAccessApp -app $app -guid $contactsGUID -value $value
                    }
                }
            }
        }
    }
    Function Calendar([string]$value){
        DeviceAccess -guid "D89823BA-7180-4B81-B50C-7E471E6121A3" -value $value
    }
    Function AccountInfo([string]$value){
        DeviceAccess -guid "C1D23ACC-752B-43E5-8448-8D0E519CD6D6" -value $value
    }
    Function Messaging([string]$value){
        DeviceAccess -guid "992AFA70-6F47-4148-B3E9-3003349C1548" -value $value
    }
    Function Radios([string]$value){
        DeviceAccess -guid "A8804298-2D5F-42E3-9531-9C8C39EB29CE" -value $value
    }
    Function OtherDevices([string]$value){
        DeviceAccessName -name "LooselyCoupled" -value $value
    }
    Function FeedbackFrequency([int]$value){
        if ($value -lt 0)
        {
            Remove-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name NumberOfSIUFInPeriod
        }
        else
        {
            Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name NumberOfSIUFInPeriod -Value $value
        }
    }
    Function AppNotifications([string]$value){
        DeviceAccess -guid "52079E78-A92B-413F-B213-E8FE35712E72" -value $value
    }    
    Function AppDiagnostics([string]$value){
        DeviceAccess -guid "2297E4E2-5DBE-466D-A12B-0F8286F0D9CA" -value $value
    } 
    # ----------- Edge Browser Privacy Functions -----------
    [string]$EdgeKey = "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge"
    Function DoNotTrack([int]$value){
        Add-RegistryDWord -Path "$EdgeKey\Main" -Name DoNotTrack -Value $value
    }
    Function SearchSuggestions([int]$value){
        Add-RegistryDWord -Path "$EdgeKey\User\Default\SearchScopes" -Name ShowSearchSuggestionsGlobal -Value $value
    }
    Function PagePrediction([int]$value){
        Add-RegistryDWord -Path "$EdgeKey\FlipAhead" -Name FPEnabled -Value $value
    }
    Function PhishingFilter([int]$value){
        Add-RegistryDWord -Path "$EdgeKey\PhishingFilter" -Name EnabledV9 -Value $value
    }
    Function StartTrackProgs([int]$value)
    {
        Add-RegistryDWord -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Value $value
    }
    Function TailoredExperiences([int]$value)
    {
        Add-RegistryDWord -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name TailoredExperiencesWithDiagnosticDataEnabled -Value $value
    }
    # ----------- Machine Settings Functions -----------
    Function ShareUpdates([int]$value){
        Test-Admin
        Add-RegistryDWord -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name DODownloadMode -Value $value        
    }
    Function WifiSense([int]$value){
        Test-Admin
        Add-RegistryDWord -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" -Name WiFiSenseCredShared -Value $value        
        Add-RegistryDWord -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" -Name WiFiSenseOpen -Value $value        
    }
    Function SpyNet([bool]$enable){
        Test-Admin
$definition = @"
using System;
using System.Runtime.InteropServices;
namespace Win32Api
{
    public class NtDll
    {
        [DllImport("ntdll.dll", EntryPoint="RtlAdjustPrivilege")]
        public static extern int RtlAdjustPrivilege(ulong Privilege, bool Enable, bool CurrentThread, ref bool Enabled);
    }
}
"@
        if (-not ("Win32Api.NtDll" -as [type])) 
        {
            Add-Type -TypeDefinition $definition -PassThru | out-null
        }
        else
        {
             ("Win32Api.NtDll" -as [type]) | Out-Null
        }
        $bEnabled = $false
        $res = [Win32Api.NtDll]::RtlAdjustPrivilege(9, $true, $false, [ref]$bEnabled)
        $adminGroupSID = "S-1-5-32-544"
        $adminGroupName = (get-wmiobject -class "win32_account" -namespace "root\cimv2" | where-object{$_.sidtype -eq 4 -and $_.Sid -eq "$adminGroupSID"}).Name 
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows Defender\Spynet", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::takeownership)
        $acl = $key.GetAccessControl()
        $acl.SetOwner([System.Security.Principal.NTAccount]$adminGroupName)
        $key.SetAccessControl($acl)
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("$adminGroupName","FullControl","Allow")
        $acl.SetAccessRule($rule)
        $key.SetAccessControl($acl)
        if ($enable)
        {
            Add-RegistryDWord -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 1 
        }
        else
        {
            Add-RegistryDWord -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 0                   
        }      
        $acl.RemoveAccessRule($rule) | Out-Null
        $key.SetAccessControl($acl)
    }
    Function Telemetry ([bool]$enable){
        Test-Admin
        if ($enable)
        {
            Set-service -Name DiagTrack -Status Running -StartupType Automatic
            if ((Get-Service | where Name -eq dmwappushservice).count -eq 1)
            {
                & sc.exe config dmwappushservice start= delayed-auto | Out-Null
                Set-service -Name dmwappushservice -Status Running
            }
            Remove-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry
        }
        else
        {            
            Stop-Service -Name DiagTrack -Force
            Set-service -Name DiagTrack -StartupType Disabled
            if((Get-Service | where Name -eq dmwappushservice).count -eq 1)
            {
                Stop-Service -Name dmwappushservice -Force
                Set-service -Name dmwappushservice -StartupType Disabled
            }
            Add-RegistryDWord -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Value 0 
        }
    }
    # ----------- Grouping Functions -----------
    Function Set-StrictPrivacyFeature([bool]$enable)
    {
        $AllowDeny = "Deny"
        $OnOff = 0      
        $OffOn = 1  
        if ($enable)
        {
            $AllowDeny = "Allow"
            $OnOff = 1
            $OffOn = 0
        }
        AdvertisingId -value $OnOff
        ImproveTyping -value $OnOff          
        Location -value $AllowDeny
        Camera -value $AllowDeny
        Microphone -value $AllowDeny
        SpeachInkingTyping -enable $enable
        AccountInfo -value $AllowDeny
        Contacts -value $AllowDeny
        Calendar -value $AllowDeny
        Messaging -value $AllowDeny
        Radios -value $AllowDeny
        OtherDevices -value $AllowDeny
        AppNotifications -value $AllowDeny
        CallHistory -value $AllowDeny
        Email -value $AllowDeny
        Tasks -value $AllowDeny
        AppDiagnostics -value $AllowDeny
        if ($enable)
        {
            FeedbackFrequency -value -1
        }
        else
        {
            FeedbackFrequency -value 0
        }
        DoNotTrack -value $OffOn
        SearchSuggestions -value $OnOff 
        PagePrediction -value $OnOff 
        PhishingFilter -value $OnOff 
        StartTrackProgs -value $OnOff
        TailoredExperiences -value $OnOff
    }
    Function Set-MiscPrivacyFeature([bool]$enable)
    {            
        if ($enable)
        {
            SmartScreen -value 1
            LanguageList -value 0
        }
        else
        {
            SmartScreen -value 0
            LanguageList -value 1
        }
    }
}
Process
{
    Write-Output "Processing settings..."
    $myOS = Get-CimInstance -ClassName Win32_OperatingSystem -Namespace root/cimv2 -Verbose:$false
    if ([int]$myOS.BuildNumber -lt 10240)
    {   
        Write-Warning "Unsupported OS version, Windows 10 or higher required" 
        Exit 101
    }
    $UserCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userIsAdmin = $false
    $UserCurrent.Groups | ForEach-Object { if($_.value -eq "S-1-5-32-544") {$userIsAdmin = $true} }
    if ($Admin)
    {        
        if ($Strong)
        {
            ShareUpdates -value 0
            WifiSense -value 0
            Telemetry -enable $false
            SpyNet -enable $false
        }
        if ($Balanced)
        {
            ShareUpdates -value 1
            WifiSense -value 0
            Telemetry -enable $false
            SpyNet -enable $true
        }
        if ($Default)
        {
            ShareUpdates -value 3
            WifiSense -value 1
            Telemetry -enable $true
            SpyNet -enable $true
        }
        Report
    }
    Get-AppSID
    if ($Strong)
    {
        Set-MiscPrivacyFeature -enable $false
        Set-StrictPrivacyFeature -enable $false        
        Report        
    }
    if ($Balanced)
    {
        Set-MiscPrivacyFeature -enable $true
        Set-StrictPrivacyFeature -enable $false
        Report        
    }
    if ($Default)
    {
        Set-MiscPrivacyFeature -enable $true
        Set-StrictPrivacyFeature -enable $true  
        Report
    }
    $AllowDeny = "Deny"
    $OnOff = 0
    $OffOn = 1   
    $DoEnable = $false  
    if ($Enable)
    {
        $AllowDeny = "Allow"
        $OnOff = 1
        $OffOn = 0
        $DoEnable = $true 
    }
    $Feature | ForEach-Object {
        switch ($_) 
            { 
                "AdvertisingId" {AdvertisingId -value $OnOff;break} 
                "ImproveTyping" {ImproveTyping -value $OnOff;break} 
                "Location" {Location -value $AllowDeny;break}
                "Camera" {Camera -value $AllowDeny;break} 
                "Microphone" {Microphone -value $AllowDeny;break} 
                "SpeachInkingTyping" {SpeachInkingTyping -enable $DoEnable;break} 
                "AccountInfo" {AccountInfo -value $AllowDeny;break} 
                "Contacts" {Contacts -value $AllowDeny;break} 
                "Calendar" {Calendar -value $AllowDeny;break} 
                "Messaging" {Messaging -value $AllowDeny;break} 
                "Radios" {Radios -value $AllowDeny;break} 
                "OtherDevices" {OtherDevices -value $AllowDeny;break} 
                "AppNotifications" {AppNotifications -value $AllowDeny;break}
                "CallHistory" {CallHistory -value $AllowDeny;break}
                "Email" {Email -value $AllowDeny;break}
                "Tasks" {Tasks -value $AllowDeny;break}
                "AppDiagnostics"{AppDiagnostics -value $AllowDeny;break}
                "FeedbackFrequency" {
                        if ($Enable) {
                            FeedbackFrequency -value -1;
                        }
                        else
                        {
                            FeedbackFrequency -value 0;
                        }
                        break} 
                "ShareUpdates" {
                        if ($Enable) {
                            ShareUpdates -value 3;
                        }
                        else
                        {
                            ShareUpdates -value 0;
                        }
                        break}
                "WifiSense" {WifiSense -value $OnOff;break}                                                                    
                "Telemetry" {Telemetry -enable $DoEnable;break} 
                "SpyNet" {SpyNet -enable $DoEnable ;break}
                "DoNotTrack" {DoNotTrack -value $OffOn;break}  
                "SearchSuggestions" {SearchSuggestions -value $OnOff;break}  
                "PagePrediction" {PagePrediction -value $OnOff;break}  
                "PhishingFilter" {PhishingFilter -value $OnOff;break}  
                "StartTrackProgs" {StartTrackProgs -value $OnOff;break}
                "TailoredExperiences"{TailoredExperiences -value $OnOff;break}
                default {"ooops, nothing selected"}
            }
    }
}
End
{
}
