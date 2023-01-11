##########
# Win10 Initial Setup Script
# Script credit: https://www.youtube.com/watch?v=PdKMiFKGQuc
# Script contributor: Windows Modding Discord @ https://discord.gg/hzScjC9re6
# Author: Disassembler <disassembler@dasm.cz>
# Version: 1.6, 2021
##########

# Ask for elevated permissions if required
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}



##########
# Privacy Settings
##########

# Disable Telemetry
Write-Host "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0


# Disable Wi-Fi Sense
Write-Host "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0


# Disable SmartScreen Filter
Write-Host "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0


# Disable Bing Search in Start Menu
Write-Host "Disabling Bing Search in Start Menu..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0


# Disable Location Tracking
Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0


# Disable Feedback
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0


# Disable Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0


# Disable Cortana
Write-Host "Disabling Cortana..."
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0


# Uninstall Cortana
Write-Host "Uninstalling Cortana..."
Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage


# Remove AutoLogger file and restrict directory
Write-Host "Removing AutoLogger file and restricting directory..."
$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
	Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null


# Stop and disable Diagnostics Tracking Service
Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled



##########
# Service Tweaks
##########

# Enable Firewall
Write-Host "Enabling Firewall on all Profiles..."
Set-NetFirewallProfile -Profile * -Enabled True

#Set your network to private
Write-Host "Setting network type to private..."
Set-NetConnectionProfile -NetworkCategory Private



##########
# UI Tweaks
##########


# Disable Autoplay
 Write-Host "Disabling Autoplay..."
 Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1


# Disable Autorun for all drives
 Write-Host "Disabling Autorun for all drives..."
 If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
}
 Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255


# Disable Sticky keys prompt
 Write-Host "Disabling Sticky keys prompt..."
 Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"


# Show small icons in taskbar
# Write-Host "Showing small icons in taskbar..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1


# Show large icons in taskbar
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons"


# Show titles in taskbar
# Write-Host "Showing titles in taskbar..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1


# Hide titles in taskbar
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel"


# Show known file extensions
Write-Host "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0


# Show hidden files
 Write-Host "Showing hidden files..."
 Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1


# Change default Explorer view to "Computer"
Write-Host "Changing default Explorer view to `"Computer`"..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1



##########
# Remove unwanted applications
##########


# Uninstall default Microsoft applications
# Write-Host "Uninstalling default Microsoft applications..."
# Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
# Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage
# Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
# Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
# Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
# Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.ScreenSketch" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
# Get-AppBackgroundTask "Microsoft.XboxIdentityProvider" | Remove-AppPackage


# Install default Microsoft applications
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.3DBuilder").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingFinance").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingNews").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingSports").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingWeather").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Getstarted").InstallLocation)\AppxManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftOfficeHub").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Office.OneNote").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.People").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.SkypeApp").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Windows.Photos").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsAlarms").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsCamera").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.windowscommunicationsapps").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsMaps").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsPhone").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsSoundRecorder").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.XboxApp").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ZuneMusic").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ZuneVideo").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.AppConnector").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ConnectivityStore").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Office.Sway").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Messaging").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.CommsPhone").InstallLocation)\AppXManifest.xml"
# In case you have removed them for good, you can try to restore the files using installation medium as follows
#New-Item C:\Mnt -Type Directory | Out-Null
#dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
#robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
#dism /Unmount-Image /Discard /MountDir:C:\Mnt
#Remove-Item -Path C:\Mnt -Recurse


# $services = @(
#     "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
#     "DiagTrack"                                # Diagnostics Tracking Service
#     "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
#     "lfsvc"                                    # Geolocation Service
#     #"MapsBroker"                              # Downloaded Maps Manager
#     "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
#     #"RemoteAccess"                            # Routing and Remote Access
#     #"RemoteRegistry"                          # Remote Registry
#     "SharedAccess"                             # Internet Connection Sharing (ICS)
#     "TrkWks"                                   # Distributed Link Tracking Client
#     # "WbioSrvc"                               # Windows Biometric Service (required for Fingerprint reader / facial detection)
#     #"WlanSvc"                                 # WLAN AutoConfig
#     #"WMPNetworkSvc"                           # Windows Media Player Network Sharing Service
#     #"wscsvc"                                  # Windows Security Center Service
#     #"WSearch"                                 # Windows Search
#     #"XblAuthManager"                          # Xbox Live Auth Manager
#     #"XblGameSave"                             # Xbox Live Game Save Service
#     #"XboxNetApiSvc"                           # Xbox Live Networking Service
#     "ndu"                                      # Windows Network Data Usage Monitor
# )

# foreach ($service in $services) {
#     Write-Output "Trying to disable $service"
#     Get-Service -Name $service | Set-Service -StartupType Disabled
# }


# #   Description:
# # This script optimizes Windows updates by disabling automatic download and
# # seeding updates to other computers.
# #
# Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

# Write-Output "Disable automatic download and installation of Windows updates"
# New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3

# Write-Output "Disable seeding of updates to other computers via Group Policies"
# New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0

# #echo "Disabling automatic driver update"
# #sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0

# #$objSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
# #$EveryOne = $objSID.Translate( [System.Security.Principal.NTAccount]).Value


# Write-Output "Disable 'Updates are available' message"

# takeown /F "$env:WinDIR\System32\MusNotification.exe"
# icacls "$env:WinDIR\System32\MusNotification.exe" /deny "$($EveryOne):(X)"
# takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
# icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "$($EveryOne):(X)"


# # This script removes unwanted Apps that come with Windows. If you  do not want
# # to remove certain Apps comment out the corresponding lines below.

# Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1
# Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

# Write-Output "Elevating privileges for this process"
# do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

# Write-Output "Uninstalling default apps"
# $apps = @(
#     # default Windows 10 apps
#     "Microsoft.3DBuilder"
#     "Microsoft.Advertising.Xaml"
#     "Microsoft.Appconnector"
#     "Microsoft.BingFinance"
#     "Microsoft.BingNews"
#     "Microsoft.BingSports"
#     "Microsoft.BingTranslator"
#     "Microsoft.BingWeather"
#     #"Microsoft.FreshPaint"
#     #"Microsoft.GamingServices"
#     "Microsoft.Microsoft3DViewer"
#     "Microsoft.WindowsFeedbackHub"
#     "Microsoft.MicrosoftOfficeHub"
#     #"Microsoft.MixedReality.Portal"
#     #"Microsoft.MicrosoftPowerBIForWindows"
#     "Microsoft.MicrosoftSolitaireCollection"
#     #"Microsoft.MicrosoftStickyNotes"
#     #"Microsoft.MinecraftUWP"
#     "Microsoft.NetworkSpeedTest"
#     "Microsoft.Office.OneNote"
#     #"Microsoft.People"
#     "Microsoft.Print3D"
#     "Microsoft.SkypeApp"
#     "Microsoft.Wallet"
#     "Microsoft.Windows.Photos"
#     # "Microsoft.WindowsAlarms"
#     # "Microsoft.WindowsCalculator"
#     # "Microsoft.WindowsCamera"
#     #"microsoft.windowscommunicationsapps"
#     #"Microsoft.WindowsMaps"
#     "Microsoft.WindowsPhone"
#     #"Microsoft.WindowsSoundRecorder"
#     #"Microsoft.WindowsStore"   # can't be re-installed
#     #"Microsoft.Xbox.TCUI"
#     #"Microsoft.XboxApp"
#     #"Microsoft.XboxGameOverlay"
#     #"Microsoft.XboxGamingOverlay"
#     #"Microsoft.XboxSpeechToTextOverlay"
#     "Microsoft.YourPhone"
#     "Microsoft.ZuneMusic"
#     "Microsoft.ZuneVideo"
#     "Microsoft.Windows.CloudExperienceHost"
#     "Microsoft.Windows.ContentDeliveryManager"
#     "Microsoft.Windows.PeopleExperienceHost"
#     #"Microsoft.XboxGameCallableUI"

#     # Threshold 2 apps
#     "Microsoft.CommsPhone"
#     #"Microsoft.ConnectivityStore"
#     "Microsoft.GetHelp"
#     #"Microsoft.Getstarted"
#     #"Microsoft.Messaging"
#     "Microsoft.Office.Sway"
#     "Microsoft.OneConnect"
#     "Microsoft.WindowsFeedbackHub"

#     # Creators Update apps
#     "Microsoft.Microsoft3DViewer"
#     #"Microsoft.MSPaint"

#     #Redstone apps
#     "Microsoft.BingFoodAndDrink"
#     "Microsoft.BingHealthAndFitness"
#     "Microsoft.BingTravel"
#     "Microsoft.WindowsReadingList"

#     # Redstone 5 apps
#     #"Microsoft.MixedReality.Portal"
#     "Microsoft.ScreenSketch"
#     #"Microsoft.XboxGamingOverlay"
#     "Microsoft.YourPhone"

#     # non-Microsoft
#     "2FE3CB00.PicsArt-PhotoStudio"
#     "46928bounde.EclipseManager"
#     "4DF9E0F8.Netflix"
#     "613EBCEA.PolarrPhotoEditorAcademicEdition"
#     "6Wunderkinder.Wunderlist"
#     "7EE7776C.LinkedInforWindows"
#     "89006A2E.AutodeskSketchBook"
#     "9E2F88E3.Twitter"
#     "A278AB0D.DisneyMagicKingdoms"
#     "A278AB0D.MarchofEmpires"
#     "ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
#     "CAF9E577.Plex"  
#     "ClearChannelRadioDigital.iHeartRadio"
#     "D52A8D61.FarmVille2CountryEscape"
#     "D5EA27B7.Duolingo-LearnLanguagesforFree"
#     "DB6EA5DB.CyberLinkMediaSuiteEssentials"
#     "DolbyLaboratories.DolbyAccess"
#     "DolbyLaboratories.DolbyAccess"
#     "Drawboard.DrawboardPDF"
#     "Facebook.Facebook"
#     "Fitbit.FitbitCoach"
#     "Flipboard.Flipboard"
#     "GAMELOFTSA.Asphalt8Airborne"
#     "KeeperSecurityInc.Keeper"
#     "NORDCURRENT.COOKINGFEVER"
#     "PandoraMediaInc.29680B314EFC2"
#     "Playtika.CaesarsSlotsFreeCasino"
#     "ShazamEntertainmentLtd.Shazam"
#     "SlingTVLLC.SlingTV"
#     "SpotifyAB.SpotifyMusic"
#     #"TheNewYorkTimes.NYTCrossword"
#     "ThumbmunkeysLtd.PhototasticCollage"
#     "TuneIn.TuneInRadio"
#     "WinZipComputing.WinZipUniversal"
#     "XINGAG.XING"
#     "flaregamesGmbH.RoyalRevolt2"
#     "king.com.*"
#     "king.com.BubbleWitch3Saga"
#     "king.com.CandyCrushSaga"
#     "king.com.CandyCrushSodaSaga"

#     # apps which cannot be removed using Remove-AppxPackage
#     #"Microsoft.BioEnrollment"
#     #"Microsoft.MicrosoftEdge"
#     #"Microsoft.Windows.Cortana"
#     #"Microsoft.WindowsFeedback"
#     #"Microsoft.XboxGameCallableUI"
#     #"Microsoft.XboxIdentityProvider"
#     #"Windows.ContactSupport"

#     # apps which other apps depend on
#     "Microsoft.Advertising.Xaml"
# )

# foreach ($app in $apps) {
#     Write-Output "Trying to remove $app"

#     Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

#     Get-AppXProvisionedPackage -Online |
#         Where-Object DisplayName -EQ $app |
#         Remove-AppxProvisionedPackage -Online
# }

# # Prevents Apps from re-installing
# $cdm = @(
#     "ContentDeliveryAllowed"
#     "FeatureManagementEnabled"
#     "OemPreInstalledAppsEnabled"
#     "PreInstalledAppsEnabled"
#     "PreInstalledAppsEverEnabled"
#     "SilentInstalledAppsEnabled"
#     "SubscribedContent-314559Enabled"
#     "SubscribedContent-338387Enabled"
#     "SubscribedContent-338388Enabled"
#     "SubscribedContent-338389Enabled"
#     "SubscribedContent-338393Enabled"
#     "SubscribedContentEnabled"
#     "SystemPaneSuggestionsEnabled"
# )

# New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
# foreach ($key in $cdm) {
#     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
# }

# New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

# # Prevents "Suggested Applications" returning
# New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

# #   Description:
# # This script will remove and disable OneDrive integration.

# Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1
# Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

# Write-Output "Kill OneDrive process"
# taskkill.exe /F /IM "OneDrive.exe"
# taskkill.exe /F /IM "explorer.exe"

# #Write-Output "Remove OneDrive"
# #if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
# #    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
# #}
# #if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
# #    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
# #}

# #Write-Output "Removing OneDrive leftovers"
# #Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
# #Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
# #Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# # check if directory is empty before removing:
# #If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
# #    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
# #}

# Write-Output "Disable OneDrive via Group Policies"
# New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

# Write-Output "Remove Onedrive from explorer sidebar"
# New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
# mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
# Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
# mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
# Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
# Remove-PSDrive "HKCR"


# # Thank you Matthew Israelsson
# Write-Output "Removing run hook for new users"
# reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
# reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
# reg unload "hku\Default"

# Write-Output "Removing startmenu entry"
# Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

# Write-Output "Removing scheduled task"
# Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

# Write-Output "Restarting explorer"
# Start-Process "explorer.exe"

# Write-Output "Waiting for explorer to complete loading"
# Start-Sleep 10

# #Write-Output "Removing additional OneDrive leftovers"
# #foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
# #    Takeown-Folder $item.FullName
# #    Remove-Item -Recurse -Force $item.FullName
# #}



# # Remove Password Age Limit (Passwords never expire) #

# net accounts /maxpwage:0


# # Set Password Age Limit to 60 Days#

# #net accounts /maxpwage:60


# # This script removes all Start Menu Tiles from the .default user #

# Set-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -Value '<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <LayoutOptions StartTileGroupCellWidth="6" />'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <DefaultLayoutOverride>'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <StartLayoutCollection>'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:StartLayout GroupCellWidth="6" />'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </StartLayoutCollection>'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  </DefaultLayoutOverride>'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <CustomTaskbarLayoutCollection>'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:TaskbarLayout>'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        <taskbar:TaskbarPinList>'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:UWA AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        </taskbar:TaskbarPinList>'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      </defaultlayout:TaskbarLayout>'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </CustomTaskbarLayoutCollection>'
# Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '</LayoutModificationTemplate>'

# $START_MENU_LAYOUT = @"
# <LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
#     <LayoutOptions StartTileGroupCellWidth="6" />
#     <DefaultLayoutOverride>
#         <StartLayoutCollection>
#             <defaultlayout:StartLayout GroupCellWidth="6" />
#         </StartLayoutCollection>
#     </DefaultLayoutOverride>
# </LayoutModificationTemplate>
# "@

# $layoutFile="C:\Windows\StartMenuLayout.xml"

# #Delete layout file if it already exists
# If(Test-Path $layoutFile)
# {
#     Remove-Item $layoutFile
# }

# #Creates the blank layout file
# $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

# $regAliases = @("HKLM", "HKCU")

# #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
# foreach ($regAlias in $regAliases){
#     $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
#     $keyPath = $basePath + "\Explorer" 
#     IF(!(Test-Path -Path $keyPath)) { 
#         New-Item -Path $basePath -Name "Explorer"
#     }
#     Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
#     Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
# }

# #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
# Stop-Process -name explorer
# Start-Sleep -s 5
# $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
# Start-Sleep -s 5

# #Enable the ability to pin items again by disabling "LockedStartLayout"
# foreach ($regAlias in $regAliases){
#     $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
#     $keyPath = $basePath + "\Explorer" 
#     Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
# }

# #Restart Explorer and delete the layout file
# Stop-Process -name explorer

# # Uncomment the next line to make clean start menu default for all new users
# Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

# Remove-Item $layoutFile


# # Prevents SYSPREP from freezing at "Getting Ready" on first boot                          #
# # NOTE, DMWAPPUSHSERVICE is a Keyboard and Ink telemetry service, and potential keylogger. #
# # It is recommended to disable this service in new builds, but SYSPREP will freeze/fail    #
# # if the service is not running. If SYSPREP will be used, add a FirstBootCommand to your   #
# # build to disable the service.                                                            #

# reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /f
# reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /t REG_DWORD /d "1"
# reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /f
# reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "2"
# # Add the line below to FirstBootCommand in answer file #
#  reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "disabledmwappushservice" /t REG_SZ /d "sc config dmwappushservice start= disabled"


# # Disable Privacy Settings Experience #
# # Also disables all settings in Privacy Experience #

# reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f
# reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
# reg delete "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
# reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
# reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
# reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
# reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f
# reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics" /f
# reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
# reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
# reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f
# reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics" /f
# reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
# reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
# reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f
# reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f
# reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
# reg delete "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Input" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
# reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
# reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
# reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
# reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
# reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f


# # Set Windows to Dark Mode #

# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
# reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
# reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
# reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
# reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
# reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
# reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
# reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
# reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f



##########
# Restart
##########


Write-Host
Write-Host "Press any key to restart your system..." -ForegroundColor Black -BackgroundColor White
$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host "Restarting..."
Restart-Computer
