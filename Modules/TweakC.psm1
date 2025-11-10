# ═══════════════════════════════════════════════════════════════════════════
# Module: TweakC.psm1 - ULTRA AGRESIVNÍ DEBLOAT (90 balíčků + HP)
# ═══════════════════════════════════════════════════════════════════════════
# REŽIM C: ULTRA AGRESIVNÍ  
# - 64 Microsoft balíčků
# - ~26 HP/OEM bloatware
# - ❌ ODSTRANÍ: MsStore, Kalkulačka, Fotky, Kalendář
# - ❌ ODSTRANÍ: Xbox App, Xbox Identity
# - ⚠️ VAROVÁNÍ: Odstraní většinu základních aplikací!
# ═══════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1
#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ═══════════════════════════════════════════════════════════════════════════
# IMPORT CORE MODULE (REQUIRED FOR PRIVILEGE OPERATIONS)
# ═══════════════════════════════════════════════════════════════════════════
# Use Core module functions - loaded by Main.ps1, only import if standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $CoreModule = Join-Path $PSScriptRoot 'Core.psm1'
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    } else {
        Write-Error "CRITICAL: Core.psm1 not found at: $CoreModule"
        throw "Missing dependency: Core.psm1"
    }
}

function Get-TweakCRegContent {
    [CmdletBinding()]
    param()

    return @'
Windows Registry Editor Version 5.00

; ================================================================
; KRAKE-FIX Registry Tweaks - REŽIM C (ULTRA AGRESIVNÍ)
; ================================================================

[-HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\Sharing]

[-HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}]
"System.IsPinnedToNameSpaceTree"=dword:0

[-HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Sharing]

[-HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Sharing]

[-HKEY_CLASSES_ROOT\Directory\shellex\CopyHookHandlers\Sharing]

[-HKEY_CLASSES_ROOT\Directory\shellex\PropertySheetHandlers\Sharing]

[-HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\Sharing]

[-HKEY_CLASSES_ROOT\Drive\shellex\PropertySheetHandlers\Sharing]

[-HKEY_CLASSES_ROOT\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing]

[-HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing]

[-HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}]
"System.IsPinnedToNameSpaceTree"=dword:0

[HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response]
"AutoRepeatDelay"="210"
"AutoRepeatRate"="22"
"BounceTime"="0"
"DelayBeforeAcceptance"="0"
"Flags"="0"
"Last BounceKey Setting"=dword:00000000
"Last Valid Delay"=dword:00000000
"Last Valid Repeat"=dword:00000000
"Last Valid Wait"=dword:00000000

[HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys]
"Flags"="0"
"MaximumSpeed"="80"
"TimeToMaximumSpeed"="0"

[HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics]
"MinAnimate"="0"

[HKEY_CURRENT_USER\Control Panel\Desktop]
"AutoEndTasks"="1"
"HungAppTimeout"="70"
"MenuShowDelay"="0"
"WaitToKillAppTimeout"="200"
"LowLevelHooksTimeout"="100"

[HKEY_CURRENT_USER\Control Panel\Keyboard]
"InitialKeyboardIndicators"="2"
"KeyboardDelay"=dword:00000000
"KeyboardSpeed"="31"

[HKEY_CURRENT_USER\Control Panel\Mouse]
"ActiveWindowTracking"=dword:00000000
"Beep"="No"
"DoubleClickHeight"="4"
"DoubleClickSpeed"="225"
"DoubleClickWidth"="4"
"ExtendedSounds"="No"
"MouseHoverHeight"="4"
"MouseHoverTime"="0"
"MouseHoverWidth"="0"
"MouseSensitivity"="10"
"MouseSpeed"="0"
"MouseThreshold1"="0"
"MouseThreshold2"="0"
"MouseTrails"="0"
"SnapToDefaultButton"="0"
"SwapMouseButtons"="0"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32]
@=""

[HKEY_CURRENT_USER\Software\Microsoft\GameBar]
"AllowAutoGameMode"=dword:00000000
"AutoGameModeEnabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC]
"Enabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization\TrainedDataStore]
"HarvestContacts"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization]
"RestrictImplicitInkCollection"=dword:00000001
"RestrictImplicitTextCollection"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Personalization\Settings]
"AcceptedPrivacyPolicy"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules]
"NumberOfSIUFInPeriod"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy]
"HasAccepted"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo]
"Enabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications]
"GlobalUserDisabled"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]
"SilentInstalledAppsEnabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration]
"IsResumeAllowed"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People]
"PeopleBand"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ShowCopilotButton"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager]
"EnthusiastMode"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize]
"StartupDelayInMSec"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects]
"VisualFXSetting"=dword:00000003

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds]
"ShellFeedsTaskbarViewMode"=dword:00000002

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR]
"AppCaptureEnabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Mobility]
"OptedIn"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.BackupReminder]
"Enabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested]
"Enabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun]
"DisableEdge"="msedge.exe"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"NoLowDiskSpaceChecks"=dword:00000001
"LinkResolveIgnoreLinkInfo"=dword:00000001
"NoResolveSearch"=dword:00000001
"NoResolveTrack"=dword:00000001
"NoInternetOpenWith"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy]
"TailoredExperiencesWithDiagnosticDataEnabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications]
"ToastEnabled"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search]
"SearchboxTaskbarMode"=dword:00000000
"BingSearchEnabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start\Companions\Microsoft.YourPhone_8wekyb3d8bbwe]
"IsEnabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications]
"EnableAccountNotifications"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize]
"EnableTransparency"=dword:00000000
"SystemUsesLightTheme"=dword:00000000
"AppsUseLightTheme"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement]
"ScoobeSystemSettingEnabled"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsCopilot]
"AllowCopilotRuntime"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\DWM]
"EnableAeroPeek"=dword:00000000
"AlwaysHibernateThumbnails"=dword:00000000

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent]
"DisableSpotlightCollectionOnDesktop"=dword:00000001

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI]
"DisableMFUTracking"=dword:00000001

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer]
"NoWindowMinimizingShortcuts"=dword:00000001

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI]
"DisableAIDataAnalysis"=dword:00000001

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsCopilot]
"TurnOffWindowsCopilot"=dword:00000001

[HKEY_CURRENT_USER\System\GameConfigStore]
"GameDVR_Enabled"="0"
"GameDVR_FSEBehavior"=dword:00000002
"GameDVR_FSEBehaviorMode"=dword:00000002
"GameDVR_DXGIHonorFSEWindowsCompatible"=dword:00000001
"GameDVR_HonorUserFSEBehaviorMode"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed]
"CursorUpdateInterval"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR]
"value"="00000000"
"GameDVR_Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio]
"Affinity"=dword:00000007
"Background Only"="True"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000006
"Scheduling Category"="Medium"
"SFIO Priority"="Normal"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing]
"Affinity"=dword:00000000
"Background Only"="True"
"BackgroundPriority"=dword:00000008
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000008
"Scheduling Category"="High"
"SFIO Priority"="High"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
"Affinity"=dword:00000000
"Background Only"="False"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000006
"Scheduling Category"="High"
"SFIO Priority"="High"
"IO Priority"="High"
"IOLatencyPolicy"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"SystemResponsiveness"=dword:00000000
"NetworkThrottlingIndex"=dword:ffffffff
"NoLazyMode"=dword:00000001
"AlwaysOn"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata]
"PreventDeviceMetadataFromNetwork"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching]
"SearchOrderConfig"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection]
"AllowTelemetry"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableBackButtonAppNav"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh]
"AllowNewsAndInterests"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge]
"PersonalizationReportingEnabled"=dword:00000000
"DiagnosticData"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat]
"AITEnable"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent]
"DisableWindowsConsumerFeatures"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection]
"AllowTelemetry"=dword:00000000
"MaxTelemetryAllowed"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR]
"AllowGameDVR"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds]
"AllowBuildPreview"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched]
"NonBestEffortLimit"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"PublishUserActivities"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds]
"EnableFeeds"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search]
"AllowCortana"=dword:00000000
"BingSearchEnabled"=dword:00000000
"CortanaConsent"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI]
"TurnOffSavingSnapshots"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot]
"TurnOffWindowsCopilot"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
"ExcludeWUDriversInQualityUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D]
"MaxPreRenderedFrames"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy]
"DisableTaggedEnergyLogging"=dword:00000001
"TelemetryMaxApplication"=dword:00000000
"TelemetryMaxTagPerApplication"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583]
"Attributes"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb]
"Attributes"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7]
"Attributes"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028]
"Attributes"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"EnergyEstimationEnabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=dword:00000024

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters]
"EnablePrefetcher"=dword:00000000
"EnableSuperfetch"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"LargeSystemCache"=dword:00000000
"DisablePagingExecutive"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control]
"WaitToKillServiceTimeout"="150"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidi2c\Parameters]
"WppRecorder_UseTimeStamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidspi\Parameters]
"WppRecorder_UseTimeStamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidUsb\Parameters]
"WppRecorder_UseTimeStamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidUsb]
"UseRawInputService"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters]
"WppRecorder_UseTimeStamp"=dword:00000000
"ConnectMultiplePorts"=dword:00000000
"KeyboardDataQueueSize"=dword:00000032
"KeyboardDeviceBaseName"="KeyboardClass"
"MaximumPortsServiced"=dword:00000003
"SendOutputToAllPorts"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters]
"WorkNicely"=dword:00000000
"WppRecorder_UseTimeStamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters]
"WppRecorder_UseTimeStamp"=dword:00000000
"MouseDataQueueSize"=dword:00000032

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid\Parameters]
"UseOnlyMice"=dword:00000000
"TreatAbsoluteAsRelative"=dword:00000000
"TreatAbsolutePointerAsAbsolute"=dword:00000000
"WppRecorder_UseTimeStamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USB]
"DisableSelectiveSuspend"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBPORT\Parameters]
"EnablePortReset"=dword:00000001
"DisableSelectiveSuspend"=dword:00000001
"EnhancedPowerMgmtEnabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xbgm]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc]
"Start"=dword:00000004

'@
}

$UtilsModule = Join-Path $PSScriptRoot 'Utils.psm1'
if (-not (Get-Command -Name Get-RegistryItemPrivilege -ErrorAction SilentlyContinue)) {
    if (Test-Path -Path $UtilsModule) {
        Import-Module $UtilsModule -Force -ErrorAction Stop
    }
}

$script:TweakCRegistryListCache = $null

function Convert-TweakCRegistryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RawPath
    )

    $trimmedPath = $RawPath.Trim()
    $hasDeletionPrefix = $false

    if ($trimmedPath.StartsWith('-', [System.StringComparison]::Ordinal)) {
        $hasDeletionPrefix = $true
        $trimmedPath = $trimmedPath.Substring(1)
    }

    $convertedPath = $trimmedPath
    $convertedPath = $convertedPath -replace '^HKEY_LOCAL_MACHINE', 'HKLM:'
    $convertedPath = $convertedPath -replace '^HKEY_CURRENT_USER', 'HKCU:'
    $convertedPath = $convertedPath -replace '^HKEY_CLASSES_ROOT', 'HKCR:'
    $convertedPath = $convertedPath -replace '^HKEY_USERS', 'HKU:'
    $convertedPath = $convertedPath -replace '^HKEY_CURRENT_CONFIG', 'HKCC:'

    if ($hasDeletionPrefix) {
        return '-' + $convertedPath
    }

    return $convertedPath
}

$script:TweakCServiceList = @(    
)


function Get-TweakCServiceList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return $script:TweakCServiceList
}

function Invoke-TweakC {
    [CmdletBinding()]
    param()

    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  TWEAK C - ULTRA AGRESIVNÍ DEBLOAT (90 balíčků + HP + EDGE)" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "⚠️  VAROVÁNÍ: Tento režim odstraní Store, Xbox a Edge!" -ForegroundColor Red
    Write-Host ""

    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 1: REGISTRY TWEAKS (S SYSTEM OPRÁVNĚNÍMI!)
    # ═══════════════════════════════════════════════════════════════════════
    Write-Host "FÁZE 1: APLIKUJI REGISTRY TWEAKS..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  🔐 Spouštím s SYSTEM oprávněními..." -ForegroundColor Cyan
    Write-Host ""

    $regContent = Get-TweakCRegContent
    
    # ScriptBlock pro SYSTEM kontext
    $applyRegistryBlock = {
        param($RegContent)
        
        $appliedCount = 0
        $currentPath = $null
        $regLines = $RegContent -split '\r?\n'

        foreach ($line in $regLines) {
            $line = $line.Trim()

            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith(';') -or $line -eq 'Windows Registry Editor Version 5.00') {
                continue
            }

            # MAZÁNÍ CELÉ SEKCE
            if ($line -match '^\[-(.+?)\]$') {
                $regPath = $matches[1].Trim()
                $psPath = $regPath -replace 'HKEY_LOCAL_MACHINE', 'HKLM:' `
                                   -replace 'HKEY_CURRENT_USER', 'HKCU:' `
                                   -replace 'HKEY_CLASSES_ROOT', 'HKCR:' `
                                   -replace 'HKEY_USERS', 'HKU:'
                
                if (Test-Path $psPath) {
                    try {
                        Remove-Item -Path $psPath -Recurse -Force -ErrorAction Stop
                        Write-Verbose "Removed registry key: $psPath"
                        $appliedCount++
                    } catch {
                        Write-Warning "Failed to remove registry key: $psPath - $($_.Exception.Message)"
                    }
                }
                $currentPath = $null
                continue
            }
            
            # NASTAVENÍ AKTUÁLNÍ CESTY
            if ($line -match '^\[(.+?)\]$') {
                $regPath = $matches[1].Trim()
                $currentPath = $regPath -replace 'HKEY_LOCAL_MACHINE', 'HKLM:' `
                                        -replace 'HKEY_CURRENT_USER', 'HKCU:' `
                                        -replace 'HKEY_CLASSES_ROOT', 'HKCR:' `
                                        -replace 'HKEY_USERS', 'HKU:'

                # Vytvoříme cestu pokud neexistuje
                if (-not (Test-Path $currentPath)) {
                    try {
                        New-Item -Path $currentPath -Force -ErrorAction Stop | Out-Null
                    } catch {
                        $currentPath = $null
                        continue
                    }
                }
                continue
            }

            # ZPRACOVÁNÍ HODNOT
            if ($null -ne $currentPath -and $line -match '^\"([^\"]+)\"=(.+)$') {
                $valueName = $matches[1].Trim()
                $valueData = $matches[2].Trim()
                
                try {
                    if ($valueData -eq '-') {
                        # ODSTRANĚNÍ HODNOTY
                        Remove-ItemProperty -Path $currentPath -Name $valueName -ErrorAction Stop
                        $appliedCount++
                    }
                    elseif ($valueData -match '^dword:([0-9a-fA-F]{8})$') {
                        # DWORD HODNOTA
                        $number = $valueData -replace 'dword:', ''
                        $value = [Convert]::ToInt32($number, 16)
                        Set-ItemProperty -Path $currentPath -Name $valueName -Value $value -Type DWord -ErrorAction Stop
                        $appliedCount++
                    }
                    elseif ($valueData -match '^\"(.*)\"$') {
                        # STRING HODNOTA
                        $value = $matches[1]
                        Set-ItemProperty -Path $currentPath -Name $valueName -Value $value -Type String -ErrorAction Stop
                        $appliedCount++
                    }
                }
                catch {
                    Write-Warning "Failed to set registry value: $currentPath\$valueName - $($_.Exception.Message)"
                }
            }
        }
        
        return $appliedCount
    }
    
    # SPUSTIT JAKO SYSTEM
    try {
        $appliedCount = Invoke-AsSystem -ScriptBlock $applyRegistryBlock -ArgumentList $regContent -TimeoutSeconds 60
        Write-Host "  ✅ Aplikováno: $appliedCount registry hodnot (SYSTEM režim)" -ForegroundColor Green
    }
    catch {
        Write-Host "  ❌ Chyba při aplikaci registry: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""

    
    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 2: SCHEDULED TASKS (NAPLÁNOVANÉ ÚLOHY - REDUKCE PROCESŮ!)
    # ═══════════════════════════════════════════════════════════════════════
    Write-Host "FÁZE 3: VYPÍNÁM SCHEDULED TASKS (REDUKCE PROCESŮ)..." -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  🔐 Spouštím s SYSTEM oprávněními..." -ForegroundColor Cyan

    # Seznam úloh k vypnutí
    $tasksToDisableList = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\PcaPatchDbTask",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
		"\Microsoft\Windows\AppxDeploymentClient\NotifyAppLastUsed",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
		"\Microsoft\Windows\CloudNotifications\CloudNotificationsProcessing",
        "\Microsoft\Windows\Defrag\ScheduledDefrag",
        "\Microsoft\Windows\Device Information\Device",
        "\Microsoft\Windows\Device Information\Device User",
        "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner",
        "\Microsoft\Windows\Diagnosis\Scheduled",
        "\Microsoft\Windows\DiskCleanup\SilentCleanup",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\DiskFootprint\Diagnostics",
        "\Microsoft\Windows\DiskFootprint\StorageSense",
        "\Microsoft\Windows\DUSM\dusmtask",
        "\Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\FileHistory\File History (maintenance mode)",
        "\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures",
        "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing",
        "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting",
        "\Microsoft\Windows\Flighting\OneSettings\RefreshCache",
        "\Microsoft\Windows\Input\LocalUserSyncDataAvailable",
        "\Microsoft\Windows\Input\MouseSyncDataAvailable",
        "\Microsoft\Windows\Input\PenSyncDataAvailable",
        "\Microsoft\Windows\Input\TouchpadSyncDataAvailable",
        "\Microsoft\Windows\International\Synchronize Language Settings",
        "\Microsoft\Windows\LanguageComponentsInstaller\Installation",
        "\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources",
        "\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation",
        "\Microsoft\Windows\License Manager\TempSignedLicenseExchange",
        "\Microsoft\Windows\Management\Provisioning\Cellular",
        "\Microsoft\Windows\Management\Provisioning\Logon",
        "\Microsoft\Windows\Maintenance\WinSAT",
        "\Microsoft\Windows\Maps\MapsToastTask",
        "\Microsoft\Windows\Maps\MapsUpdateTask",
        "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser",
        "\Microsoft\Windows\MUI\LPRemove",
        "\Microsoft\Windows\NetTrace\GatherNetworkInfo",
        "\Microsoft\Windows\PI\Sqm-Tasks",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
        "\Microsoft\Windows\PushToInstall\Registration",
        "\Microsoft\Windows\Retail Demo\CleanupOfflineContent",
        "\Microsoft\Windows\Retail Demo\RetailDemo",
        "\Microsoft\Windows\RetailDemo\CleanupOfflineContent",
        "\Microsoft\Windows\SettingSync\NetworkStateChangeTask",
        "\Microsoft\Windows\Setup\SetupCleanupTask",
        "\Microsoft\Windows\Setup\SnapshotCleanupTask",
	"\Microsoft\Windows\Shell\CreateObjectTask",
        "\Microsoft\Windows\SpacePort\SpaceAgentTask",
        "\Microsoft\Windows\SpacePort\SpaceManagerTask",
        "\Microsoft\Windows\Speech\SpeechModelDownloadTask",
        "\Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization",
        "\Microsoft\Windows\Subscription\EnableLicenseAcquisition",
        "\Microsoft\Windows\Subscription\LicenseAcquisition",
        "\Microsoft\Windows\Sysmain\ResPriStaticDbSync",
        "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask",
	"\Microsoft\Windows\OneDrive\OneDrive Standalone Update Task",
        "\Microsoft\Windows\Task Manager\Interactive",
        "\Microsoft\Windows\TPM\Tpm-HASCertRetr",
        "\Microsoft\Windows\TPM\Tpm-Maintenance",
        "\Microsoft\Windows\UPnP\UPnPHostConfig",
        "\Microsoft\Windows\User Profile Service\HiveUploadTask",
        "\Microsoft\Windows\WDI\ResolutionHost",
        "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
        "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
        "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
        "\Microsoft\Windows\Windows Defender\Windows Defender Verification",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange",
        "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary",
        "\Microsoft\Windows\WindowsBackup\ConfigNotification",
        "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
        "\Microsoft\Windows\Wininet\CacheTask",
        "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization",
        "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work",
        "\Microsoft\Windows\Workplace Join\Automatic-Device-Join",
        "\Microsoft\XblGameSave\XblGameSaveTask",
        "\Microsoft\XblGameSave\XblGameSaveTaskLogon"
    )

    # ScriptBlock pro SYSTEM kontext
    $disableTasksBlock = {
        param($tasksList)
        
        $successCount = 0
        $failCount = 0
        
        foreach ($taskPath in $tasksList) {
            try {
                if ($taskPath.Contains('\')) {
                    $path = $taskPath.Substring(0, $taskPath.LastIndexOf('\') + 1)
                    $name = $taskPath.Substring($taskPath.LastIndexOf('\') + 1)
                    
                    $task = Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
                    if ($task -and $task.State -ne 'Disabled') {
                        Disable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction Stop | Out-Null
                        $successCount++
                    }
                }
            }
            catch {
                $failCount++
            }
        }
        
        return @{
            Success = $successCount
            Failed = $failCount
        }
    }

    # Spustit jako SYSTEM
    try {
        $result = Invoke-AsSystem -ScriptBlock $disableTasksBlock -ArgumentList (,$tasksToDisableList)
        
        if ($null -ne $result -and $result -is [hashtable]) {
            Write-Host "  ✅ Zakázáno: $($result.Success) naplánovaných úloh (SYSTEM režim)" -ForegroundColor Green
            if ($result.Failed -gt 0) {
                Write-Host "  ⚠️  Selhalo: $($result.Failed) úloh (neexistují nebo chráněné)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  ⚠️  SYSTEM eskalace vrátila neplatný výsledek - zkouším jako Admin..." -ForegroundColor Yellow
            
            # Fallback - zkusit jako běžný Admin
            $disabledTaskCount = 0
            foreach ($taskPath in $tasksToDisableList) {
                try {
                    if ($taskPath.Contains('\')) {
                        $path = $taskPath.Substring(0, $taskPath.LastIndexOf('\') + 1)
                        $name = $taskPath.Substring($taskPath.LastIndexOf('\') + 1)
                        
                        $task = Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
                        if ($task -and $task.State -ne 'Disabled') {
                            Disable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue | Out-Null
                            $disabledTaskCount++
                        }
                    }
                }
                catch { }
            }
            Write-Host "  ✅ Zakázáno: $disabledTaskCount úloh (Admin režim)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ❌ Chyba při vypínání úloh: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""

    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 3: APPX BALÍČKY (ULTRA AGRESIVNÍ - 90 balíčků)
    # ═══════════════════════════════════════════════════════════════════════
    Write-Host "FÁZE 4: ODSTRAŇUJI APPX BALÍČKY (ULTRA - 90 balíčků)..." -ForegroundColor Yellow
    Write-Host ""

    # HP/OEM bloatware (úplný seznam pro ULTRA režim)
    $hpOemBloatware = @("ACGMediaPlayer", "ActiproSoftwareLLC", "AD2F1837.HPAIExperienceCenter", "AD2F1837.HPConnectedMusic", "AD2F1837.HPConnectedPhotopoweredbySnapfish", "AD2F1837.HPDesktopSupportUtilities", "AD2F1837.HPEasyClean", "AD2F1837.HPFileViewer", "AD2F1837.HPJumpStarts", "AD2F1837.HPPCHardwareDiagnosticsWindows", "AD2F1837.HPPowerManager", "AD2F1837.HPPrinterControl", "AD2F1837.HPPrivacySettings", "AD2F1837.HPQuickDrop", "AD2F1837.HPQuickTouch", "AD2F1837.HPRegistration", "AD2F1837.HPSupportAssistant", "AD2F1837.HPSureShieldAI", "AD2F1837.HPSystemInformation", "AD2F1837.HPWelcome", "AD2F1837.HPWorkWell", "AD2F1837.myHP", "AdobeSystemsIncorporated.AdobePhotoshopExpress", "Amazon.com.Amazon", "AmazonVideo.PrimeVideo", "Asphalt8Airborne", "AutodeskSketchBook", "CaesarsSlotsFreeCasino", "Clipchamp.Clipchamp", "COOKINGFEVER", "CyberLinkMediaSuiteEssentials", "Disney", "DisneyMagicKingdoms", "DrawboardPDF", "Duolingo-LearnLanguagesforFree", "EclipseManager", "Facebook", "FarmVille2CountryEscape", "fitbit", "Flipboard", "HiddenCity", "HULULLC.HULUPLUS", "iHeartRadio", "Instagram", "king.com.BubbleWitch3Saga", "king.com.CandyCrushSaga", "CandyCrushSodaSaga", "LinkedInforWindows", "MarchofEmpires", "NYTCrossword", "OneCalendar", "PandoraMediaInc", "PhototasticCollage", "PicsArt-PhotoStudio", "Plex", "PolarrPhotoEditorAcademicEdition", "Royal Revolt", "Shazam", "Sidia.LiveWallpaper", "SlingTV", "TikTok", "TuneInRadio", "Twitter", "Viber", "WinZipUniversal", "Wunderlist", "XING", "4DF9E0F8.Netflix", "SpotifyAB.SpotifyMusic")

    # Microsoft apps - ULTRA AGRESIVNÍ (64 balíčků)
    # ❌ ODSTRANÍ: Store, Kalkulačka, Fotky, Kalendář, Xbox App, Xbox Identity
    $msApps_Ultra = @("Microsoft.549981C3F5F10", "Microsoft.3DBuilder", "Microsoft.BingFinance", "Microsoft.BingFoodAndDrink", "Microsoft.BingHealthAndFitness", "Microsoft.BingNews", "Microsoft.BingSearch", "Microsoft.BingSports", "Microsoft.BingTranslator", "Microsoft.BingTravel", "Microsoft.BingWeather", "Microsoft.Copilot", "Microsoft.GamingApp", "Microsoft.GamingServices", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftJournal", "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftPowerBIForWindows", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MicrosoftStickyNotes", "Microsoft.MinecraftUWP", "Microsoft.MixedReality.Portal", "Microsoft.NetworkSpeedTest", "Microsoft.News", "Microsoft.Office.OneNote", "Microsoft.Office.Sway", "Microsoft.OneConnect", "Microsoft.OneDrive", "Microsoft.OutlookForWindows", "Microsoft.People", "Microsoft.PowerAutomateDesktop", "Microsoft.Print3D", "Microsoft.RemoteDesktop", "Microsoft.ScreenSketch", "Microsoft.SkypeApp", "Microsoft.StartExperiencesApp", "Microsoft.Todos", "Microsoft.Wallet", "Microsoft.Whiteboard", "Microsoft.Windows.DevHome", "Microsoft.Windows.Photos", "Microsoft.WindowsAlarms", "Microsoft.WindowsCalculator", "Microsoft.WindowsCamera", "microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsPhone", "Microsoft.WindowsSoundRecorder", "Microsoft.Xbox.TCUI", "Microsoft.XboxApp", "Microsoft.XboxGameOverlay", "Microsoft.XboxGamingOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "MicrosoftCorporationII.MicrosoftFamily", "MicrosoftCorporationII.QuickAssist", "MicrosoftTeams", "MSTeams")

    $appsToRemove = $msApps_Ultra + $hpOemBloatware

    Write-Host "  -> Celkem k odstranění: $($appsToRemove.Count) balíčků" -ForegroundColor Cyan
    Write-Host "  -> ⚠️  ODSTRANÍ: Store, Xbox, Kalkulačka, Fotky!" -ForegroundColor Red
    Write-Host "  -> Odstraňuji přímo jako Administrator..." -ForegroundColor Yellow

    # PŘÍMÉ ODSTRANĚNÍ jako Administrator - funguje lépe než SYSTEM eskalace
    $removedCount = 0
    
    foreach ($appName in $appsToRemove) {
        try {
            # Odstranění nainstalovaných balíčků pro všechny uživatele
            $packages = Get-AppxPackage -Name "*$appName*" -AllUsers -ErrorAction SilentlyContinue
            foreach ($pkg in $packages) {
                try {
                    Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                    $removedCount++
                    Write-Host "    🗑️ $($pkg.Name)" -ForegroundColor Red
                } catch { }
            }

            # Odstranění provisionovaných balíčků (pro nové uživatele)
            $provPackages = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$appName*" }
            foreach ($provPkg in $provPackages) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $provPkg.PackageName -ErrorAction SilentlyContinue
                    Write-Host "    📦 $($provPkg.DisplayName)" -ForegroundColor DarkRed
                } catch { }
            }
        }
        catch {
            # Tiché pokračování
        }
    }

    Write-Host "  ✅ Odstraněno: $removedCount balíčků" -ForegroundColor Green
    Write-Host ""

    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 4: MICROSOFT EDGE UNINSTALL (ULTRA AGGRESSIVE ONLY)
    # ═══════════════════════════════════════════════════════════════════════
    Write-Host "FÁZE 4b: ODSTRAŇUJI MICROSOFT EDGE..." -ForegroundColor Magenta
    Write-Host ""

    try {
        $edgeSetupPath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*\Installer\setup.exe"
        $edgeSetup = Get-Item -Path $edgeSetupPath -ErrorAction SilentlyContinue | Sort-Object -Property FullName -Descending | Select-Object -First 1
        
        if ($edgeSetup) {
            Write-Host "  -> Spouštím Edge uninstaller: $($edgeSetup.FullName)" -ForegroundColor Yellow
            Start-Process -FilePath $edgeSetup.FullName -ArgumentList "--uninstall --force-uninstall --system-level" -Wait -NoNewWindow -ErrorAction Stop
            Write-Host "  ✅ Microsoft Edge odstraněn!" -ForegroundColor Green
        } 
        else {
            Write-Host "  ⚠️  Edge setup.exe nenalezen, možná už byl odstraněn." -ForegroundColor Yellow
        }
    } 
    catch {
        Write-Host "  ❌ Chyba při odstraňování Edge: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""

    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 5: FSUTIL OPTIMALIZACE (SSD)
    # ═══════════════════════════════════════════════════════════════════════
    Write-Host "FÁZE 5: FSUTIL OPTIMALIZACE (SSD)..." -ForegroundColor Yellow
    Write-Host ""

    try {
        Start-Process -FilePath "fsutil.exe" -ArgumentList "behavior", "set", "DisableLastAccess", "1" -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "  ✅ DisableLastAccess = 1" -ForegroundColor Green
    }
    catch {
        Write-Warning "  ⚠️  fsutil DisableLastAccess selhal"
    }

    try {
        Start-Process -FilePath "fsutil.exe" -ArgumentList "behavior", "set", "EncryptPagingFile", "0" -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "  ✅ EncryptPagingFile = 0" -ForegroundColor Green
    }
    catch {
        Write-Warning "  ⚠️  fsutil EncryptPagingFile selhal"
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✅ TWEAK C DOKONČEN!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "⚠️  VAROVÁNÍ: Bez Store NELZE používat Xbox a Nvidia CP (UWP)!" -ForegroundColor Red
    Write-Host "💡 TIP: RESTART PC je NUTNÝ!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Get-TweakCRegistryList {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    if ($null -ne $script:TweakCRegistryListCache) {
        return $script:TweakCRegistryListCache
    }

    $regContent = Get-TweakCRegContent
    $lines = $regContent -split "`r?`n"
    $currentPath = $null
    $items = New-Object System.Collections.Generic.List[psobject]

    foreach ($rawLine in $lines) {
        $line = $rawLine.Trim()

        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line.StartsWith(';')) {
            continue
        }
        if ($line -eq 'Windows Registry Editor Version 5.00') {
            continue
        }

        if ($line -match '^\[(.+)\]$') {
            $currentPath = Convert-TweakCRegistryPath -RawPath $matches[1]
            continue
        }

        if ($null -eq $currentPath) {
            continue
        }

        if ($line -match '^"([^"]+)"=(.+)$') {
            $nameToken = $matches[1]
            $valueToken = $matches[2].Trim()

            $valueName = if ($nameToken -eq '@') { '(Default)' } else { $nameToken }

            $normalizedPath = $currentPath
            $isDeletionPath = $false
            if ($normalizedPath.StartsWith('-', [System.StringComparison]::Ordinal)) {
                $isDeletionPath = $true
                $normalizedPath = $normalizedPath.Substring(1)
            }

            $requiredPrivilege = 'Admin'
            if (-not [string]::IsNullOrWhiteSpace($normalizedPath) -and (Get-Command -Name Get-RegistryItemPrivilege -ErrorAction SilentlyContinue)) {
                try {
                    $requiredPrivilege = Get-RegistryItemPrivilege -Path $normalizedPath
                } catch {
                    $requiredPrivilege = 'Admin'
                }
            }

            $itemObject = [PSCustomObject]@{
                Path              = if ($isDeletionPath) { '-' + $normalizedPath } else { $normalizedPath }
                Name              = $valueName
                Value             = $valueToken
                RequiredPrivilege = $requiredPrivilege
            }

            $items.Add($itemObject)
        }
    }

    $script:TweakCRegistryListCache = $items.ToArray()
    return $script:TweakCRegistryListCache
}

function Get-TweakCSnapshot {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $registryItems = Get-TweakCRegistryList
    $snapshot = New-Object System.Collections.Generic.List[psobject]

    foreach ($item in $registryItems) {
        $queryPath = $item.Path
        $valueExists = $false
        $valueKind = 'None'
        $currentValue = 'ValueDoesNotExist'

        if ($queryPath.StartsWith('-', [System.StringComparison]::Ordinal)) {
            $queryPath = $queryPath.Substring(1)
        }

        if (-not [string]::IsNullOrWhiteSpace($queryPath) -and (Test-Path -LiteralPath $queryPath)) {
            try {
                $registryKey = Get-Item -LiteralPath $queryPath -ErrorAction Stop

                if ($item.Name -eq '(Default)') {
                    try {
                        $currentValue = $registryKey.GetValue('', $null)
                        $valueKind = $registryKey.GetValueKind('').ToString()
                        $valueExists = $true
                    } catch {
                        $currentValue = 'ValueDoesNotExist'
                        $valueKind = 'None'
                    }
                } else {
                    $valueNames = $registryKey.GetValueNames()
                    if ($valueNames -contains $item.Name) {
                        $currentValue = $registryKey.GetValue($item.Name, $null)
                        $valueKind = $registryKey.GetValueKind($item.Name).ToString()
                        $valueExists = $true
                    }
                }
            } catch {
                $currentValue = "ReadError: $($_.Exception.Message)"
                $valueKind = 'Error'
            }
        }

        $snapshot.Add([PSCustomObject]@{
            Path              = $item.Path
            Name              = $item.Name
            TargetValue       = $item.Value
            CurrentValue      = $currentValue
            ValueExists       = $valueExists
            ValueKind         = $valueKind
            RequiredPrivilege = $item.RequiredPrivilege
        })
    }

    return $snapshot.ToArray()
}

function Invoke-ModuleEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $ModuleContext
    )

    if ($null -eq $ModuleContext) {
        throw [System.ArgumentNullException]::new('ModuleContext')
    }

    Invoke-TweakC
}

Export-ModuleMember -Function @(
    'Invoke-TweakC',
    'Get-TweakCServiceList',
    'Get-TweakCRegistryList',
    'Get-TweakCSnapshot',
    'Invoke-ModuleEntry'
)

