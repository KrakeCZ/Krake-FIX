# ═══════════════════════════════════════════════════════════════════════════
# Module: TweakT.psm1 - Task Enable 
# ═══════════════════════════════════════════════════════════════════════════
# REŽIM T: Obnova povolení Task / Ůloh
# - Obnova úloh twaku B/ C - soupis C
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
    }
    else {
        Write-Error "CRITICAL: Core.psm1 not found at: $CoreModule"
        throw "Missing dependency: Core.psm1"
    }
}

function Invoke-TweakT {
    [CmdletBinding()]
    param()

    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  TWEAK T - Obnova Úloh/task" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "⚠️  Obnovuje úlohy/task !" -ForegroundColor Red
    Write-Host ""
    
    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 1: SCHEDULED TASKS (NAPLÁNOVANÉ ÚLOHY - Spuštění PROCESŮ!)
    # ═══════════════════════════════════════════════════════════════════════
    Write-Host "FÁZE 1: Zapínám SCHEDULED TASKS (Spuštění PROCESŮ)..." -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  🔐 Spouštím s SYSTEM oprávněními..." -ForegroundColor Cyan

    # Seznam úloh k zapnutí
    $tasksToEnableList = @(
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
    $EnableTasksBlock = {
        param($tasksList)
        
        $successCount = 0
        $failCount = 0
        
        foreach ($taskPath in $tasksList) {
            try {
                if ($taskPath.Contains('\')) {
                    $path = $taskPath.Substring(0, $taskPath.LastIndexOf('\') + 1)
                    $name = $taskPath.Substring($taskPath.LastIndexOf('\') + 1)
                    
                    # 1. Získání úlohy
                    $task = Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
                    
                    if ($null -ne $task) {
                        # 2. Povolení úlohy (Enable)
                        if ($task.State -ne 'Enabled') {
                            Enable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue | Out-Null
                        }
                        
                        # 3. Spuštění úlohy (Start) - Best effort
                        # Některé úlohy nelze spustit "on demand" (např. spouštěné událostí), ignorujeme chyby spuštění
                        Start-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue | Out-Null
                        
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
            Failed  = $failCount
        }
    }

    # Spustit jako SYSTEM
    try {
        $result = Invoke-AsSystem -ScriptBlock $EnableTasksBlock -ArgumentList (, $tasksToEnableList)
        
        if ($null -ne $result -and $result -is [hashtable]) {
            Write-Host "  ✅ Povoleno: $($result.Success) naplánovaných úloh (SYSTEM režim)" -ForegroundColor Green
            if ($result.Failed -gt 0) {
                Write-Host "  ⚠️  Selhalo: $($result.Failed) úloh (neexistují nebo chráněné)" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "  ⚠️  SYSTEM eskalace vrátila neplatný výsledek - zkouším jako Admin..." -ForegroundColor Yellow
            
            # Fallback - zkusit jako běžný Admin
            $EnabledTaskCount = 0
            foreach ($taskPath in $tasksToEnableList) {
                try {
                    if ($taskPath.Contains('\')) {
                        $path = $taskPath.Substring(0, $taskPath.LastIndexOf('\') + 1)
                        $name = $taskPath.Substring($taskPath.LastIndexOf('\') + 1)
                        
                        $task = Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
                        
                        if ($null -ne $task) {
                            # Enable
                            if ($task.State -ne 'Enabled') {
                                Enable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue | Out-Null
                            }
                            # Start
                            Start-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue | Out-Null
                            
                            $EnabledTaskCount++
                        }
                    }
                }
                catch { }
            }
            Write-Host "  ✅ Povoleno: $EnabledTaskCount úloh (Admin režim)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ❌ Chyba při vypínání úloh: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✅ TWEAK T DOKONČEN!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "⚠️  Úlohy/task byly obnoveny!" -ForegroundColor Red
    Write-Host "💡 TIP: RESTART PC je NUTNÝ! reinstal MsStore přes xboxApp" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

Export-ModuleMember -Function @(
    'Invoke-TweakT',
    'Get-TweakTSnapshot',
    'Invoke-ModuleEntry'
)

