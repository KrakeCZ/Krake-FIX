# ═══════════════════════════════════════════════════════════════════════════
# KRAKE-FIX v2 - Modular Edition - MAIN LAUNCHER
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX v2 Modular
# Version:      2.0.0
# Author:       KRAKE-FIX Team
# Created:      2025-10-29
# Last Updated: 2025-10-29
# ═══════════════════════════════════════════════════════════════════════════
# Description:  Main launcher script for KRAKE-FIX v2 modular architecture.
#               Provides interactive menu system for all modules.
# Admin Rights: REQUIRED (most operations require elevated privileges)
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️  SECURITY & COMPLIANCE NOTICE
# ═══════════════════════════════════════════════════════════════════════════
# • This script modifies Windows system settings (Registry, Services, etc.)
# • Designed for educational, testing, and gaming performance purposes ONLY
# • Author assumes no liability for misuse outside academic context
# • Always create system restore point before applying tweaks
# • BSI4 compliant: Privilege checks, error handling, backup/restore
# ═══════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1
#Requires -RunAsAdministrator

using namespace System.Management.Automation

# ───────────────────────────────────────────────────────────────────────────
# SCRIPT INITIALIZATION
# ───────────────────────────────────────────────────────────────────────────

param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Suppress warnings about restricted characters in function names (GPU modules use dash-separated names)
$WarningPreference = 'SilentlyContinue'

# Banner & Version
$script:Version = '2.0.0'
$script:BuildDate = '2025-10-29'
$script:ModulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules'

# ───────────────────────────────────────────────────────────────────────────
# MODULE LOADING
# ───────────────────────────────────────────────────────────────────────────

function Initialize-KrakeFix {
    <#
    .SYNOPSIS
        Initializes KRAKE-FIX environment and loads all modules.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  KRAKE-FIX v$script:Version - Modular Edition" -ForegroundColor Cyan
    Write-Host "  Build: $script:BuildDate" -ForegroundColor Gray
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Inicializuji prostředí..." -ForegroundColor Yellow
    Write-Host ""

    # Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "⚠️  Tento skript vyžaduje administrátorská oprávnění!"
        Write-Host ""
        Write-Host "Spusťte PowerShell jako správce a zkuste to znovu." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Stiskněte Enter pro ukončení..." ; $null = Read-Host
        exit 1
    }

    # Check Modules directory
    if (-not (Test-Path $script:ModulesPath)) {
        Write-Error "⚠️  Modules adresář nenalezen: $script:ModulesPath"
        Write-Host ""
        Write-Host "Stiskněte Enter pro ukončení..." ; $null = Read-Host
        exit 1
    }

    # Preflight: Task Scheduler (Schedule) service is required for SYSTEM eskalaci
    try {
        $scheduleSvc = Get-Service -Name Schedule -ErrorAction SilentlyContinue
        if ($null -eq $scheduleSvc) {
            Write-Warning "Služba 'Schedule' (Task Scheduler) nebyla nalezena. Funkce vyžadující SYSTEM eskalaci nemusí fungovat."
        }
        elseif ($scheduleSvc.Status -ne 'Running') {
            try {
                Set-Service -Name Schedule -StartupType Automatic -ErrorAction Stop
                Start-Service -Name Schedule -ErrorAction Stop
                Write-Host "  ✅ Task Scheduler spuštěn" -ForegroundColor Green
            }
            catch {
                Write-Warning ("Nelze spustit službu 'Schedule': {0}" -f $_.Exception.Message)
            }
        }
    }
    catch {
        Write-Warning ("Kontrola služby 'Schedule' selhala: {0}" -f $_.Exception.Message)
    }

    # Load Core module first (dependency for others)
    Write-Host "[1/3] Načítám Core.psm1..." -ForegroundColor Gray
    $corePath = Join-Path -Path $script:ModulesPath -ChildPath 'Core.psm1'
    if (Test-Path $corePath) {
        try {
            Import-Module $corePath -Force -Global -ErrorAction Stop
            Write-Host "  ✅ Core.psm1 loaded" -ForegroundColor Green
        }
        catch {
            Write-Error ("⚠️  Core.psm1 import selhal: {0}" -f $_.Exception.Message)
            Write-Host ""; Write-Host "Stiskněte Enter pro ukončení..." ; $null = Read-Host
            exit 1
        }
    }
    else {
        Write-Error "⚠️  Core.psm1 not found! Cannot continue."
        exit 1
    }

    # Load all other modules dynamically
    Write-Host "[2/3] Načítám moduly..." -ForegroundColor Gray
    $modulesToLoad = Get-ChildItem -Path $script:ModulesPath -Filter *.psm1 | Where-Object { $_.Name -ne 'Core.psm1' -and $_.Name -notlike '_*' }
    $totalModuleCount = ($modulesToLoad | Measure-Object).Count

    $loadedCount = 0
    $failedImports = New-Object System.Collections.Generic.List[object]
    foreach ($moduleFile in $modulesToLoad) {
        try {
            Import-Module $moduleFile.FullName -Force -Global -ErrorAction Stop
            $loadedCount++
            Write-Host "  ✅ $($moduleFile.Name)" -ForegroundColor Green
        }
        catch {
            $errMsg = $_.Exception.Message
            Write-Warning "  ⚠️  Failed to load $($moduleFile.Name) : $errMsg"
            $failedImports.Add([pscustomobject]@{ Module = $moduleFile.Name; Error = $errMsg }) | Out-Null
        }
    }

    Write-Host "[3/3] Ověřuji závislosti..." -ForegroundColor Gray
    Write-Host "  ✅ Načteno $loadedCount/$totalModuleCount modulů" -ForegroundColor Green
    if ($failedImports.Count -gt 0) {
        Write-Host ""; Write-Host "Nenačtené moduly (menu by bylo neúplné):" -ForegroundColor Yellow
        $failedImports | ForEach-Object {
            Write-Host ("  - {0}: {1}" -f $_.Module, $_.Error) -ForegroundColor Yellow
        }
        Write-Host ""; Write-Error "Import modulů selhal. Ukončuji, aby nedošlo k rozbitému menu."
        Write-Host ""; Write-Host "Stiskněte Enter pro ukončení..." ; $null = Read-Host
        exit 1
    }
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✅ KRAKE-FIX v$script:Version připraven!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
Start-Sleep -Seconds 2
}

function Invoke-ModuleEntryPoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [hashtable]$AdditionalContext
    )

    $qualifiedName = '{0}\Invoke-ModuleEntry' -f $ModuleName

    try {
        $command = Get-Command -Name $qualifiedName -ErrorAction Stop
    }
    catch {
        Write-Warning ("Module entry point not found: {0}" -f $ModuleName)
        return $false
    }

    $modulePath = Join-Path -Path $script:ModulesPath -ChildPath ('{0}.psm1' -f $ModuleName)
    $moduleContext = @{
        ModuleName = $ModuleName
        ModulePath = if (Test-Path -LiteralPath $modulePath) { $modulePath } else { $null }
    }

    if ($AdditionalContext) {
        foreach ($key in $AdditionalContext.Keys) {
            $moduleContext[$key] = $AdditionalContext[$key]
        }
    }

    try {
        & $command -ModuleContext $moduleContext
        return $true
    }
    catch {
        Write-Warning ("Module entry execution failed ({0}): {1}" -f $ModuleName, $_.Exception.Message)
        return $false
    }
}

# ───────────────────────────────────────────────────────────────────────────
# MAIN MENU
# ───────────────────────────────────────────────────────────────────────────

function Show-MainMenu {
    <#
    .SYNOPSIS
        Displays main interactive menu for KRAKE-FIX v2.
    #>
    [CmdletBinding()]
    param()

    while ($true) {
        Clear-Host
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "              KRAKE-FIX - GAMING OPTIMIZATION" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Vyberte požadovanou akci:"
        Write-Host "--------------------------------------------------"
        Write-Host "[0] 🔧 PRE-TWEAK Kontrola závislostí (PsExec/LanmanServer)" -ForegroundColor Yellow
        Write-Host "    → Aktivujte PŘED těžkými tweaky pro 100% spolehlivost" -ForegroundColor Gray
        Write-Host "--------------------------------------------------"
        Write-Host "[1] Aplikovat obecné tweaky  (Debloat + Latency)" -ForegroundColor Blue
        Write-Host "[2] Aplikovat specifické GPU tweaky  (Nvidia / Intel)" -ForegroundColor Cyan
        Write-Host "[3] Nastavit Win32PrioritySeparation" -ForegroundColor Cyan
        Write-Host "[4] Nastavit latenci Vstupu  (Klávesnice/Myš)" -ForegroundColor Cyan
        Write-Host "[5] Optimalizovat LargeSystemCache (Kompilace shaderů / Hraní)" -ForegroundColor Magenta
        Write-Host "[6] Obnovit bezpečné výchozí nastavení Windows" -ForegroundColor Yellow
        Write-Host "--------------------------------------------------"
        Write-Host "[7] Security Hazard Tweaks (Vyžaduje autorizaci)" -ForegroundColor Magenta
        Write-Host "[8] Odemknout Core Parking a Boost (Vyžaduje autorizaci)" -ForegroundColor Cyan
        Write-Host "[9] Konfigurace Plánů Napájení" -ForegroundColor Cyan
        Write-Host "[10] NOVÉ: Gaming Performance Tweaks" -ForegroundColor Red
        Write-Host "[11] NOVÉ: Telemetrie & Další služby" -ForegroundColor Red
        Write-Host "[12] 🌐 Síťové optimalizace (DNS + TCP/IP)" -ForegroundColor Cyan
        Write-Host "[13] 🔄 Windows Update Management" -ForegroundColor Cyan
        Write-Host "[14] 🔧 SYSTÉMOVÁ OPRAVA (DISM + SFC + CHKDSK)" -ForegroundColor Red
        Write-Host "[15] 🎮 NVIDIA Control Panel - Povolit/Zakázat" -ForegroundColor Cyan
        Write-Host "[16] 🗑️  Microsoft Edge Blockade (Registry/IFEO/ACL)" -ForegroundColor Magenta
        Write-Host "[17] 🎮 GAME + AUDIO Priority (MMCSS Profily)" -ForegroundColor Cyan
        Write-Host "--------------------------------------------------"
        Write-Host "[*] 🔍 Diagnostika (CPU/RAM/GPU Info + Nástroje)" -ForegroundColor Green
        Write-Host "[/] Obnovit menu" -ForegroundColor Gray
        Write-Host "[Q] Ukončit" -ForegroundColor Red
        Write-Host "-------------------------------------PO Aplikaci RESTARTUJ!-----" -ForegroundColor Yellow

        $choice = Read-Host -Prompt "`nZadejte svou volbu"

        switch ($choice) {
            '/' {
                # Manuální refresh/obnovení menu
                Clear-Host
                continue
            }
            '0' {
                # PRE-TWEAK Dependencies Check
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'PreTweak')) {
                    if (Get-Command Show-PreTweakMenu -ErrorAction SilentlyContinue) {
                        Show-PreTweakMenu
                    }
                    else {
                        Write-Warning "PreTweak.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '*' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'Diagnostics')) {
                    if (Get-Command Show-DiagnosticsMenu -ErrorAction SilentlyContinue) {
                        Show-DiagnosticsMenu
                    }
                    else {
                        Write-Warning "Diagnostics.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            'D' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'Diagnostics')) {
                    if (Get-Command Show-DiagnosticsMenu -ErrorAction SilentlyContinue) {
                        Show-DiagnosticsMenu
                    }
                    else {
                        Write-Warning "Diagnostics.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            'd' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'Diagnostics')) {
                    if (Get-Command Show-DiagnosticsMenu -ErrorAction SilentlyContinue) {
                        Show-DiagnosticsMenu
                    }
                    else {
                        Write-Warning "Diagnostics.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '1' {
                # Tweaky A/B/C menu
                if (Get-Command Invoke-ApplyTweaks -ErrorAction SilentlyContinue) {
                    Invoke-ApplyTweaks
                }
                else {
                    Show-TweaksMenu
                }
            }
            '2' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'GPU')) {
                    if (Get-Command Show-GpuMenu -ErrorAction SilentlyContinue) {
                        Show-GpuMenu
                    }
                    else {
                        Write-Warning "GPU.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '3' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'System' -AdditionalContext @{ RequestedAction = 'Win32Priority' })) {
                    if (Get-Command Show-Win32PrioMenu -ErrorAction SilentlyContinue) {
                        Show-Win32PrioMenu
                    }
                    else {
                        Write-Warning "System.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '4' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'System' -AdditionalContext @{ RequestedAction = 'HidLatency' })) {
                    if (Get-Command Show-HidMenu -ErrorAction SilentlyContinue) {
                        Show-HidMenu
                    }
                    else {
                        Write-Warning "System.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '5' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'System' -AdditionalContext @{ RequestedAction = 'LargeSystemCache' })) {
                    if (Get-Command Show-LargeSystemCacheMenu -ErrorAction SilentlyContinue) {
                        Show-LargeSystemCacheMenu
                    }
                    else {
                        Write-Warning "System.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '6' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'RevertHazard')) {
                    if (Get-Command Show-RevertMenu -ErrorAction SilentlyContinue) {
                        Show-RevertMenu
                    }
                    else {
                        Write-Warning "RevertHazard.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '7' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'Security')) {
                    if (Get-Command Show-SecurityHazardMenu -ErrorAction SilentlyContinue) {
                        Show-SecurityHazardMenu
                    }
                    else {
                        Write-Warning "Security.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '8' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'CoreParking')) {
                    if (Get-Command Show-CoreParkingMenu -ErrorAction SilentlyContinue) {
                        Show-CoreParkingMenu
                    }
                    else {
                        Write-Warning "CoreParking.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '9' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'PowerPlan')) {
                    if (Get-Command Show-PowerPlanMenu -ErrorAction SilentlyContinue) {
                        Show-PowerPlanMenu
                    }
                    else {
                        Write-Warning "PowerPlan.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '10' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'Gaming')) {
                    if (Get-Command Show-GamingPerfMenu -ErrorAction SilentlyContinue) {
                        Show-GamingPerfMenu
                    }
                    else {
                        Write-Warning "Gaming.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '11' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'Telemetry')) {
                    if (Get-Command Show-TelemetryServicesMenu -ErrorAction SilentlyContinue) {
                        Show-TelemetryServicesMenu
                    }
                    else {
                        Write-Warning "Telemetry.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '12' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'Network')) {
                    if (Get-Command Show-NetworkOptimizationMenu -ErrorAction SilentlyContinue) {
                        Show-NetworkOptimizationMenu
                    }
                    else {
                        Write-Warning "Network.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '13' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'Updates')) {
                    if (Get-Command Show-WindowsUpdateMenu -ErrorAction SilentlyContinue) {
                        Show-WindowsUpdateMenu
                    }
                    else {
                        Write-Warning "Updates.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '14' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'Restore')) {
                    if (Get-Command Show-SystemRepairMenu -ErrorAction SilentlyContinue) {
                        Show-SystemRepairMenu
                    }
                    else {
                        Write-Warning "Restore.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '15' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'GPU_NVIDIA')) {
                    if (Get-Command Show-NvidiaControlPanelMenu -ErrorAction SilentlyContinue) {
                        Show-NvidiaControlPanelMenu
                    }
                    else {
                        Write-Warning "GPU.psm1 nebo GPU_NVIDIA.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '16' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'MEBlock')) {
                    if (Get-Command Show-EdgeBlockadeMenu -ErrorAction SilentlyContinue) {
                        Show-EdgeBlockadeMenu
                    }
                    elseif (Get-Command Invoke-EdgeBlockadeMenu -ErrorAction SilentlyContinue) {
                        Invoke-EdgeBlockadeMenu
                    }
                    else {
                        Write-Warning "MEBlock.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            '17' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'MMCSS')) {
                    if (Get-Command Show-GameAudioPriorityMenu -ErrorAction SilentlyContinue) {
                        Show-GameAudioPriorityMenu
                    }
                    else {
                        Write-Warning "MMCSS.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            'Q' {
                Write-Host ""
                Write-Host "Skript byl ukončen." -ForegroundColor Yellow
                return
            }
            'q' {
                Write-Host ""
                Write-Host "Skript byl ukončen." -ForegroundColor Yellow
                return
            }
            default {
                Write-Host "Neplatná volba." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ───────────────────────────────────────────────────────────────────────────
# TWEAKS SUBMENU
# ───────────────────────────────────────────────────────────────────────────

function Show-TweaksMenu {
    <#
    .SYNOPSIS
        Displays submenu for Tweaks A/B/C variants.
    #>
    [CmdletBinding()]
    param()

    while ($true) {
        Clear-Host
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  🎮 OBECNÉ TWEAKY - VÝBĚR VARIANTY" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Vyberte variantu tweaků:" -ForegroundColor White
        Write-Host ""
        Write-Host "[A] 📝 BASE - Základní tweaky (Registry + AppX)" -ForegroundColor Green
        Write-Host "    → Konzervativní přístup, bezpečné + fsutil optimalizace" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[B] ⚙️  MODERATE - Mírné tweaky (Registry + AppX)" -ForegroundColor Yellow
        Write-Host "    → Více AppX balíčků, větší debloat + fsutil optimalizace" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[C] 🔥 ULTRA - Agresivní tweaky (Registry + AppX + Edge)" -ForegroundColor Red
        Write-Host "    → 90 AppX balíčků (včetně , Xbox, Kalkulačka, Fotky)" -ForegroundColor Gray
        Write-Host "    → Edge uninstall + fsutil optimalizace" -ForegroundColor Gray
        Write-Host "    ⚠️  VAROVÁNÍ: Odstraní Store a základní aplikace!" -ForegroundColor Red
        Write-Host "    → XBOX stahni z webu MS, instaluje msStore, aktualně zachovan" -ForegroundColor Gray
        Write-Host ""
        Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "[R] 🔄 TWEAK R - Reset služeb do výchozího stavu" -ForegroundColor Magenta
        Write-Host "    → OPAK TWEAKC! Obnovuje všechny služby (Automatic/Running)" -ForegroundColor Gray
        Write-Host "    → Používá SYSTEM oprávnění! " -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] ⬅️  Zpět do hlavního menu" -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        switch ($choice.ToUpper()) {
            'A' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'TweakA')) {
                    if (Get-Command Invoke-TweakA -ErrorAction SilentlyContinue) {
                        Invoke-TweakA
                    }
                    else {
                        Write-Warning "TweakA.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            'B' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'TweakB')) {
                    if (Get-Command Invoke-TweakB -ErrorAction SilentlyContinue) {
                        Invoke-TweakB
                    }
                    else {
                        Write-Warning "TweakB.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            'C' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'TweakC')) {
                    if (Get-Command Invoke-TweakC -ErrorAction SilentlyContinue) {
                        Invoke-TweakC
                    }
                    else {
                        Write-Warning "TweakC.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            'R' {
                if (-not (Invoke-ModuleEntryPoint -ModuleName 'TweakR')) {
                    if (Get-Command Invoke-TweakR -ErrorAction SilentlyContinue) {
                        Invoke-TweakR
                    }
                    else {
                        Write-Warning "TweakR.psm1 není načten."
                        Start-Sleep -Seconds 2
                    }
                }
            }
            'Q' { return }
            default {
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

try {
    Initialize-KrakeFix
    Show-MainMenu
}
catch {
    Write-Error "Kritická chyba: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    Write-Host ""
    Write-Host "Stiskněte Enter pro ukončení..." ; $null = Read-Host
    exit 1
}

# ═══════════════════════════════════════════════════════════════════════════
# END OF MAIN.PS1
# ═══════════════════════════════════════════════════════════════════════════
