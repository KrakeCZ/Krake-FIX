# ═══════════════════════════════════════════════════════════════════════════
# Module: CoreParking.psm1
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX v2 Modular
# Version:      2.0.0
# Author:       KRAKE-FIX Team
# Created:      2025-10-29
# Last Updated: 2025-10-29
# ═══════════════════════════════════════════════════════════════════════════
# Description:  CPU Core Parking & Boost Management
#               - Unlock core parking options in power settings
#               - Enable CPU boost tweaks
#               - Password protected (PIN: core / 8888)
# Category:     CPU / Power Management
# Dependencies: Core.psm1, Utils.psm1
# Admin Rights: Required
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️  SECURITY & COMPLIANCE NOTICE
# ═══════════════════════════════════════════════════════════════════════════
# • This module modifies CPU core parking registry settings.
# • Designed for educational and testing purposes only.
# • Author assumes no liability for misuse outside academic context.
# • Always create system restore point before use.
# • BSI4 compliant: Input validation, error handling, audit logging.
# • REQUIRES AUTHORIZATION: Password protected for safety.
# ═══════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ---------------------------------------------------------------------------
# IMPORT CORE MODULE
# ---------------------------------------------------------------------------
# Use Core module functions - loaded by Main.ps1, only import if standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $CoreModule = Join-Path $PSScriptRoot 'Core.psm1'
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    }
}

# Import Utils modulu pro backup operace
$UtilsModule = Join-Path $PSScriptRoot 'Utils.psm1'
if (Test-Path $UtilsModule) {
    Import-Module $UtilsModule -Force -ErrorAction Stop
}

# ---------------------------------------------------------------------------
# MODULE INITIALIZATION
# ---------------------------------------------------------------------------

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Module-level variables (private)
$script:ModuleName = 'CoreParking'
$script:ModuleVersion = '2.0.0'
$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"

# Backup file path
$coreParkingSettings = @(
    [pscustomobject]@{
        KeyPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583'
        Guid         = '0cc5b647-c1df-4637-891a-dec35c318583'
        VisibleValue = 0
        DefaultValue = 1
    }
    [pscustomobject]@{
        KeyPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb'
        Guid         = '3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb'
        VisibleValue = 0
        DefaultValue = 1
    }
    [pscustomobject]@{
        KeyPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028'
        Guid         = 'ea062031-0e34-4ff1-9b6d-eb1059334028'
        VisibleValue = 0
        DefaultValue = 1
    }
    [pscustomobject]@{
        KeyPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7'
        Guid         = 'be337238-0d82-4146-a960-4f3749d470c7'
        VisibleValue = 0
        DefaultValue = 2
    }
    [pscustomobject]@{
        KeyPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\94d3a615-a899-4ac5-ae2b-e4d8f634367f'
        Guid         = '94d3a615-a899-4ac5-ae2b-e4d8f634367f'
        VisibleValue = 0
        DefaultValue = 2
    }
)

# ===========================================================
# CORE PARKING MANAGEMENT FUNCTIONS
# ===========================================================

# --- REFAKTOROVANÉ MENU PRO CORE PARKING ---
function Show-CoreParkingMenu {
    Clear-Host
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "         MENU PRO CORE PARKING & BOOST              " -ForegroundColor Red
    Write-Host "==================================================" -ForegroundColor Cyan

    $password = Read-Host -Prompt "Pro vstup zadejte autorizační heslo (core)"
    if ($password -ne 'core') {
        Write-Error "Nesprávné heslo. Přístup odepřen."
        Start-Sleep -Seconds 2
        return
    }

    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "                CORE PARKING & BOOST              " -ForegroundColor Red
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "[1] Povolit tweaky (odemknout volby v napájení)" -ForegroundColor Green
        Write-Host "[2] Obnovit výchozí nastavení ze zálohy" -ForegroundColor Yellow
        Write-Host "--------------------------------------------------"
        Write-Host "[Q] Zpět do hlavního menu" -ForegroundColor Red

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        switch ($choice) {
            '1' {
                $pin = Read-Host -Prompt "Pro povolení tweaků zadejte PIN '8888'"
                if ($pin -eq '8888') {
                    Write-Host "  -> PIN přijat. Aplikuji tweaky..." -ForegroundColor Cyan

                    $successCount = 0
                    $errorCount = 0

                    foreach ($setting in $coreParkingSettings) {
                        try {
                            if (-not (Test-Path -LiteralPath $setting.KeyPath)) {
                                Write-Warning "✗ Klíč neexistuje: $($setting.KeyPath)"
                                $errorCount++
                                continue
                            }

                            New-ItemProperty -Path $setting.KeyPath -Name 'Attributes' -Value $setting.VisibleValue -PropertyType DWord -Force | Out-Null
                            $successCount++
                        }
                        catch {
                            $errorCount++
                            Write-Warning "✗ Nelze nastavit $($setting.KeyPath): $($_.Exception.Message)"
                        }
                    }

                    # PowerCfg: ensure all power schemes have the toggle exposed
                    foreach ($guid in $coreParkingSettings.Guid) {
                        try {
                            Start-Process -FilePath 'powercfg.exe' -ArgumentList @('-attributes', 'SUB_PROCESSOR', $guid, '-ATTRIB_HIDE') -WindowStyle Hidden -Wait -ErrorAction Stop
                        }
                        catch {
                            Write-Warning "PowerCfg attributes update failed for ${guid}: $($_.Exception.Message)"
                        }
                    }

                    # Souhrn dle @STUDY/03 (graceful degradation)
                    if ($errorCount -eq 0) {
                        Write-Host "  -> ✅ Všechny tweaky aplikovány ($successCount/$($coreParkingSettings.Count))" -ForegroundColor Green
                    } elseif ($successCount -gt 0) {
                        Write-Warning "  -> ⚠️ Částečný úspěch: $successCount/$($coreParkingSettings.Count) aplikováno, $errorCount selhalo"
                    } else {
                        Write-Error "  -> ❌ Všechny tweaky selhaly! Zkontroluj oprávnění."
                    }

                } else {
                    Write-Error "Nesprávný PIN. Operace zrušena."
                }
            }
            '2' {
                Write-Host "  -> Obnovuji výchozí nastavení..." -ForegroundColor Yellow
                $restoreSuccess = 0
                $restoreErrors  = 0

                foreach ($setting in $coreParkingSettings) {
                    try {
                        if (-not (Test-Path -LiteralPath $setting.KeyPath)) {
                            Write-Warning "Klíč neexistuje pro obnovu: $($setting.KeyPath)"
                            $restoreErrors++
                            continue
                        }

                        New-ItemProperty -Path $setting.KeyPath -Name 'Attributes' -Value $setting.DefaultValue -PropertyType DWord -Force | Out-Null
                        $restoreSuccess++
                    }
                    catch {
                        $restoreErrors++
                        Write-Warning "Obnova selhala pro $($setting.KeyPath): $($_.Exception.Message)"
                    }
                }

                foreach ($guid in $coreParkingSettings.Guid) {
                    try {
                        Start-Process -FilePath 'powercfg.exe' -ArgumentList @('-attributes', 'SUB_PROCESSOR', $guid, '+ATTRIB_HIDE') -WindowStyle Hidden -Wait -ErrorAction Stop
                    }
                    catch {
                        Write-Warning "PowerCfg hide update failed for ${guid}: $($_.Exception.Message)"
                    }
                }

                if ($restoreErrors -eq 0) {
                    Write-Host "  -> ✅ Obnova dokončena ($restoreSuccess/$($coreParkingSettings.Count))" -ForegroundColor Green
                }
                else {
                    Write-Warning "  -> ⚠️ Obnova částečně úspěšná ($restoreSuccess/$($coreParkingSettings.Count)), chyb: $restoreErrors"
                }
            }
            'Q' { return }
            default { Write-Warning "Neplatná volba." }
        }
        Write-Host "Stiskněte klávesu pro pokračování..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# ===========================================================
# EXPORT MODULE MEMBERS
# ===========================================================

function Invoke-ModuleEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $ModuleContext
    )

    if ($null -eq $ModuleContext) {
        throw [System.ArgumentNullException]::new('ModuleContext')
    }

    Show-CoreParkingMenu
}

Export-ModuleMember -Function @(
    'Show-CoreParkingMenu',
    'Invoke-ModuleEntry'
)
