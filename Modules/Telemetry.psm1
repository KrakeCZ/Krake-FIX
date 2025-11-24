# ═══════════════════════════════════════════════════════════════════════════
# Module: Telemetry.psm1
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX v2 Modular
# Version:      2.0.0
# Author:       KRAKE-FIX Team
# Created:      2025-10-29
# Last Updated: 2025-10-29
# ═══════════════════════════════════════════════════════════════════════════
# Description:  Windows Telemetry & Diagnostic Services Management
#               - Disable/Enable telemetry services
#               - DiagTrack, diagsvc, dmwappushservice
#               - lfsvc, MapsBroker, TroubleshootingSvc
#               - WdiServiceHost, WdiSystemHost, wisvc
#               - And other telemetry services
# Category:     Privacy / Telemetry
# Dependencies: Core.psm1 (for Invoke-RevertToDefaults)
# Admin Rights: Required
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️  SECURITY & COMPLIANCE NOTICE
# ═══════════════════════════════════════════════════════════════════════════
# • This module disables Windows telemetry and diagnostic services.
# • May limit some Windows diagnostic features.
# • Designed for educational and testing purposes only.
# • Author assumes no liability for misuse outside academic context.
# • Always create system restore point before use.
# • BSI4 compliant: Input validation, error handling, audit logging.
# ═══════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ---------------------------------------------------------------------------
# IMPORT CORE MODULE (REQUIRED FOR Invoke-RevertToDefaults)
# ---------------------------------------------------------------------------
# Use Core module functions - loaded by Main.ps1, only import if standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $CoreModule = Join-Path $PSScriptRoot 'Core.psm1'
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    } else {
        Write-Error "CRITICAL: Core.psm1 not found! Telemetry.psm1 requires Core.psm1."
        throw "Missing dependency: Core.psm1"
    }
}

# ---------------------------------------------------------------------------
# MODULE INITIALIZATION
# ---------------------------------------------------------------------------

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Module-level variables (private)
$script:ModuleName = 'Telemetry'
$script:ModuleVersion = '2.0.0'
$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"

# ===========================================================
# TELEMETRY MANAGEMENT FUNCTIONS
# ===========================================================

# --- NOVÉ: MENU PRO TELEMETRII A DALŠÍ SLUŽBY ---
function Show-TelemetryServicesMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Magenta
        Write-Host "         TELEMETRIE & DALŠÍ SLUŽBY                " -ForegroundColor Magenta
        Write-Host "==================================================" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "Zakázání telemetrie a diagnostických služeb:"
        Write-Host "  - DiagTrack, diagsvc, dmwappushservice"
        Write-Host "  - lfsvc, MapsBroker, TroubleshootingSvc"
        Write-Host "  - WdiServiceHost, WdiSystemHost, wisvc"
        Write-Host "  - a další telemetrické služby"
        Write-Host ""
        Write-Host "POZOR: Může omezit některé diagnostické funkce Windows!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] Zakázat telemetrické služby" -ForegroundColor Cyan
        Write-Host "[2] Obnovit telemetrické služby" -ForegroundColor Yellow
        Write-Host "[Q] Zpět do hlavního menu" -ForegroundColor Red

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        switch ($choice) {
            '1' {
                $confirm = Read-Host -Prompt "Opravdu chcete zakázat telemetrické služby? (Ano/Ne)"
                if ($confirm -match '^a') {
                    Write-Host "  -> Zakazuji telemetrické služby..." -ForegroundColor Cyan
                    Invoke-RevertToDefaults -Category 'TelemetryServices' -Apply
                    Write-Host "  -> Telemetrické služby zakázány!" -ForegroundColor Green
                } else {
                    Write-Host "Operace zrušena." -ForegroundColor Yellow
                }
            }
            '2' {
                Write-Host "  -> Obnovuji telemetrické služby..." -ForegroundColor Yellow
                Invoke-RevertToDefaults -Category 'TelemetryServices'
                Write-Host "  -> Telemetrické služby obnoveny." -ForegroundColor Green
            }
            'Q' { return }
            default { Write-Warning "Neplatná volba." }
        }
        Write-Host "Stiskněte klávesu pro pokračování..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}
$script:TelemetryServices = @{
        Name = 'Telemetry & Diagnostic Services'
        Description = 'Disable Windows telemetry and diagnostic data collection'
        RequiresRestart = $true

        Registry = @(
            # ─── Telemetry Registry Keys ───
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
                Name = 'AllowTelemetry'
                Type = 'DWord'
                ApplyValue = 0          # Disabled
                RevertValue = 1         # Basic
                Description = 'Main telemetry switch'
                RequiresSystem = $false
            }
        )

        Services = @(
            # ─── Telemetry Services to DISABLE ───
            @{
                Name = 'DiagTrack'
                Operation = 'Disable'
                ApplyStartType = 4      # Disabled
                RevertStartType = 2     # Automatic
                Description = 'Connected User Experiences and Telemetry'
                RequiresSystem = $true
            }
            @{
                Name = 'dmwappushservice'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3     # Manual
                Description = 'Device Management Wireless Application Protocol'
                RequiresSystem = $true
            }
        )

        Hosts = @{
            # ─── Telemetry domains to block via hosts file ───
            Domains = @(
                'vortex.data.microsoft.com',
                'vortex-win.data.microsoft.com',
                'telecommand.telemetry.microsoft.com',
                'telecommand.telemetry.microsoft.com.nsatc.net',
                'oca.telemetry.microsoft.com',
                'sqm.telemetry.microsoft.com',
                'watson.telemetry.microsoft.com',
                'redir.metaservices.microsoft.com',
                'choice.microsoft.com',
                'df.telemetry.microsoft.com',
                'reports.wes.df.telemetry.microsoft.com',
                'wes.df.telemetry.microsoft.com',
                'services.wes.df.telemetry.microsoft.com',
                'sqm.df.telemetry.microsoft.com',
                'telemetry.microsoft.com',
                'watson.ppe.telemetry.microsoft.com',
                'telemetry.appex.bing.net',
                'telemetry.urs.microsoft.com',
                'telemetry.appex.bing.net:443',
                'settings-sandbox.data.microsoft.com',
                'vortex-sandbox.data.microsoft.com',
                'survey.watson.microsoft.com',
                'watson.live.com',
                'watson.microsoft.com',
                'statsfe2.ws.microsoft.com',
                'corpext.msitadfs.glbdns2.microsoft.com',
                'compatexchange.cloudapp.net',
                'cs1.wpc.v0cdn.net',
                'a-0001.a-msedge.net',
                'statsfe2.update.microsoft.com.akadns.net',
                'sls.update.microsoft.com.akadns.net',
                'fe2.update.microsoft.com.akadns.net',
                'diagnostics.support.microsoft.com',
                'corp.sts.microsoft.com',
                'statsfe1.ws.microsoft.com',
                'pre.footprintpredict.com',
                'i1.services.social.microsoft.com',
                'i1.services.social.microsoft.com.nsatc.net'
            )
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

    Show-TelemetryServicesMenu
}

Export-ModuleMember -Function @(
    'Show-TelemetryServicesMenu',
    'Invoke-ModuleEntry'
)
