# ═══════════════════════════════════════════════════════════════════════════
# Module: Gaming.psm1
# ═══════════════════════════════════════════════════════════════════════════
# Description: Gaming performance menu (migrated from System.psm1)
# Dependencies: Core.psm1
# Requires: Administrator privileges
# ═══════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1
#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Import Core module for privilege helpers and revert defaults
# Use Core module functions - loaded by Main.ps1, only import if standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $CoreModule = Join-Path $PSScriptRoot 'Core.psm1'
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    } else {
        Write-Error "CRITICAL: Core.psm1 not found. Gaming module cannot continue."
        throw "Missing dependency: Core.psm1"
    }
}

function Show-GamingPerfMenu {
    <#
    .SYNOPSIS
        Menu pro Gaming Performance Tweaks.

    .DESCRIPTION
        [10] Gaming Performance optimalizace - MMCSS, Network throttling,
        Memory management, Service optimization pro gaming.

        PIN PROTECTED: Vyžaduje PIN '5555' pro aplikaci.

    .NOTES
        Volá Invoke-RevertToDefaults -Category 'GamingPerf' (z Core.psm1)
    #>
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "         GAMING PERFORMANCE TWEAKS                " -ForegroundColor Green
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Tyto tweaky optimalizují systém pro hraní her:"
        Write-Host "  - Snížení síťového throttlingu"
        Write-Host "  - Optimalizace multimediálního profilu"
        Write-Host "  - Zakázání SysMain (Superfetch) a WSearch"
        Write-Host "  - Optimalizace memory managementu"
        Write-Host "  - Zvýšení herní priority"
        Write-Host ""
        Write-Host "[1] Aplikovat Gaming Performance Tweaky" -ForegroundColor Cyan
        Write-Host "[2] Obnovit výchozí nastavení" -ForegroundColor Yellow
        Write-Host "[Q] Zpět do hlavního menu" -ForegroundColor Red

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        switch ($choice) {
            '1' {
                $pin = Read-Host -Prompt "Pro aplikaci zadejte PIN '5555'"
                if ($pin -eq '5555') {
                    Write-Host "  -> PIN přijat. Aplikuji Gaming Performance Tweaky..." -ForegroundColor Cyan
                    if (Get-Command Invoke-RevertToDefaults -ErrorAction SilentlyContinue) {
                        Invoke-RevertToDefaults -Category 'GamingPerf' -Apply
                        Write-Host "  -> Gaming Performance Tweaky aplikovány!" -ForegroundColor Green
                    } else {
                        Write-Warning "Invoke-RevertToDefaults není dostupná (Core.psm1 nepřipojeno)"
                    }
                } else {
                    Write-Error "Nesprávný PIN. Operace zrušena."
                }
            }
            '2' {
                Write-Host "  -> Obnovuji výchozí nastavení..." -ForegroundColor Yellow
                if (Get-Command Invoke-RevertToDefaults -ErrorAction SilentlyContinue) {
                    Invoke-RevertToDefaults -Category 'GamingPerf'
                    Write-Host "  -> Výchozí nastavení obnoveno." -ForegroundColor Green
                } else {
                    Write-Warning "Invoke-RevertToDefaults není dostupná (Core.psm1 nepřipojeno)"
                }
            }
            'Q' { return }
            'q' { return }
            default { Write-Warning "Neplatná volba." }
        }

        Write-Host "Stiskněte klávesu pro pokračování..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
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

    Show-GamingPerfMenu
}

Export-ModuleMember -Function @(
    'Show-GamingPerfMenu',
    'Invoke-ModuleEntry'
)

