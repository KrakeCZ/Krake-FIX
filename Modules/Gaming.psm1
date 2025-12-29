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

function Show-RamLimitSubMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Magenta
        Write-Host "         IO PAGE LOCK LIMIT (RAM)                 " -ForegroundColor Magenta
        Write-Host "==================================================" -ForegroundColor Magenta
        Write-Host "Nastaví registry klíč IoPageLockLimit dle velikosti RAM."
        Write-Host "Vyšší hodnota může zlepšit I/O výkon u her."
        Write-Host ""
        Write-Host "[1] 4 GB RAM   (Limit: 256 MB)"
        Write-Host "[2] 8 GB RAM   (Limit: 512 MB)"
        Write-Host "[3] 12 GB RAM  (Limit: 768 MB)"
        Write-Host "[4] 16 GB RAM  (Limit: 1024 MB)"
        Write-Host "[5] 24 GB RAM  (Limit: 1536 MB)"
        Write-Host "[6] 32 GB RAM  (Limit: 2048 MB)"
        Write-Host "[7] 64 GB RAM  (Limit: 4095 MB - Max 32bit)"
        Write-Host "[8] 128 GB RAM (Limit: 4095 MB - Max 32bit)"
        Write-Host "[9] 192 GB RAM (Limit: 4095 MB - Max 32bit)"
        Write-Host "[C] Vlastní hodnota (zadat v MB)"
        Write-Host "[D] Windows Default (Smazat hodnotu)"
        Write-Host "[Q] Zpět"
        Write-Host ""

        $ramChoice = Read-Host -Prompt "Vyberte velikost vaší RAM"
        
        $limitValue = $null
        $limitDesc = ""
        $isDelete = $false

        switch ($ramChoice) {
            '1' { $limitValue = 268435456; $limitDesc = "256 MB" }
            '2' { $limitValue = 536870912; $limitDesc = "512 MB" }
            '3' { $limitValue = 805306368; $limitDesc = "768 MB" }
            '4' { $limitValue = 1073741824; $limitDesc = "1024 MB" }
            '5' { $limitValue = 1610612736; $limitDesc = "1536 MB" }
            '6' { $limitValue = 2147483648; $limitDesc = "2048 MB" }
            '7' { $limitValue = 4293918720; $limitDesc = "4095 MB" }
            '8' { $limitValue = 4293918720; $limitDesc = "4095 MB" }
            '9' { $limitValue = 4293918720; $limitDesc = "4095 MB" }
            'C' {
                $mbInput = Read-Host -Prompt "Zadejte hodnotu v MB (např. 128, 1024)"
                if ($mbInput -match '^\d+$') {
                    try {
                        $val = [long]$mbInput * 1MB
                        if ($val -gt 4294967295) {
                            Write-Warning "Hodnota je příliš vysoká pro 32-bit DWORD (Max 4095 MB)."
                            Start-Sleep -Seconds 2
                            continue
                        }
                        $limitValue = $val
                        $limitDesc = "$mbInput MB (Vlastní)"
                    } catch {
                        Write-Warning "Chyba při převodu čísla."
                        Start-Sleep -Seconds 2
                        continue
                    }
                } else {
                    Write-Warning "Neplatné číslo."
                    Start-Sleep -Seconds 2
                    continue
                }
            }
            'c' {
                $mbInput = Read-Host -Prompt "Zadejte hodnotu v MB (např. 128, 1024)"
                if ($mbInput -match '^\d+$') {
                    try {
                        $val = [long]$mbInput * 1MB
                        if ($val -gt 4294967295) {
                            Write-Warning "Hodnota je příliš vysoká pro 32-bit DWORD (Max 4095 MB)."
                            Start-Sleep -Seconds 2
                            continue
                        }
                        $limitValue = $val
                        $limitDesc = "$mbInput MB (Vlastní)"
                    } catch {
                        Write-Warning "Chyba při převodu čísla."
                        Start-Sleep -Seconds 2
                        continue
                    }
                } else {
                    Write-Warning "Neplatné číslo."
                    Start-Sleep -Seconds 2
                    continue
                }
            }
            'D' { $isDelete = $true; $limitDesc = "Windows Default (Smazáno)" }
            'd' { $isDelete = $true; $limitDesc = "Windows Default (Smazáno)" }
            'Q' { return }
            'q' { return }
            default { Write-Warning "Neplatná volba." }
        }

        if ($isDelete) {
             Write-Host "  -> Obnovuji Windows Default (mažu IoPageLockLimit)..." -ForegroundColor Cyan
             $scriptBlock = {
                $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
                if (Test-Path $path) {
                    Remove-ItemProperty -Path $path -Name 'IoPageLockLimit' -ErrorAction SilentlyContinue
                }
            }
            try {
                Invoke-AsSystem -ScriptBlock $scriptBlock
                Write-Host "  ✅ IoPageLockLimit smazán (Default)" -ForegroundColor Green
            } catch {
                Write-Error "Chyba: $_"
            }
            Write-Host "Stiskněte klávesu pro pokračování..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }

        if ($limitValue) {
            Write-Host "  -> Nastavuji IoPageLockLimit na $limitDesc..." -ForegroundColor Cyan
            
            $scriptBlock = {
                param($val)
                $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -Path $path -Name 'IoPageLockLimit' -Value $val -Type DWord -Force
            }

            try {
                $result = Invoke-AsSystem -ScriptBlock $scriptBlock -ArgumentList $limitValue
                if ($result) {
                    Write-Host "  ✅ IoPageLockLimit úspěšně nastaven na $limitDesc" -ForegroundColor Green
                } else {
                    Write-Error "  ❌ Nepodařilo se nastavit limit (Invoke-AsSystem selhal)."
                }
            } catch {
                Write-Error "Chyba při nastavování limitu: $_"
            }
            
            Write-Host "Stiskněte klávesu pro pokračování..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
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
        Write-Host "  - IO Page Lock Limit"
        Write-Host ""
        Write-Host "[1] Aplikovat Gaming Performance Tweaky (Default 768MB)" -ForegroundColor Cyan
        Write-Host "[2] Obnovit výchozí nastavení" -ForegroundColor Yellow
        Write-Host "[3] Nastavit IO Page Lock Limit (dle RAM)" -ForegroundColor Magenta
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
            '3' {
                Show-RamLimitSubMenu
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

