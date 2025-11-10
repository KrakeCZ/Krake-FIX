# ===========================================================
# Modul: GPU.psm1
# Popis: Hlavní GPU menu - Lazy loading sub-modulů
# Autor: KRAKE-FIX Team
# Projekt: KRAKE-FIX v2 Modular
# ===========================================================
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ===========================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ===========================================================
# MODULE-LEVEL VARIABLES
# ===========================================================

$script:ModuleName = 'GPU'
$script:ModuleVersion = '2.0.0'
$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"

# ===========================================================
# MAIN GPU MENU (with Lazy Loading)
# ===========================================================

<#
.SYNOPSIS
    Hlavní menu pro GPU optimalizace.

.DESCRIPTION
    Zobrazuje interaktivní menu pro správu GPU tweaků.
    Používá lazy loading - načítá sub-moduly pouze když jsou potřeba:
      - GPU_NVIDIA.psm1 (NVIDIA GPU Tweaky)
      - GPU_Intel.psm1 (Intel iGPU Tweaky)
      - GPU_AMD.psm1 (AMD GPU Tweaky - placeholder)
    
    Podporuje:
      - NVIDIA GPU tweaky (Gaming profil, Latency, Performance, Stability)
      - Intel iGPU tweaky (Balanced, Latency, MaxPerf)
      - AMD GPU tweaky (připraveno pro budoucnost)

.NOTES
    Všechny změny jsou automaticky zálohovány.
    Sub-moduly jsou načítány pouze když uživatel vstoupí do jejich menu.
#>
function Show-GpuMenu {
    while ($true) {
        Clear-Host
        Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "                   🎮 GPU TWEAKY MENU                     " -ForegroundColor Green
        Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-Host "Vyberte GPU výrobce:" -ForegroundColor White
        Write-Host ""
        
        Write-Host "[1] 🎮 NVIDIA GPU Tweaky" -ForegroundColor Cyan
        Write-Host "    Gaming profil, Latency, Performance, Stability" -ForegroundColor Gray
        Write-Host ""
        
        Write-Host "[2] 💻 Intel iGPU Tweaky" -ForegroundColor Cyan
        Write-Host "    Balanced, Latency, Maximum Performance" -ForegroundColor Gray
        Write-Host ""
        
        Write-Host "[3] 🔴 AMD GPU Tweaky" -ForegroundColor Cyan
        Write-Host "    Připraveno pro budoucnost (placeholder)" -ForegroundColor Gray
        Write-Host ""
        
        Write-Host "──────────────────────────────────────────────────────────"
        Write-Host "[4] 🔧 POKROČILÉ / UNIVERZÁLNÍ" -ForegroundColor Magenta
        Write-Host "    HAGS, Herní režim, Resizable BAR (pro všechny GPU)" -ForegroundColor Gray
        Write-Host ""
        
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host "[Q] ⬅️  Zpět do hlavního menu" -ForegroundColor Red
        Write-Host ""
        
        $choice = Read-Host -Prompt "Zadejte svou volbu"

        switch ($choice.ToUpper()) {
            '1' { 
                # Lazy loading - načte GPU_NVIDIA.psm1 pouze když je potřeba
                $nvidiaModule = Join-Path $PSScriptRoot 'GPU_NVIDIA.psm1'
                if (Test-Path $nvidiaModule) {
                    Import-Module $nvidiaModule -Force -ErrorAction SilentlyContinue
                    if (Get-Command Show-NvidiaSubMenu -ErrorAction SilentlyContinue) {
                        Show-NvidiaSubMenu
                    } else {
                        Write-Warning "Nepodařilo se načíst NVIDIA modul."
                        Start-Sleep 3
                    }
                } else {
                    Write-Warning "NVIDIA modul nebyl nalezen: $nvidiaModule"
                    Start-Sleep 3
                }
            }
            '2' { 
                # Lazy loading - načte GPU_Intel.psm1 pouze když je potřeba
                $intelModule = Join-Path $PSScriptRoot 'GPU_Intel.psm1'
                if (Test-Path $intelModule) {
                    Import-Module $intelModule -Force -ErrorAction SilentlyContinue
                    if (Get-Command Show-IntelIgpuSubMenu -ErrorAction SilentlyContinue) {
                        Show-IntelIgpuSubMenu
                    } else {
                        Write-Warning "Nepodařilo se načíst Intel modul."
                        Start-Sleep 3
                    }
                } else {
                    Write-Warning "Intel modul nebyl nalezen: $intelModule"
                    Start-Sleep 3
                }
            }
            '3' { 
                # Lazy loading - načte GPU_AMD.psm1 pouze když je potřeba
                $amdModule = Join-Path $PSScriptRoot 'GPU_AMD.psm1'
                if (Test-Path $amdModule) {
                    Import-Module $amdModule -Force -ErrorAction SilentlyContinue
                    if (Get-Command Show-AmdSubMenu -ErrorAction SilentlyContinue) {
                        Show-AmdSubMenu
                    } else {
                        Write-Warning "Nepodařilo se načíst AMD modul."
                        Start-Sleep 3
                    }
                } else {
                    Write-Warning "AMD modul nebyl nalezen: $amdModule"
                    Start-Sleep 3
                }
            }
            '4' { 
                # Lazy loading - načte GPU_Advanced.psm1 pouze když je potřeba
                $advancedModule = Join-Path $PSScriptRoot 'GPU_Advanced.psm1'
                if (Test-Path $advancedModule) {
                    Import-Module $advancedModule -Force -ErrorAction SilentlyContinue
                    if (Get-Command Show-AdvancedGpuMenu -ErrorAction SilentlyContinue) {
                        Show-AdvancedGpuMenu
                    } else {
                        Write-Warning "Nepodařilo se načíst Advanced modul."
                        Start-Sleep 3
                    }
                } else {
                    Write-Warning "Advanced modul nebyl nalezen: $advancedModule"
                    Start-Sleep 3
                }
            }
            'Q' { return }
            default { 
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep 2
            }
        }
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

    Show-GpuMenu
}

# ===========================================================
# MODULE EXPORTS
# ===========================================================

Export-ModuleMember -Function @(
    'Show-GpuMenu',
    'Invoke-ModuleEntry'
)

# ===========================================================
# MODULE INITIALIZATION LOG
# ===========================================================

if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
    Write-CoreLog -Message "GPU.psm1 v$script:ModuleVersion loaded successfully (main menu only)" -Level Info
}
