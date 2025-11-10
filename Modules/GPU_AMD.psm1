# ===========================================================
# Modul: GPU_AMD.psm1
# Popis: AMD GPU Tweaky - PŘIPRAVENO PRO BUDOUCNOST
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
# POZNÁMKA: Core.psm1 není potřeba pro GPU registry tweaky
# Registry operace používají přímý Set-ItemProperty (jako TweakC)
# ===========================================================

# ===========================================================
# MODULE-LEVEL VARIABLES
# ===========================================================

$script:ModuleName = 'GPU_AMD'
$script:ModuleVersion = '2.0.0'
$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"

# Backup file pro GPU tweaky (sdílený s GPU.psm1)
$script:GpuBackupFile = Join-Path ([Environment]::GetFolderPath('Desktop')) "KRAKE-Backup\GPU_Backup.json"

# Dokumentace cesty
$script:DocPath = Join-Path (Split-Path $PSScriptRoot -Parent) "NastrojTemp\gpu"

#region AMD-GpuHelpers (INLINE helpers, původně z Utils)
function Initialize-AmdBackupObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()][object]$ExistingObject
    )

    $metadata = [ordered]@{
        Module    = $script:ModuleName
        Version   = $script:ModuleVersion
        Timestamp = Get-Date
    }

    if ($null -eq $ExistingObject) {
        return [pscustomobject]([ordered]@{
            Metadata   = $metadata
            Registries = @{}
            Services   = @()
        })
    }

    if ($ExistingObject -isnot [psobject]) {
        $ExistingObject = [pscustomobject]$ExistingObject
    }

    if ($ExistingObject.PSObject.Properties.Match('Metadata').Count -eq 0 -or $null -eq $ExistingObject.Metadata) {
        $ExistingObject | Add-Member -MemberType NoteProperty -Name 'Metadata' -Value $metadata -Force
    } else {
        $ExistingObject.Metadata.Module = $metadata.Module
        $ExistingObject.Metadata.Version = $metadata.Version
        $ExistingObject.Metadata.Timestamp = $metadata.Timestamp
    }

    if ($ExistingObject.PSObject.Properties.Match('Registries').Count -eq 0 -or $null -eq $ExistingObject.Registries -or $ExistingObject.Registries -isnot [hashtable]) {
        $ExistingObject.Registries = @{}
    }

    if ($ExistingObject.PSObject.Properties.Match('Services').Count -eq 0 -or $null -eq $ExistingObject.Services) {
        $ExistingObject.Services = @()
    }

    return $ExistingObject
}

function Get-BackupData {
    [CmdletBinding()]
    [OutputType([Object])]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$FilePath
    )
    try {
        if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
            return Initialize-AmdBackupObject
        }

        $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
        $backupData = switch ($extension) {
            '.json' { Get-Content -Path $FilePath -Raw -ErrorAction Stop | ConvertFrom-Json }
            '.xml'  { Import-Clixml -Path $FilePath -ErrorAction Stop }
            default { throw "Unsupported format: $extension" }
        }
        return Initialize-AmdBackupObject -ExistingObject $backupData
    } catch {
        return Initialize-AmdBackupObject
    }
}

function Save-BackupData {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][Object]$Data,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$FilePath,
        [Parameter(Mandatory = $false)][ValidateSet('JSON','XML')][string]$Format = 'JSON'
    )
    try {
        $normalizedData = Initialize-AmdBackupObject -ExistingObject $Data
        $directory = [System.IO.Path]::GetDirectoryName($FilePath)
        if (-not (Test-Path $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
        $finalPath = $FilePath
        switch ($Format) {
            'JSON' { $normalizedData | ConvertTo-Json -Depth 10 | Out-File $finalPath -Encoding UTF8 }
            'XML'  { $normalizedData | Export-Clixml -Path $finalPath -Depth 10 }
        }
        return $finalPath
    } catch { return $null }
}

function Backup-RegistryValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)][string]$BackupPath = $null,
        [Parameter(Mandatory = $false)][object]$BackupData = $null
    )
    if ($null -ne $BackupData) {
        try {
            $null = Initialize-AmdBackupObject -ExistingObject $BackupData
            if (-not (Test-Path -Path $Path)) { return $null }
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($value) {
                if ($BackupData.PSObject.Properties.Match('Registries').Count -eq 0 -or $null -eq $BackupData.Registries) {
                    $BackupData.Registries = @{}
                }
                $key = "$Path\$Name"
                $BackupData.Registries[$key] = @{ Path = $Path; Name = $Name; Value = $value.$Name; Timestamp = Get-Date }
            }
            return $null
        } catch { return $null }
    }
    try {
        if (-not (Test-Path -Path $Path)) { return $null }
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        if (-not $BackupPath) {
            $BackupPath = "$env:TEMP\Registry_${Name}_$((Get-Date -Format 'yyyyMMdd_HHmmss')).xml"
        }
        $backupDataLegacy = @{ Path = $Path; Name = $Name; Value = $value.$Name; Type = $value.PSObject.Properties[$Name].TypeNameOfValue; Timestamp = Get-Date }
        $backupDataLegacy | Export-Clixml -Path $BackupPath
        return $BackupPath
    } catch { return $null }
}

function Wait-ScriptContinue {
    [CmdletBinding()]
    param ([string]$Message = "Stiskněte libovolnou klávesu pro pokračování...")
    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
#endregion AMD-GpuHelpers

# ===========================================================
# HELPER FUNCTIONS
# ===========================================================

<#
.SYNOPSIS
    Detekuje generaci AMD GPU na základě názvu ovladače.

.DESCRIPTION
    Prohledá WMI a vrátí klíčové slovo generace (RDNA3, RDNA2, RDNA1, Vega, Polaris).

.OUTPUTS
    String: "RDNA3", "RDNA2", "RDNA1", "Vega", "Polaris", "Unknown"

.EXAMPLE
    $gen = Get-AmdGpuGeneration
    if ($gen -in @("RDNA1", "RDNA2", "RDNA3")) {
        Write-Host "Moderní RDNA architektura" -ForegroundColor Green
    }
#>
function Get-AmdGpuGeneration {
    try {
        $gpu = Get-WmiObject Win32_VideoController -ErrorAction Stop |
            Where-Object { $_.Name -like "*AMD*" -or $_.Name -like "*Radeon*" } |
            Select-Object -First 1

        if ($null -eq $gpu) {
            Write-Warning "Get-AmdGpuGeneration: Není detekována žádná AMD/Radeon GPU."
            return "Unknown"
        }

        $gpuName = $gpu.Name

        # Detekce RDNA 3 (RX 7xxx)
        if ($gpuName -match "7\d{3}") { return "RDNA3" }

        # Detekce RDNA 2 (RX 6xxx)
        if ($gpuName -match "6\d{3}") { return "RDNA2" }

        # Detekce RDNA 1 (RX 5xxx)
        if ($gpuName -match "5\d{3}") { return "RDNA1" }

        # Detekce Vega (Vega 56/64, Radeon VII)
        if ($gpuName -match "Vega" -or $gpuName -match "Radeon VII") { return "Vega" }

        # Detekce Polaris (RX 4xx, RX 5xx)
        if ($gpuName -match "(RX 4|RX 5)\d{2}") { return "Polaris" }

        # Pokud nic neodpovídá
        Write-Warning "Get-AmdGpuGeneration: Nalezeno GPU '$gpuName', ale nelze určit generaci."
        return "Unknown"

    } catch {
        Write-Error "Get-AmdGpuGeneration: Chyba při dotazu WMI: $($_.Exception.Message)"
        return "Unknown"
    }
}

<#
.SYNOPSIS
    Dynamicky detekuje registry cestu k AMD ovladači.

.DESCRIPTION
    Prohledá HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968...}\0*
    a vrátí cestu k aktivnímu AMD/Radeon ovladači.

.OUTPUTS
    String: Cesta k registry klíči (např. "HKLM:\SYSTEM\...\0000")
    Nebo $null, pokud AMD GPU není nalezena.

.EXAMPLE
    $path = Get-AmdDriverRegistryPath
    if ($null -ne $path) {
        Write-Host "AMD ovladač nalezen: $path"
    }
#>
function Get-AmdDriverRegistryPath {
    try {
        $amdDriverKey = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -ErrorAction SilentlyContinue |
            Where-Object { $_.DriverDesc -like "*AMD*" -or $_.DriverDesc -like "*Radeon*" } |
            Select-Object -First 1

        if ($null -ne $amdDriverKey) {
            $amdDriverPath = $amdDriverKey.PSPath.Replace("Microsoft.PowerShell.Core\Registry::", "")
            return $amdDriverPath
        } else {
            Write-Warning "Get-AmdDriverRegistryPath: AMD GPU ovladač nebyl nalezen v registru."
            return $null
        }
    } catch {
        Write-Error "Get-AmdDriverRegistryPath: Chyba při detekci: $($_.Exception.Message)"
        return $null
    }
}

# ===========================================================
# AMD TWEAKING FUNCTIONS
# ===========================================================

<#
.SYNOPSIS
    AMD Stabilita Tweaky (ULPS + ShaderCache).

.DESCRIPTION
    Implementuje 2 klíčové tweaky pro stabilitu AMD GPU:
      1. ULPS (Ultra-Low Power State) OFF - Oprava stability v idle/multi-monitor
      2. ShaderCache vynucen - Oprava stutteringu ve hrách

    MPO (Multi-Plane Overlay) byl přesunut do GPU_Advanced.psm1 (univerzální pro všechny GPU).

.NOTES
    Všechny tweaky používají přímý Set-ItemProperty s automatickým backupem.
#>
function Invoke-AmdTweaks-Stability {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  🛡️ AMD STABILITA (ULPS + ShaderCache)"
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    Write-Host "Aplikuji klíčové tweaky pro stabilitu AMD GPU..." -ForegroundColor Cyan
    Write-Host ""

    # Dynamická detekce cesty k AMD ovladači
    $amdDriverPath = Get-AmdDriverRegistryPath

    if ($null -eq $amdDriverPath) {
        Write-Error "Kritická chyba: Nebyla nalezena žádná aktivní AMD GPU v registru."
        Write-Host ""
        Write-Host "Stiskněte klávesu pro pokračování..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }

    Write-Host "  [INFO] Detekován AMD ovladač v cestě:" -ForegroundColor Gray
    Write-Host "         $amdDriverPath" -ForegroundColor Gray
    Write-Host ""

    $backupObject = Get-BackupData -FilePath $script:GpuBackupFile

    # Definice tweaků
    $umdPath = Join-Path $amdDriverPath "UMD"

    # Tweak 1: ULPS (Specifická cesta ovladače)
    $ulpsTweak = @{
        Path  = $amdDriverPath
        Name  = "EnableUlps"
        Value = 0
        Type  = "DWord"
    }

    # Tweak 2: ShaderCache (Specifická UMD cesta)
    $shaderTweak = @{
        Path  = $umdPath
        Name  = "ShaderCache"
        Value = ([byte[]](0x32, 0x00))
        Type  = "Binary"
    }

    $allTweaks = @($ulpsTweak, $shaderTweak)

    # Aplikace tweaků
    try {
        # ═══════════════════════════════════════════════════════════
        # BATCH REGISTRY OPERATIONS (jako TweakC - rychlé a přímé)
        # ═══════════════════════════════════════════════════════════
        $appliedCount = 0
        
        # Vytvoření cest, pokud neexistují
        foreach ($tweak in $allTweaks) {
            if (-not (Test-Path -Path $tweak.Path)) {
                try {
                    New-Item -Path $tweak.Path -Force -ErrorAction Stop | Out-Null
                    Write-Host "  -> Vytvořen klíč: $($tweak.Path)" -ForegroundColor Gray
                }
                catch {
                    Write-Warning "  ⚠️ Nelze vytvořit klíč: $($tweak.Path)"
                    continue
                }
            }
        }

        # Backup všech hodnot
        foreach ($tweak in $allTweaks) {
            Backup-RegistryValue -BackupData $backupObject -Path $tweak.Path -Name $tweak.Name
        }

        # BATCH aplikace všech hodnot najednou
        foreach ($tweak in $allTweaks) {
            try {
                Set-ItemProperty -Path $tweak.Path -Name $tweak.Name -Value $tweak.Value -Type $tweak.Type -Force -ErrorAction Stop
                Write-Host "  ✅ $($tweak.Name) aplikován." -ForegroundColor Green
                $appliedCount++
            }
            catch {
                Write-Warning "  ❌ Failed: $($tweak.Name) - $($_.Exception.Message)"
            }
        }

        Save-BackupData -Data $backupObject -FilePath $script:GpuBackupFile
        Write-Host ""
        Write-Host "  -> Aplikováno: $appliedCount registry hodnot" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host "  ✅ AMD STABILITA TWEAKY ÚSPĚŠNĚ APLIKOVÁNY!" -ForegroundColor Green
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host ""
        Write-Host "Výsledek:" -ForegroundColor Yellow
        Write-Host "  • ULPS zakázáno (Oprava stability v idle/multi-monitor)" -ForegroundColor White
        Write-Host "  • ShaderCache vynucen (Oprava stutteringu ve hrách)" -ForegroundColor White
        Write-Host ""
        Write-Host "💡 TIP: Pro MPO (black screens/flickering) použij" -ForegroundColor Cyan
        Write-Host "         GPU Menu → [4] Pokročilé → [M] MPO Toggle" -ForegroundColor Cyan

    } catch {
        Write-Error "Chyba při aplikaci AMD stability tweaků: $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "Stiskněte klávesu pro pokračování..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

<#
.SYNOPSIS
    AMD Latence Optimalizace (Input lag).

.DESCRIPTION
    Implementuje 3 tweaky pro snížení input lagu:
      1. KMD_DeLagEnabled = 0 (Vypne Anti-Lag na úrovni ovladače)
      2. KMD_FRTEnabled = 0 (Vypne Frame Rate Target)
      3. DisableDMACopy = 1 (Nižší latence DMA)

.NOTES
    Všechny tweaky jsou aplikovány do UMD podklíče AMD ovladače.
#>
function Invoke-AmdTweaks-Latency {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  ⚡ AMD LATENCE OPTIMALIZACE"
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    Write-Host "Aplikuji 3 tweaky pro snížení input lagu..." -ForegroundColor Cyan
    Write-Host ""

    # Dynamická detekce cesty k AMD ovladači
    $amdDriverPath = Get-AmdDriverRegistryPath

    if ($null -eq $amdDriverPath) {
        Write-Error "Kritická chyba: Nebyla nalezena žádná aktivní AMD GPU v registru."
        Write-Host ""
        Write-Host "Stiskněte klávesu pro pokračování..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }

    $umdPath = Join-Path $amdDriverPath "UMD"
    Write-Host "  [INFO] Detekována cesta UMD: $umdPath" -ForegroundColor Gray
    Write-Host ""

    # Vytvoření UMD cesty, pokud neexistuje
    if (-not (Test-Path -Path $umdPath)) {
        New-Item -Path $umdPath -Force -ErrorAction Stop | Out-Null
        Write-Host "  -> Vytvořen klíč: $umdPath" -ForegroundColor Gray
    }

    $backupObject = Get-BackupData -FilePath $script:GpuBackupFile

    # Definice tweaků
    $tweaks = @{
        "KMD_DeLagEnabled" = @{ Value = 0; Type = "DWord" }
        "KMD_FRTEnabled"   = @{ Value = 0; Type = "DWord" }
        "DisableDMACopy"   = @{ Value = 1; Type = "DWord" }
    }

    try {
        # ═══════════════════════════════════════════════════════════
        # BATCH REGISTRY OPERATIONS (jako TweakC - rychlé a přímé)
        # ═══════════════════════════════════════════════════════════
        $appliedCount = 0
        
        # Backup všech hodnot
        foreach ($name in $tweaks.Keys) {
            Backup-RegistryValue -BackupData $backupObject -Path $umdPath -Name $name
        }

        # BATCH aplikace všech hodnot najednou
        foreach ($name in $tweaks.Keys) {
            $tweak = $tweaks[$name]
            
            try {
                Set-ItemProperty -Path $umdPath -Name $name -Value $tweak.Value -Type $tweak.Type -Force -ErrorAction Stop
                Write-Host "  ✅ $name = $($tweak.Value)" -ForegroundColor Green
                $appliedCount++
            }
            catch {
                Write-Warning "  ❌ Failed: $name - $($_.Exception.Message)"
            }
        }

        Save-BackupData -Data $backupObject -FilePath $script:GpuBackupFile
        Write-Host ""
        Write-Host "  -> Aplikováno: $appliedCount registry hodnot" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host "  ✅ AMD LATENCE TWEAKY ÚSPĚŠNĚ APLIKOVÁNY!" -ForegroundColor Green
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host ""
        Write-Host "Výsledek:" -ForegroundColor Yellow
        Write-Host "  • Vypnuty interní funkce ovladače (Anti-Lag, FRT)" -ForegroundColor White
        Write-Host "  • DMA Copy optimalizováno pro latenci" -ForegroundColor White

    } catch {
        Write-Error "Chyba při aplikaci AMD latency tweaků: $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "Stiskněte klávesu pro pokračování..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

<#
.SYNOPSIS
    AMD Performance Optimalizace (Bezpečné tweaky).

.DESCRIPTION
    Implementuje 3 bezpečné tweaky pro maximální výkon:
      1. PP_PowerSavingFeatureEnabled = 0 (Vypne agresivní power saving)
      2. PP_SclkDeepSleepDisable = 1 (Vypne hluboký spánek jádra)
      3. KMD_EnableInternalLargePage = 1 (Povolí large page pro VRAM)

.NOTES
    PP_ tweaky jsou v rootu ovladače, KMD_ tweaky jsou v UMD.
    Tyto tweaky NEOBSAHUJÍ thermal throttling OFF (to je pro Hall of Tweaks).
#>
function Invoke-AmdTweaks-Performance {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  🚀 AMD PERFORMANCE OPTIMALIZACE (Bezpečné)"
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    Write-Host "Aplikuji 3 bezpečné tweaky pro výkon..." -ForegroundColor Cyan
    Write-Host ""

    # Dynamická detekce cesty k AMD ovladači
    $amdDriverPath = Get-AmdDriverRegistryPath

    if ($null -eq $amdDriverPath) {
        Write-Error "Kritická chyba: Nebyla nalezena žádná aktivní AMD GPU v registru."
        Write-Host ""
        Write-Host "Stiskněte klávesu pro pokračování..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }

    $umdPath = Join-Path $amdDriverPath "UMD"
    Write-Host "  [INFO] Detekována cesta ovladače: $amdDriverPath" -ForegroundColor Gray
    Write-Host "  [INFO] Detekována cesta UMD: $umdPath" -ForegroundColor Gray
    Write-Host ""

    if (-not (Test-Path -Path $umdPath)) {
        New-Item -Path $umdPath -Force -ErrorAction Stop | Out-Null
        Write-Host "  -> Vytvořen klíč: $umdPath" -ForegroundColor Gray
    }

    $backupObject = Get-BackupData -FilePath $script:GpuBackupFile

    # Definice tweaků (rozděleno podle cesty)
    $tweaks = @(
        @{ Path = $amdDriverPath; Name = "PP_PowerSavingFeatureEnabled"; Value = 0; Type = "DWord" }
        @{ Path = $amdDriverPath; Name = "PP_SclkDeepSleepDisable"; Value = 1; Type = "DWord" }
        @{ Path = $umdPath; Name = "KMD_EnableInternalLargePage"; Value = 1; Type = "DWord" }
    )

    try {
        # ═══════════════════════════════════════════════════════════
        # BATCH REGISTRY OPERATIONS (jako TweakC - rychlé a přímé)
        # ═══════════════════════════════════════════════════════════
        $appliedCount = 0
        
        # Backup všech hodnot
        foreach ($tweak in $tweaks) {
            Backup-RegistryValue -BackupData $backupObject -Path $tweak.Path -Name $tweak.Name
        }

        # BATCH aplikace všech hodnot najednou
        foreach ($tweak in $tweaks) {
            try {
                Set-ItemProperty -Path $tweak.Path -Name $tweak.Name -Value $tweak.Value -Type $tweak.Type -Force -ErrorAction Stop
                Write-Host "  ✅ $($tweak.Name) = $($tweak.Value)" -ForegroundColor Green
                $appliedCount++
            }
            catch {
                Write-Warning "  ❌ Failed: $($tweak.Name) - $($_.Exception.Message)"
            }
        }

        Save-BackupData -Data $backupObject -FilePath $script:GpuBackupFile
        Write-Host ""
        Write-Host "  -> Aplikováno: $appliedCount registry hodnot" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host "  ✅ AMD PERFORMANCE TWEAKY (Bezpečné) APLIKOVÁNY!" -ForegroundColor Green
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host ""
        Write-Host "Výsledek:" -ForegroundColor Yellow
        Write-Host "  • Vypnuty úsporné funkce (PowerSaving, DeepSleep)" -ForegroundColor White
        Write-Host "  • Povolena optimalizace 'Large Page' pro VRAM" -ForegroundColor White

    } catch {
        Write-Error "Chyba při aplikaci AMD performance tweaků: $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "Stiskněte klávesu pro pokračování..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===========================================================
# AMD GPU SUB-MENU (PLACEHOLDER)
# ===========================================================

<#
.SYNOPSIS
    AMD GPU Tweaky - Sub-menu (PLACEHOLDER pro budoucnost).

.DESCRIPTION
    Zobrazuje informační menu pro AMD GPU.
    Struktura je připravena pro budoucí implementaci tweaků.

    Volby:
      [i] Info o AMD tweacích + dokumentace
      [Q] Zpět

.NOTES
    Tweaky budou doplněny, jakmile budou dostupné validované hodnoty.
    Struktura podpory je kompletně připravena.
#>
function Show-AmdSubMenu {
    while ($true) {
        Clear-Host
        Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "             🎮 AMD GPU TWEAKY                            " -ForegroundColor Green
        Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""

        # Detekce AMD GPU
        try {
            $gpu = Get-WmiObject Win32_VideoController -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*AMD*" -or $_.Name -like "*Radeon*" } | Select-Object -First 1
            if ($gpu) {
                $generation = Get-AmdGpuGeneration
                Write-Host "  GPU: $($gpu.Name)" -ForegroundColor Cyan
                Write-Host "  Generace: $generation" -ForegroundColor Gray
                Write-Host ""
            }
        } catch {
            # Tiché selhání
        }

        Write-Host "┌──────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
        Write-Host "│  TWEAKY (Gaming Optimalizace)                            │" -ForegroundColor Cyan
        Write-Host "└──────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        Write-Host ""

        Write-Host "[1] ⚡ LATENCE OPTIMALIZACE" -ForegroundColor Yellow
        Write-Host "    → Anti-Lag OFF, DMA latency, FRT OFF (3 tweaky)" -ForegroundColor White
        Write-Host "    💡 Benefit: Nižší input lag, rychlejší odezva" -ForegroundColor Gray
        Write-Host "    ⚠️  Riziko: Nízké" -ForegroundColor Green
        Write-Host ""

        Write-Host "[2] 🚀 PERFORMANCE OPTIMALIZACE" -ForegroundColor Yellow
        Write-Host "    → Power saving OFF, Deep sleep OFF, Large pages (3 tweaky)" -ForegroundColor White
        Write-Host "    💡 Benefit: Vyšší FPS, stabilnější clocks" -ForegroundColor Gray
        Write-Host "    ⚠️  Riziko: Nízké (žádné thermal tweaky)" -ForegroundColor Green
        Write-Host ""

        Write-Host "[3] 🛡️  STABILITA" -ForegroundColor Yellow
        Write-Host "    → ULPS OFF, ShaderCache vynucen (2 tweaky)" -ForegroundColor White
        Write-Host "    💡 Benefit: Oprava stutteringu, multi-monitor stability" -ForegroundColor Gray
        Write-Host "    ⚠️  Riziko: Minimální" -ForegroundColor Green
        Write-Host "    ℹ️  MPO (black screens) → GPU Menu [4] Pokročilé [M]" -ForegroundColor DarkGray
        Write-Host ""

        Write-Host "──────────────────────────────────────────────────────────"
        Write-Host "[i] ℹ️  INFO O AMD TWEACÍCH + DOKUMENTACE" -ForegroundColor White
        Write-Host ""

        Write-Host "[Q] ⬅️  ZPĚT DO HLAVNÍHO GPU MENU" -ForegroundColor Red
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        switch ($choice.ToUpper()) {
            '1' { Invoke-AmdTweaks-Latency }
            '2' { Invoke-AmdTweaks-Performance }
            '3' { Invoke-AmdTweaks-Stability }
            'I' { Show-AmdInfo }
            'Q' { return }
            default {
                Write-Warning "Neplatná volba. Zadejte 1-3, I, nebo Q."
                Start-Sleep -Seconds 2
            }
        }
    }
}

# ===========================================================
# AMD GPU INFO + DOKUMENTACE
# ===========================================================

<#
.SYNOPSIS
    Zobrazí informace o AMD GPU tweacích a jak je doplnit.

.DESCRIPTION
    Detailní vysvětlení:
      - Jak najít svou AMD GPU registry cestu
      - Příklady AMD tweaků
      - Odkazy na dokumentaci
      - Návod jak doplnit tweaky do tohoto modulu

.NOTES
    Slouží jako "nápověda" pro implementaci AMD tweaků.
#>
function Show-AmdInfo {
    Clear-Host
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "          ℹ️  AMD GPU TWEAKY - DOKUMENTACE" -ForegroundColor White
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "═══ AMD GPU TWEAKY - STATUS ═══" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "⚠️  PŘIPRAVENO PRO BUDOUCNOST" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Struktura modulu je kompletně připravena." -ForegroundColor White
    Write-Host "Stačí doplnit validované AMD tweaky." -ForegroundColor White
    Write-Host ""

    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""

    Write-Host "🔍 JAK NAJÍT SVOU AMD GPU REGISTRY CESTU:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "PowerShell příkaz:" -ForegroundColor Cyan
    Write-Host '  Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -ErrorAction SilentlyContinue |' -ForegroundColor Gray
    Write-Host '      Where-Object {$_.DriverDesc -like "*AMD*" -or $_.DriverDesc -like "*Radeon*"} |' -ForegroundColor Gray
    Write-Host '      Select-Object PSPath, DriverDesc, DriverVersion' -ForegroundColor Gray
    Write-Host ""
    Write-Host "Výstup ukáže cestu typu:" -ForegroundColor White
    Write-Host "  PSPath: Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\...\0000" -ForegroundColor Gray
    Write-Host "  DriverDesc: AMD Radeon RX 6800 XT" -ForegroundColor Gray
    Write-Host "  DriverVersion: 31.0.12029.7000" -ForegroundColor Gray
    Write-Host ""

    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""

    Write-Host "📝 PŘÍKLADY AMD TWEAKŮ (pro budoucí implementaci):" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "LATENCE:" -ForegroundColor Cyan
    Write-Host "  • KMD_DeLagEnabled = 0 (AMD Anti-Lag control)" -ForegroundColor White
    Write-Host "  • KMD_FRTEnabled = 0 (Frame Rate Target)" -ForegroundColor White
    Write-Host "  • DisableDMACopy = 1 (Lower latency)" -ForegroundColor White
    Write-Host ""
    Write-Host "PERFORMANCE:" -ForegroundColor Cyan
    Write-Host "  • PP_PowerSavingFeatureEnabled = 0 (Disable power saving)" -ForegroundColor White
    Write-Host "  • PP_ThermalAutoThrottlingEnable = 0 (Disable thermal throttling)" -ForegroundColor White
    Write-Host "  • PP_SclkDeepSleepDisable = 1 (Disable deep sleep)" -ForegroundColor White
    Write-Host "  • KMD_EnableInternalLargePage = 1 (Large page support)" -ForegroundColor White
    Write-Host ""
    Write-Host "⚠️  VAROVÁNÍ:" -ForegroundColor Yellow
    Write-Host "  • Thermal tweaky vyžadují sledování teplot!" -ForegroundColor White
    Write-Host "  • Pokud >95°C junction, REVERT tweaky!" -ForegroundColor White
    Write-Host "  • AMD běží horkěji než NVIDIA" -ForegroundColor White
    Write-Host ""

    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""

    Write-Host "💡 KOMPATIBILITA:" -ForegroundColor Yellow
    Write-Host "  ✅ RDNA3 (RX 7xxx) - Plánováno" -ForegroundColor Green
    Write-Host "  ✅ RDNA2 (RX 6xxx) - Plánováno" -ForegroundColor Green
    Write-Host "  ⚠️ RDNA1 (RX 5xxx) - Částečná podpora" -ForegroundColor Yellow
    Write-Host "  ⚠️ Vega/Polaris - Netestováno (SLEDUJTE TEPLOTY!)" -ForegroundColor Yellow
    Write-Host ""

    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""

    Write-Host "📄 DETAILNÍ DOKUMENTACE:" -ForegroundColor Yellow
    Write-Host ""

    $docAmd = Join-Path $script:DocPath "AMD-TWEAKS-PŘÍKLADY.txt"
    $docImpl = Join-Path $script:DocPath "AMD-GPU-IMPLEMENTACE.txt"

    if (Test-Path $docAmd) {
        Write-Host "  ✅ AMD-TWEAKS-PŘÍKLADY.txt" -ForegroundColor Green
        Write-Host "     Cesta: $docAmd" -ForegroundColor Gray
        Write-Host "     Obsah: Příklady AMD tweaků pro budoucnost (230 řádků)" -ForegroundColor Gray
        Write-Host ""
    } else {
        Write-Host "  ⚠️ AMD-TWEAKS-PŘÍKLADY.txt - NENALEZENO" -ForegroundColor Yellow
        Write-Host "     Očekávaná cesta: $docAmd" -ForegroundColor Gray
        Write-Host ""
    }

    if (Test-Path $docImpl) {
        Write-Host "  ✅ AMD-GPU-IMPLEMENTACE.txt" -ForegroundColor Green
        Write-Host "     Cesta: $docImpl" -ForegroundColor Gray
        Write-Host "     Obsah: Dokumentace implementace (144 řádků)" -ForegroundColor Gray
        Write-Host ""
    } else {
        Write-Host "  ⚠️ AMD-GPU-IMPLEMENTACE.txt - NENALEZENO" -ForegroundColor Yellow
        Write-Host "     Očekávaná cesta: $docImpl" -ForegroundColor Gray
        Write-Host ""
    }

    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""

    Write-Host "🛠️ JAK DOPLNIT AMD TWEAKY DO TOHOTO MODULU:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Sběr AMD Tweaků:" -ForegroundColor Cyan
    Write-Host "   • Najdi validované AMD registry tweaky" -ForegroundColor White
    Write-Host "   • Ověř jejich bezpečnost a účinek" -ForegroundColor White
    Write-Host "   • Zdokumentuj, co každý tweak dělá" -ForegroundColor White
    Write-Host ""
    Write-Host "2. Implementace:" -ForegroundColor Cyan
    Write-Host "   • Otevři GPU_AMD.psm1" -ForegroundColor White
    Write-Host "   • Vytvoř funkce: Invoke-AmdTweaks-Latency, -Performance, -Stability" -ForegroundColor White
    Write-Host "   • Použij stejnou strukturu jako NVIDIA/Intel" -ForegroundColor White
    Write-Host ""
    Write-Host "3. Testování:" -ForegroundColor Cyan
    Write-Host "   • Spusť na AMD GPU systému" -ForegroundColor White
    Write-Host "   • Ověř, že tweaky fungují" -ForegroundColor White
    Write-Host "   • Zkontroluj backup/restore mechanismus" -ForegroundColor White
    Write-Host ""

    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""

    Write-Host "💬 FREQUENTLY ASKED:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Q: Kdy budou AMD tweaky dostupné?" -ForegroundColor Cyan
    Write-Host "A: Jakmile budou seženy validované hodnoty." -ForegroundColor White
    Write-Host "   Struktura je již připravena!" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Q: Můžu použít NVIDIA tweaky na AMD?" -ForegroundColor Cyan
    Write-Host "A: ❌ NE! Každý výrobce má jiné registry cesty." -ForegroundColor White
    Write-Host ""
    Write-Host "Q: Je modul bezpečný bez tweaků?" -ForegroundColor Cyan
    Write-Host "A: ✅ ANO! Žádné tweaky se neaplikují automaticky." -ForegroundColor White
    Write-Host ""

    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    Write-Host "Stiskněte klávesu pro návrat do AMD menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===========================================================
# MODULE EXPORTS
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

    Show-AmdSubMenu
}

Export-ModuleMember -Function @(
    # Helper functions
    'Get-AmdGpuGeneration',
    'Get-AmdDriverRegistryPath',

    # Tweaking functions
    'Invoke-AmdTweaks-Stability',
    'Invoke-AmdTweaks-Latency',
    'Invoke-AmdTweaks-Performance',

    # Menu functions
    'Show-AmdSubMenu',
    'Show-AmdInfo',
    'Invoke-ModuleEntry'
)

# ===========================================================
# MODULE INITIALIZATION LOG
# ===========================================================

if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
    Write-CoreLog -Message "GPU_AMD.psm1 v$script:ModuleVersion loaded successfully (9 tweaks ready)" -Level Info
}

