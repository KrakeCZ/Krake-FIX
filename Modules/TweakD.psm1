# ═══════════════════════════════════════════════════════════════════════════
# Module: TweakD.psm1 - NVME REGISTRY DISK + FSUTIL Optimalizace
# ═══════════════════════════════════════════════════════════════════════════
# REŽIM D: DISK NVME BOOST + fsutil
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

function Get-TweakDRegContent {
    [CmdletBinding()]
    param()

    return @'
Windows Registry Editor Version 5.00

; ================================================================
; KRAKE-FIX Registry Tweaks - REŽIM NVME REGISTRY
; ================================================================

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides]
"735209102"=dword:00000001
"1853569164"=dword:00000001
"156965516"=dword:00000001
'@
}

$UtilsModule = Join-Path $PSScriptRoot 'Utils.psm1'
if (-not (Get-Command -Name Get-RegistryItemPrivilege -ErrorAction SilentlyContinue)) {
    if (Test-Path -Path $UtilsModule) {
        Import-Module $UtilsModule -Force -ErrorAction Stop
    }
}

$script:TweakDRegistryListCache = $null

function Convert-TweakDRegistryPath {
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

$script:TweakDServiceList = @(    
)


function Get-TweakDServiceList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return $script:TweakDServiceList
}

function Show-TweakDInfo {
    Clear-Host
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  TWEAK D: INFO & VYSVĚTLENÍ" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "1. NVMe Driver & FeatureManagement (Registry)" -ForegroundColor Magenta
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
    Write-Host "Přístupové doby v syntetických benchmarkech se snížily."
    Write-Host "Propustnost se u PCIe 4.0 SSD zvýšila přibližně o 10 až 15 procent."
    Write-Host "Toto však nebylo měřeno čistě v klinickém testovacím prostředí,"
    Write-Host "ale spíše na „normální“ pracovní stanici."
    Write-Host "Další úvodní testy také ukázaly zvýšení výkonu u systémů s PCIe 3.0 SSD."
    Write-Host "Systémy dosahují „stabilního stavu“ znatelně rychleji po restartu."
    Write-Host ""
    Write-Host "Nový ovladač je v našich testech v systému Windows 11 25H2/ 24H2 aktivní."
    Write-Host "To lze ověřit ve Správci zařízení (Device Manager) -> 'Úložná média'."
    Write-Host "Po přepnutí se disk zobrazuje v 'Úložná média' místo v 'Disky'."
    Write-Host "Podrobnosti o ovladači obsahují položku 'nvmedisk.sys'."
    Write-Host ""

    Write-Host "2. FSUTIL Optimalizace (Disk Latency & Wear)" -ForegroundColor Magenta
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
    Write-Host "Tento skript se snaží zredukovat zbytečné operace na pozadí."
    Write-Host "Cílem je uvolnit systémové prostředky pro hry a prodloužit životnost disku."
    Write-Host ""
    Write-Host "A) DisableLastAccess = 1" -ForegroundColor Green
    Write-Host "   Co to dělá: Vypne zápis metadat 'naposledy otevřeno' při každém čtení."
    Write-Host "   Výkon: Ušetří se tisíce malých zápisů. Disk se soustředí jen na čtení."
    Write-Host "   Životnost: Menší opotřebení paměťových buněk SSD."
    Write-Host ""
    Write-Host "B) EncryptPagingFile = 0" -ForegroundColor Green
    Write-Host "   Co to dělá: Vypne šifrování stránkovacího souboru (swap)."
    Write-Host "   Výkon CPU: Šifrování stojí CPU cycles. U herního PC chceme CPU pro hru."
    Write-Host "   Latence: Může snížit mikro-lagy pokud hra využívá swap."
    Write-Host ""
    
    Write-Host "Stiskněte libovolnou klávesu pro návrat..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Invoke-RevertTweakD {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  REVERT TWEAK D - Obnova výchozího nastavení" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
    
    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 1: ODSTRANĚNÍ REGISTRY KLÍČŮ
    # ═══════════════════════════════════════════════════════════════════════
    Write-Host "FÁZE 1: Odstraňuji NVMe Registry Tweaks..." -ForegroundColor Yellow
    
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides"
    $valuesToRemove = @('735209102', '1853569164', '156965516')
    
    if (Test-Path $regPath) {
        foreach ($val in $valuesToRemove) {
            try {
                Remove-ItemProperty -Path $regPath -Name $val -ErrorAction SilentlyContinue
                Write-Host "  ✅ Odstraněna hodnota: $val" -ForegroundColor Green
            }
            catch {
                # Může selhat pokud neexistuje, to je v pořádku
                Write-Verbose "Hodnota $val nebyla nalezena."
            }
        }
    }
    else {
        Write-Host "  ⚠️  Cesta k registrům neexistuje (již čisto?)" -ForegroundColor DarkGray
    }
    
    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 2: RESET FSUTIL
    # ═══════════════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "FÁZE 2: Resetuji FSUTIL (Default)..." -ForegroundColor Yellow
    
    # DisableLastAccess = 2 (System Managed / Default often 2 or 3 on modern OS, 0 is User Enabled)
    try {
        Start-Process -FilePath "fsutil.exe" -ArgumentList "behavior", "set", "DisableLastAccess", "2" -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "  ✅ DisableLastAccess = 2 (System Managed)" -ForegroundColor Green
    }
    catch {
        Write-Warning "  ⚠️  fsutil DisableLastAccess reset failed"
    }

    # EncryptPagingFile = 0 (Default is disabled)
    try {
        Start-Process -FilePath "fsutil.exe" -ArgumentList "behavior", "set", "EncryptPagingFile", "0" -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "  ✅ EncryptPagingFile = 0 (Default)" -ForegroundColor Green
    }
    catch {
        Write-Warning "  ⚠️  fsutil EncryptPagingFile reset failed"
    }
    
    Write-Host ""
    Write-Host "✅ Tweak D byl úspěšně vrácen do výchozího stavu." -ForegroundColor Green
    Start-Sleep -Seconds 2
}

function Invoke-TweakD {
    [CmdletBinding()]
    param()

    # Loop to allow returning from Info screen
    while ($true) {
        Clear-Host
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host "  TWEAK D - NVMe/SSD Boost" -ForegroundColor Magenta
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "Vyberte akci:" 
        Write-Host "[1] 🔥 APLIKOVAT Tweak (Boost = NVMe Registry + Fsutil)" -ForegroundColor Green
        Write-Host "[2] ↩️  OBNOVIT výchozí nastavení (Revert)" -ForegroundColor Yellow
        Write-Host "[3] 💿 POUZE FSUTIL (SSD Bez NVME Registry)" -ForegroundColor Cyan
        Write-Host "[i] ℹ️  INFO - Vysvětlení a Detaily" -ForegroundColor Blue
        Write-Host "[Q] Zpět" -ForegroundColor Gray
        Write-Host ""
        
        $action = Read-Host "Vaše volba"
        
        if ($action -eq '2') {
            Invoke-RevertTweakD
            return
        }
        if ($action -eq 'i' -or $action -eq 'I') {
            Show-TweakDInfo
            continue # Loop back to menu
        }
        if ($action -eq 'Q' -or $action -eq 'q') {
            return
        }
        
        # Valid options to proceed (1 or 3)
        if ($action -eq '1' -or $action -match '^1$' -or $action -eq '3' -or $action -match '^3$') {
            break # Exit loop and proceed to apply
        }
    }
    
    # POKRAČOVAT V APLIKACI (Volba 1 nebo 3)

    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  TWEAK pouze pro Registry - NVME" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""

    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 1: REGISTRY TWEAKS (Pouze pokud volba NENÍ 3)
    # ═══════════════════════════════════════════════════════════════════════
    if ($action -ne '3') {
        Write-Host ""
        Write-Host "FÁZE 1: APLIKUJI REGISTRY TWEAKS..." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  🔐 Spouštím s SYSTEM oprávněními..." -ForegroundColor Cyan
        Write-Host ""

        $regContent = Get-TweakDRegContent
        
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
                        }
                        catch {
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
                        }
                        catch {
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
    }
    else {
        Write-Host "ℹ️  Přeskakuji Registry Tweaks (Vybrána volba 3)..." -ForegroundColor DarkGray
        Write-Host ""
    }

    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 2: FSUTIL OPTIMALIZACE (SSD)
    # ═══════════════════════════════════════════════════════════════════════
    Write-Host "FÁZE 2: FSUTIL OPTIMALIZACE (SSD)..." -ForegroundColor Yellow
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
    Write-Host "  ✅ TWEAK DOKONČEN!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "💡 TIP: RESTART PC je NUTNÝ!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Get-TweakDRegistryList {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    if ($null -ne $script:TweakDRegistryListCache) {
        return $script:TweakDRegistryListCache
    }

    $regContent = Get-TweakDRegContent
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
            $currentPath = Convert-TweakDRegistryPath -RawPath $matches[1]
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
                }
                catch {
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

    $script:TweakDRegistryListCache = $items.ToArray()
    return $script:TweakDRegistryListCache
}

function Get-TweakDSnapshot {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $registryItems = Get-TweakDRegistryList
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
                    }
                    catch {
                        $currentValue = 'ValueDoesNotExist'
                        $valueKind = 'None'
                    }
                }
                else {
                    $valueNames = $registryKey.GetValueNames()
                    if ($valueNames -contains $item.Name) {
                        $currentValue = $registryKey.GetValue($item.Name, $null)
                        $valueKind = $registryKey.GetValueKind($item.Name).ToString()
                        $valueExists = $true
                    }
                }
            }
            catch {
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

    Invoke-TweakD
}

Export-ModuleMember -Function @(
    'Invoke-TweakD',
    'Invoke-RevertTweakD',
    'Get-TweakDRegistryList',
    'Get-TweakDSnapshot',
    'Invoke-ModuleEntry'
)
