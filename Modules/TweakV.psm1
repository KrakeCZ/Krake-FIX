# ═══════════════════════════════════════════════════════════════════════════
# Module: TweakV.psm1 - REGISTRY
# ═══════════════════════════════════════════════════════════════════════════
# REŽIM RestoreOLD_Windows_Photo_Viewer_CURRENT_USER
# ===========================================================
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ===========================================================
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
function Get-TweakVRegContent {
    [CmdletBinding()]
    param()
    return @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\Classes\.bmp]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.cr2]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.dib]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.gif]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.ico]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jfif]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jpe]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jpeg]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jpg]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jxr]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.png]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.tif]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.tiff]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.wdp]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cr2\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=hex(0):

'@
}
$UtilsModule = Join-Path $PSScriptRoot 'Utils.psm1'
if (-not (Get-Command -Name Get-RegistryItemPrivilege -ErrorAction SilentlyContinue)) {
    if (Test-Path -Path $UtilsModule) {
        Import-Module $UtilsModule -Force -ErrorAction Stop
    }
}
$script:TweakVRegistryListCache = $null
function Convert-TweakVRegistryPath {
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
$script:TweakVServiceList = @(    
)
function Get-TweakVServiceList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()
    return $script:TweakVServiceList
}
function Invoke-TweakV {
    [CmdletBinding()]
    param()
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  RestoreOLD_Windows_Photo_Viewer_CURRENT_USER" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "⚠️  Přidá zpět starý Windows Photo Viewer pro aktuálního uživatele" -ForegroundColor Red
    Write-Host ""
    # ═══════════════════════════════════════════════════════════════════════
    # FÁZE 1: REGISTRY APLIKACE (CURRENT USER)
    # ═══════════════════════════════════════════════════════════════════════
    Write-Host "FÁZE 1: APLIKUJI REGISTRY ..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  👤 Spouštím v kontextu aktuálního uživatele..." -ForegroundColor Cyan
    Write-Host ""
    $regContent = Get-TweakVRegContent
    # ScriptBlock pro USER kontext
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
            if ($null -ne $currentPath -and $line -match '^("(?<name>[^"]+)"|(?<default>@))=(?<data>.+)$') {
                $valueName = if ($matches['default'] -eq '@') { '(default)' } else { $matches['name'] }
                $valueData = $matches['data'].Trim()
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
                    elseif ($valueData -eq 'hex(0):') {
                        # HEX(0) = Empty Binary (for OpenWithProgids)
                        Set-ItemProperty -Path $currentPath -Name $valueName -Value ([byte[]]@()) -Type Binary -ErrorAction Stop
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
    # SPUSTIT JAKO AKTUÁLNÍ UŽIVATEL (Admin)
    try {
        # Spustíme blok přímo v aktuálním kontextu
        $appliedCount = & $applyRegistryBlock -RegContent $regContent
        Write-Host "  ✅ Aplikováno: $appliedCount registry hodnot (User režim)" -ForegroundColor Green
    }
    catch {
        Write-Host "  ❌ Chyba při aplikaci registry: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✅Starý Windows Photo Viewer byl obnoven!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "💡 TIP: RESTART PC je NUTNÝ!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
function Get-TweakVRegistryList {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()
    if ($null -ne $script:TweakVRegistryListCache) {
        return $script:TweakVRegistryListCache
    }
    $regContent = Get-TweakVRegContent
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
            $currentPath = Convert-TweakVRegistryPath -RawPath $matches[1]
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
    $script:TweakVRegistryListCache = $items.ToArray()
    return $script:TweakVRegistryListCache
}
function Get-TweakVSnapshot {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()
    $registryItems = Get-TweakVRegistryList
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
    Invoke-TweakV
}
Export-ModuleMember -Function @(
    'Invoke-TweakV',
    'Get-TweakVServiceList',
    'Get-TweakVRegistryList',
    'Get-TweakVSnapshot',
    'Invoke-ModuleEntry'
)