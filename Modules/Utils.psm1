# ═══════════════════════════════════════════════════════════════════════════
# Module: Utils.psm1
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX v2 Modular
# Version:      2.0.0
# Author:       KRAKE-FIX Team
# Created:      2025-10-30
# Last Updated: 2025-10-30
# ═══════════════════════════════════════════════════════════════════════════
# Description:  Utility & Backup Helper Functions
#               - Backup data management (Get/Save)
#               - Tweakable items enumeration
#               - Registry & Service backup wrappers
#               - Wait utilities
# Category:     Utilities / Helpers
# Dependencies: Core.psm1
# Admin Rights: Required for backup operations
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️  SECURITY & COMPLIANCE NOTICE
# ═══════════════════════════════════════════════════════════════════════════
# • This module provides helper functions for backup operations.
# • Designed for educational and testing purposes only.
# • Author assumes no liability for misuse outside academic context.
# • BSI4 compliant: Input validation, error handling, audit logging.
# ═══════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1
#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ───────────────────────────────────────────────────────────────────────────
# IMPORT CORE MODULE (REQUIRED FOR LOGGING)
# ───────────────────────────────────────────────────────────────────────────
# Use Core module functions - loaded by Main.ps1, only import if standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $CoreModule = Join-Path $PSScriptRoot 'Core.psm1'
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    } else {
        Write-Error "CRITICAL: Core.psm1 not found at: $CoreModule"
        throw "Missing dependency: Core.psm1"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# BACKUP DATA MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════

function Get-BackupData {
    <#
    .SYNOPSIS
        Načte data ze záložního souboru.

    .DESCRIPTION
        Podporuje JSON a XML formáty. Automaticky detekuje typ podle přípony.
        Robustní error handling.

    .PARAMETER FilePath
        Cesta k záložnímu souboru (.json nebo .xml).

    .OUTPUTS
        [Object] - Deserializovaný obsah zálohy nebo $null při chybě.

    .EXAMPLE
        $backup = Get-BackupData -FilePath "C:\Backup\registry.json"
        if ($backup) {
            Write-Host "Backup loaded: $($backup.Timestamp)"
        }

    .NOTES
        - JSON: ConvertFrom-Json
        - XML: Import-Clixml
        - Returns $null on failure
    #>
    [CmdletBinding()]
    [OutputType([Object])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )

    try {
        Write-Verbose "Loading backup from: $FilePath"

        if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
            Write-CoreLog "Backup file not found: $FilePath" -Level ERROR -Module 'Utils'
            Write-Error "Backup file not found: $FilePath"
            return $null
        }

        $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()

        $backupData = switch ($extension) {
            '.json' {
                Write-Verbose "Loading JSON backup..."
                Get-Content -Path $FilePath -Raw -ErrorAction Stop | ConvertFrom-Json
            }
            '.xml' {
                Write-Verbose "Loading XML backup..."
                Import-Clixml -Path $FilePath -ErrorAction Stop
            }
            default {
                throw "Unsupported backup format: $extension (supported: .json, .xml)"
            }
        }

        Write-CoreLog "Backup loaded successfully: $FilePath" -Level SUCCESS -Module 'Utils'
        return $backupData

    } catch {
        Write-CoreLog "Failed to load backup: $($_.Exception.Message)" -Level ERROR -Module 'Utils'
        Write-Error "Failed to load backup from $FilePath : $($_.Exception.Message)"
        return $null
    }
}

function Save-BackupData {
    <#
    .SYNOPSIS
        Uloží data do záložního souboru s timestampem.

    .DESCRIPTION
        Podporuje JSON a XML formáty. Automaticky vytvoří adresář pokud neexistuje.
        Přidá timestamp do názvu souboru.

    .PARAMETER Data
        Data k zálohování (libovolný objekt).

    .PARAMETER FilePath
        Cesta k záložnímu souboru. Pokud neobsahuje timestamp, přidá se automaticky.

    .PARAMETER Format
        Formát zálohy ('JSON' nebo 'XML'). Výchozí: JSON.

    .OUTPUTS
        [string] - Plná cesta k vytvořenému záložnímu souboru nebo $null při chybě.

    .EXAMPLE
        $data = @{ Registry = @(); Services = @(); Timestamp = (Get-Date) }
        $backupPath = Save-BackupData -Data $data -FilePath "C:\Backup\registry.json"
        # Vytvoří: C:\Backup\registry_20251029_143052.json

    .NOTES
        - JSON: ConvertTo-Json -Depth 10
        - XML: Export-Clixml
        - Auto-creates directory
        - Adds timestamp to filename
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [Object]$Data,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'XML')]
        [string]$Format = 'JSON'
    )

    try {
        Write-Verbose "Saving backup to: $FilePath (Format: $Format)"

        # Ensure directory exists
        $directory = [System.IO.Path]::GetDirectoryName($FilePath)
        if (-not (Test-Path -Path $directory)) {
            Write-Verbose "Creating backup directory: $directory"
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        # Add timestamp to filename if not present
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        $extension = [System.IO.Path]::GetExtension($FilePath)

        if ($fileName -notmatch '_\d{8}_\d{6}$') {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $fileName = "{0}_{1}" -f $fileName, $timestamp
        }

        # Reconstruct path
        $finalPath = Join-Path -Path $directory -ChildPath ("{0}{1}" -f $fileName, $extension)

        # Save data
        switch ($Format) {
            'JSON' {
                Write-Verbose "Exporting as JSON..."
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $finalPath -Encoding UTF8 -ErrorAction Stop
            }
            'XML' {
                Write-Verbose "Exporting as XML..."
                $Data | Export-Clixml -Path $finalPath -Depth 10 -ErrorAction Stop
            }
        }

        Write-CoreLog "Backup saved successfully: $finalPath" -Level SUCCESS -Module 'Utils'
        Write-Verbose "Backup saved: $finalPath"

        return $finalPath

    } catch {
        Write-CoreLog "Failed to save backup: $($_.Exception.Message)" -Level ERROR -Module 'Utils'
        Write-Error "Failed to save backup to $FilePath : $($_.Exception.Message)"
        return $null
    }
}

function Get-RegistryItemPrivilege {
    <#
    .SYNOPSIS
        Určí požadované oprávnění pro registry path na základě @STUDY dokumentace.

    .DESCRIPTION
        Mapuje registry paths na požadované privilege levels podle vzorů z:
        - 02-Registry-Security-Deep-Dive.md
        - 12-TrustedInstaller-Context.md
        - 16-Service-ACLs-SDDL.md

        **PRIVILEGE HIERARCHY:**
        User (Standard) < Administrator < SYSTEM < TrustedInstaller

        **PATH PATTERNS:**
        - HKLM:\SYSTEM\...\Services\ → SYSTEM
        - HKLM:\SOFTWARE\Classes\CLSID\ → TrustedInstaller
        - HKCU:\* → Admin
        - HKLM:\SOFTWARE\Policies\ → Admin

    .PARAMETER Path
        Registry cesta (např. 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv')

    .OUTPUTS
        [string] 'Admin', 'SYSTEM', nebo 'TrustedInstaller'

    .EXAMPLE
        Get-RegistryItemPrivilege -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv'
        # Returns: 'SYSTEM'

        Get-RegistryItemPrivilege -Path 'HKCU:\Control Panel\Desktop\MenuShowDelay'
        # Returns: 'Admin'

    .NOTES
        Reference: @STUDY\EXTRACTED-REGISTRY-ITEMS\PRIVILEGE-MAP-FROM-STUDY.md

        Conservative approach: Pokud je path neznámý, předpokládá Admin (fail-safe).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    # Normalize path (case-insensitive)
    $normalizedPath = $Path.ToUpperInvariant()

    # ═══════════════════════════════════════════════════════════════════════
    # SYSTEM REQUIRED PATTERNS (Priority 1)
    # ═══════════════════════════════════════════════════════════════════════

    # Services registry (SYSTEM owner, SYSTEM write required)
    if ($normalizedPath -match 'HKLM:\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\') {
        return 'SYSTEM'
    }
    if ($normalizedPath -match 'HKLM:\\SYSTEM\\CONTROLSET\d+\\SERVICES\\') {
        return 'SYSTEM'
    }

    # System Control paths (SYSTEM only)
    if ($normalizedPath -match 'HKLM:\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SESSION MANAGER') {
        return 'SYSTEM'
    }
    if ($normalizedPath -match 'HKLM:\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\PRIORITYCONTROL') {
        return 'SYSTEM'
    }

    # Multimedia SystemProfile (MMCSS - SYSTEM context)
    if ($normalizedPath -match 'WINDOWS NT\\CURRENTVERSION\\MULTIMEDIA\\SYSTEMPROFILE') {
        return 'Admin'
    }

    # ═══════════════════════════════════════════════════════════════════════
    # TRUSTEDINSTALLER REQUIRED PATTERNS (Priority 2)
    # ═══════════════════════════════════════════════════════════════════════

    # COM Classes (TrustedInstaller owned)
    if ($normalizedPath -match 'HKLM:\\SOFTWARE\\CLASSES\\CLSID\\') {
        return 'TrustedInstaller'
    }
    if ($normalizedPath -match 'HKCU:\\SOFTWARE\\CLASSES\\CLSID\\') {
        # Exception: Most HKCU is Admin, but some CLSIDs are TI protected
        # Conservative: Mark as TI
        return 'TrustedInstaller'
    }

    # Windows Defender (security critical, TI protected)
    if ($normalizedPath -match 'WINDOWS DEFENDER') {
        return 'TrustedInstaller'
    }

    # Windows Feeds (News & Interests) key requires SYSTEM privileges even under HKCU
    if ($normalizedPath -match 'HKCU:\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\FEEDS') {
        return 'SYSTEM'
    }

    # Startup Run keys (malware target, TI protected) - only HKLM
    if ($normalizedPath -match 'HKLM:\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN' -and
        -not ($normalizedPath -match 'HKCU:')) {
        return 'TrustedInstaller'
    }

    # ═══════════════════════════════════════════════════════════════════════
    # ADMIN SUFFICIENT (Default)
    # ═══════════════════════════════════════════════════════════════════════

    # All HKCU paths (user registry, admin can modify)
    if ($normalizedPath -match '^HKCU:') {
        return 'Admin'
    }

    # Group Policy paths (admin writable)
    if ($normalizedPath -match 'HKLM:\\SOFTWARE\\POLICIES\\') {
        return 'Admin'
    }

    # Standard software paths (already caught SYSTEM/TI exceptions above)
    if ($normalizedPath -match 'HKLM:\\SOFTWARE\\MICROSOFT\\') {
        return 'Admin'
    }

    # Default: Admin (conservative approach - if unknown, assume Admin sufficient)
    Write-Verbose "Unknown registry path pattern, defaulting to Admin: $Path"
    return 'Admin'
}

function Get-AllTweakableItems {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    throw "Get-AllTweakableItems has been relocated to Recovery.psm1. Import the Recovery module and call its implementation."
}

# ═══════════════════════════════════════════════════════════════════════════
# BACKUP/RESTORE WRAPPERS (Deprecated - use Core.psm1 auto-backup)
# ═══════════════════════════════════════════════════════════════════════════
# NOTE: These functions are provided for backward compatibility with v1.
#       Core.psm1 already provides auto-backup via:
#       - Invoke-RegistryOperation (auto-backup before modify)
#       - Invoke-ServiceOperation (auto-backup before modify)
#       New code should use those instead.
# ═══════════════════════════════════════════════════════════════════════════

function Backup-RegistryValue {
    <#
    .SYNOPSIS
        [DEPRECATED] Manuální záloha registry hodnoty.

    .DESCRIPTION
        Vytvoří zálohu jedné registry hodnoty do XML souboru.

        ⚠️ DEPRECATED: Použijte Invoke-RegistryOperation z Core.psm1 (auto-backup).

    .PARAMETER Path
        Registry cesta (např. 'HKLM:\SYSTEM\CurrentControlSet\...')

    .PARAMETER Name
        Název hodnoty

    .PARAMETER BackupPath
        Cesta kam uložit zálohu (optional, auto-generuje)

    .OUTPUTS
        [string] - Cesta k záložnímu souboru nebo $null při chybě.

    .EXAMPLE
        $backupFile = Backup-RegistryValue -Path 'HKLM:\SYSTEM\Test' -Name 'MyValue'

    .NOTES
        DEPRECATED - Use Invoke-RegistryOperation instead!
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$BackupPath = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$BackupData = $null
    )

    Write-Warning "Backup-RegistryValue is DEPRECATED. Use Invoke-RegistryOperation from Core.psm1 instead."

    # Support both BackupPath (legacy) and BackupData (new Recovery.psm1 usage)
    if ($null -ne $BackupData) {
        # New usage: Store in BackupData hashtable (used by Recovery.psm1)
        try {
            if (-not (Test-Path -Path $Path)) {
                Write-Verbose "Registry path not found, skipping: $Path"
                return $null
            }

            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($value) {
                $key = "$Path\$Name"
                $BackupData.Registries[$key] = @{
                    Path = $Path
                    Name = $Name
                    Value = $value.$Name
                    Timestamp = Get-Date
                }
                Write-Verbose "Registry value backed up to BackupData: $key"
            }
            return $null  # No file created
        } catch {
            Write-Verbose "Failed to backup registry: $($_.Exception.Message)"
            return $null
        }
    }

    # Legacy usage: Save to file
    try {
        if (-not (Test-Path -Path $Path)) {
            Write-Error "Registry path not found: $Path"
            return $null
        }

        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop

        if (-not $BackupPath) {
            $backupDir = Join-Path -Path ([Environment]::GetFolderPath('Desktop')) -ChildPath 'zalohaNASTROJ'
            if (-not (Test-Path -Path $backupDir)) {
                New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            }
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $safeName = $Name -replace '[^\w]', '_'
            $BackupPath = Join-Path -Path $backupDir -ChildPath "Registry_${safeName}_${timestamp}.xml"
        }

        $backupDataLegacy = @{
            Path      = $Path
            Name      = $Name
            Value     = $value.$Name
            Type      = $value.PSObject.Properties[$Name].TypeNameOfValue
            Timestamp = Get-Date
        }

        $backupDataLegacy | Export-Clixml -Path $BackupPath -Force
        Write-CoreLog "Registry value backed up: $Path\$Name -> $BackupPath" -Level INFO -Module 'Utils'

        return $BackupPath

    } catch {
        Write-CoreLog "Registry backup failed: $($_.Exception.Message)" -Level ERROR -Module 'Utils'
        Write-Error "Failed to backup registry value: $($_.Exception.Message)"
        return $null
    }
}

function Backup-ServiceState {
    <#
    .SYNOPSIS
        [DEPRECATED] Manuální záloha stavu služby.

    .DESCRIPTION
        Vytvoří zálohu stavu služby (StartupType, Status) do XML souboru.

        ⚠️ DEPRECATED: Použijte Invoke-ServiceOperation z Core.psm1 (auto-backup).

    .PARAMETER Name
        Název služby

    .PARAMETER BackupPath
        Cesta kam uložit zálohu (optional, auto-generuje)

    .PARAMETER BackupData
        Hashtable pro ukládání do paměti (nový režim pro Recovery.psm1)

    .OUTPUTS
        [string] - Cesta k záložnímu souboru nebo $null při chybě.

    .EXAMPLE
        $backupFile = Backup-ServiceState -Name 'wuauserv'

    .NOTES
        DEPRECATED - Use Invoke-ServiceOperation instead!
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$BackupPath = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$BackupData = $null
    )

    Write-Warning "Backup-ServiceState is DEPRECATED. Use Invoke-ServiceOperation from Core.psm1 instead."

    # Support both BackupPath (legacy) and BackupData (new Recovery.psm1 usage)
    if ($null -ne $BackupData) {
        # New usage: Store in BackupData hashtable
        try {
            $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
            if ($service) {
                $serviceInfo = @{
                    Name = $Name
                    DisplayName = $service.DisplayName
                    StartupType = $service.StartType
                    Status = $service.Status
                    Timestamp = Get-Date
                }
                $BackupData.Services += $serviceInfo
                Write-Verbose "Service backed up to BackupData: $Name"
            }
            return $null  # No file created
        } catch {
            Write-Verbose "Failed to backup service: $($_.Exception.Message)"
            return $null
        }
    }

    # Legacy usage: Save to file
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop

        if (-not $BackupPath) {
            $backupDir = Join-Path -Path ([Environment]::GetFolderPath('Desktop')) -ChildPath 'zalohaNASTROJ'
            if (-not (Test-Path -Path $backupDir)) {
                New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            }
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $BackupPath = Join-Path -Path $backupDir -ChildPath "Service_${Name}_${timestamp}.xml"
        }

        $backupDataLegacy = @{
            ServiceName = $Name
            DisplayName = $service.DisplayName
            StartupType = $service.StartType
            Status      = $service.Status
            Timestamp   = Get-Date
        }

        $backupDataLegacy | Export-Clixml -Path $BackupPath -Force
        Write-CoreLog "Service state backed up: $Name -> $BackupPath" -Level INFO -Module 'Utils'

        return $BackupPath

    } catch {
        Write-CoreLog "Service backup failed: $($_.Exception.Message)" -Level ERROR -Module 'Utils'
        Write-Error "Failed to backup service state: $($_.Exception.Message)"
        return $null
    }
}

function Restore-RegistryValue {
    <#
    .SYNOPSIS
        [DEPRECATED] Obnoví registry hodnotu ze zálohy.

    .DESCRIPTION
        Načte záložní XML soubor a obnoví registry hodnotu.

        ⚠️ DEPRECATED: Core.psm1 auto-rollback is preferred.

    .PARAMETER BackupPath
        Cesta k záložnímu XML souboru

    .OUTPUTS
        [bool] - $true při úspěchu, $false při chybě.

    .EXAMPLE
        Restore-RegistryValue -BackupPath 'C:\Backup\Registry_MyValue_20251029.xml'

    .NOTES
        DEPRECATED - Core.psm1 auto-rollback is preferred!
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$BackupPath
    )

    Write-Warning "Restore-RegistryValue is DEPRECATED. Core.psm1 auto-rollback is preferred."

    try {
        $backupData = Import-Clixml -Path $BackupPath -ErrorAction Stop

        if (-not $backupData.Path -or -not $backupData.Name) {
            throw "Invalid backup file format"
        }

        # Ensure registry path exists
        if (-not (Test-Path -Path $backupData.Path)) {
            New-Item -Path $backupData.Path -Force | Out-Null
        }

        # Restore value
        Set-ItemProperty -Path $backupData.Path -Name $backupData.Name -Value $backupData.Value -Force -ErrorAction Stop

        Write-CoreLog "Registry value restored: $($backupData.Path)\$($backupData.Name)" -Level SUCCESS -Module 'Utils'
        Write-Host "Registry value restored from: $BackupPath" -ForegroundColor Green

        return $true

    } catch {
        Write-CoreLog "Registry restore failed: $($_.Exception.Message)" -Level ERROR -Module 'Utils'
        Write-Error "Failed to restore registry value: $($_.Exception.Message)"
        return $false
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# WAIT UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

function Wait-ScriptContinue {
    <#
    .SYNOPSIS
        Počká na stisk klávesy před pokračováním.

    .DESCRIPTION
        Zobrazí zprávu a počká na stisk libovolné klávesy.
        Používá se po operacích, které vyžadují potvrzení.

    .PARAMETER Message
        Vlastní zpráva k zobrazení (výchozí: "Stiskněte libovolnou klávesu...").

    .EXAMPLE
        Wait-ScriptContinue

        # OUTPUT:
        # Stiskněte libovolnou klávesu pro pokračování...

    .EXAMPLE
        Wait-ScriptContinue -Message "Operace dokončena. Pokračujte..."
    #>
    [CmdletBinding()]
    param (
        [string]$Message = "Stiskněte libovolnou klávesu pro pokračování..."
    )

    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Verbose "User pressed key, continuing..."
}

# ═══════════════════════════════════════════════════════════════════════════
# MODULE EXPORT
# ═══════════════════════════════════════════════════════════════════════════

function Invoke-ModuleEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $ModuleContext
    )

    if ($null -eq $ModuleContext) {
        throw [System.ArgumentNullException]::new('ModuleContext')
    }

    return [pscustomobject]@{
        ModuleName        = 'Utils'
        ExportedFunctions = @(
            'Get-BackupData',
            'Save-BackupData',
            'Get-RegistryItemPrivilege',
            'Backup-RegistryValue',
            'Backup-ServiceState',
            'Restore-RegistryValue',
            'Wait-ScriptContinue'
        )
    }
}

Export-ModuleMember -Function @(
    # Backup Data Management
    'Get-BackupData',
    'Save-BackupData',

    # Privilege Detection (NEW!)
    'Get-RegistryItemPrivilege',

    # Backup/Restore Wrappers (Deprecated)
    'Backup-RegistryValue',
    'Backup-ServiceState',
    'Restore-RegistryValue',

    # Wait Utilities
    'Wait-ScriptContinue',

    # Module Entry
    'Invoke-ModuleEntry'
)

