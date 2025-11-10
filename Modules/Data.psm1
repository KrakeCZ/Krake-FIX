# ═══════════════════════════════════════════════════════════════════════════
# Module: Data.psm1
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX v2 Modular
# Version:      2.0.0
# Author:       KRAKE-FIX Team
# Created:      2025-10-29
# Last Updated: 2025-10-29
# ═══════════════════════════════════════════════════════════════════════════
# Description:  Centralized data storage for all system tweaks, services,
#               registry keys, and other configuration data.
#               Per @STUDY/09-Module-Architecture-Design.md
# Category:     Data
# Dependencies: None (this is a pure data module)
# Admin Rights: Not required (read-only data)
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️  SECURITY & COMPLIANCE NOTICE
# ═══════════════════════════════════════════════════════════════════════════
# • This module contains static data only (no executable code)
# • All registry paths and values are documented
# • Designed for educational and testing purposes only
# • Author assumes no liability for misuse outside academic context
# • BSI4 compliant: All data is versioned and auditable
# ═══════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1

Set-StrictMode -Version Latest

# ───────────────────────────────────────────────────────────────────────────
# MODULE METADATA
# ───────────────────────────────────────────────────────────────────────────

$script:DataModuleVersion = '2.0.0'
$script:DataLastUpdated = '2025-10-29'

# ═══════════════════════════════════════════════════════════════════════════
# TWEAK CATEGORY DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════
#
# Structure per @STUDY/09:
# - Each category has: Name, Description, Registry tweaks, Service operations
# - Apply = tweak value, Revert = default value
# - RequiresSystem = bool (needs SYSTEM privilege)
# ═══════════════════════════════════════════════════════════════════════════

$script:TweakCategories = @{

    # ─────────────────────────────────────────────────────────────────────
    # GAMING PERFORMANCE TWEAKS
    # ─────────────────────────────────────────────────────────────────────
    GamingPerf = @{
        Name = 'Gaming Performance Optimization'
        Description = 'MMCSS, Network throttling, Memory optimization for gaming'
        RequiresRestart = $true

        Registry = @(
            # ─── Multimedia Class Scheduler Service (MMCSS) ───
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
                Name = 'SystemResponsiveness'
                Type = 'DWord'
                ApplyValue = 0          # Gaming: Max responsiveness
                RevertValue = 20        # Default: Balanced
                Description = 'System responsiveness for multimedia (0 = max gaming performance)'
                RequiresSystem = $false # SOFTWARE hive - Admin OK
            }
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
                Name = 'NetworkThrottlingIndex'
                Type = 'DWord'
                ApplyValue = 0xffffffff # Disable network throttling
                RevertValue = 10        # Default: 10 Mbps throttle
                Description = 'Network packet scheduling throttle (0xFFFFFFFF = disabled)'
                RequiresSystem = $false
            }
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
                Name = 'NoLazyMode'
                Type = 'DWord'
                ApplyValue = 1
                RevertValue = $null     # Remove on revert (not default present)
                Description = 'Disable lazy mode for MMCSS'
                RequiresSystem = $false
            }
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
                Name = 'AlwaysOn'
                Type = 'DWord'
                ApplyValue = 1
                RevertValue = $null     # Remove on revert
                Description = 'Always-on mode for MMCSS'
                RequiresSystem = $false
            }

            # ─── MMCSS Games Task Profile ───
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
                Name = 'Affinity'
                Type = 'DWord'
                ApplyValue = 0x00000000 # All cores
                RevertValue = $null
                Description = 'CPU affinity for games task'
                RequiresSystem = $false
            }
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
                Name = 'Background Only'
                Type = 'String'
                ApplyValue = 'False'
                RevertValue = $null
                Description = 'Allow foreground priority'
                RequiresSystem = $false
            }
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
                Name = 'Clock Rate'
                Type = 'DWord'
                ApplyValue = 0x00002710 # 10000 (10ms)
                RevertValue = $null
                Description = 'MMCSS clock rate for games'
                RequiresSystem = $false
            }
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
                Name = 'GPU Priority'
                Type = 'DWord'
                ApplyValue = 0x00000008 # High (8)
                RevertValue = $null
                Description = 'GPU scheduling priority (8 = high)'
                RequiresSystem = $false
            }
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
                Name = 'Priority'
                Type = 'DWord'
                ApplyValue = 0x00000006 # High (6)
                RevertValue = $null
                Description = 'Thread priority (6 = high)'
                RequiresSystem = $false
            }
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
                Name = 'Scheduling Category'
                Type = 'String'
                ApplyValue = 'High'
                RevertValue = $null
                Description = 'MMCSS scheduling category'
                RequiresSystem = $false
            }
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
                Name = 'SFIO Priority'
                Type = 'String'
                ApplyValue = 'High'
                RevertValue = $null
                Description = 'Storage I/O priority'
                RequiresSystem = $false
            }

            # ─── Memory Management (REQUIRES SYSTEM!) ───
            @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
                Name = 'IoPageLockLimit'
                Type = 'DWord'
                ApplyValue = 0x30000000 # 768 MB
                RevertValue = $null      # Remove on revert
                Description = 'I/O page lock limit (768MB for gaming)'
                RequiresSystem = $true   # HKLM:\SYSTEM requires SYSTEM privilege
            }
            @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
                Name = 'DisablePagingExecutive'
                Type = 'DWord'
                ApplyValue = 1
                RevertValue = 0
                Description = 'Keep kernel in physical RAM (not paged)'
                RequiresSystem = $true
            }

            # ─── System Responsiveness ───
            @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Control'
                Name = 'WaitToKillServiceTimeout'
                Type = 'String'
                ApplyValue = '150'     # 150ms (fast shutdown)
                RevertValue = '2000'   # 2000ms (default)
                Description = 'Service shutdown timeout'
                RequiresSystem = $true
            }
        )

        Services = @(
            # ─── Services to DISABLE for gaming ───
            @{
                Name = 'SysMain'
                Operation = 'Disable'
                ApplyStartType = 4      # Disabled
                RevertStartType = 2     # Automatic
                Description = 'Superfetch/Prefetch (can cause stuttering)'
                RequiresSystem = $true
            }
            @{
                Name = 'WSearch'
                Operation = 'Disable'
                ApplyStartType = 4      # Disabled
                RevertStartType = 2     # Automatic
                Description = 'Windows Search (background indexing)'
                RequiresSystem = $true
            }
        )
    }

    # ─────────────────────────────────────────────────────────────────────
    # TELEMETRY SERVICES MANAGEMENT
    # ─────────────────────────────────────────────────────────────────────
    TelemetryServices = @{
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
            @{
                Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                Name = 'AllowTelemetry'
                Type = 'DWord'
                ApplyValue = 0
                RevertValue = 1
                Description = 'Policies: Disable telemetry data collection'
                RequiresSystem = $false
            }
            @{
                Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                Name = 'MaxTelemetryAllowed'
                Type = 'DWord'
                ApplyValue = 0
                RevertValue = 3
                Description = 'Telemetry level cap (0 = Security)'
                RequiresSystem = $false
            }
            @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy'
                Name = 'TelemetryMaxApplication'
                Type = 'DWord'
                ApplyValue = 0
                RevertValue = 1
                Description = 'Limit telemetry application energy logging'
                RequiresSystem = $true
            }
            @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy'
                Name = 'TelemetryMaxTagPerApplication'
                Type = 'DWord'
                ApplyValue = 0
                RevertValue = 1
                Description = 'Limit telemetry tag logging per application'
                RequiresSystem = $true
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
                Name = 'diagsvc'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3     # Manual
                Description = 'Diagnostic Service Host'
                RequiresSystem = $true
            }
            @{
                Name = 'diagnosticshub.standardcollector.service'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3
                Description = 'Diagnostics Hub Standard Collector'
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
            @{
                Name = 'lfsvc'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3
                Description = 'Geolocation Service'
                RequiresSystem = $true
            }
            @{
                Name = 'MapsBroker'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3
                Description = 'Download maps manager'
                RequiresSystem = $true
            }
            @{
                Name = 'NaturalAuthentication'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3
                Description = 'Natural Authentication service (biometrics telemetry)'
                RequiresSystem = $true
            }
            @{
                Name = 'TroubleshootingSvc'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3
                Description = 'Recommended Troubleshooting service'
                RequiresSystem = $true
            }
            @{
                Name = 'tzautoupdate'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3
                Description = 'Auto Time Zone Update service'
                RequiresSystem = $true
            }
            @{
                Name = 'WdiServiceHost'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3
                Description = 'Diagnostic Service Host (WDI)'
                RequiresSystem = $true
            }
            @{
                Name = 'WdiSystemHost'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3
                Description = 'Diagnostic System Host (WDI)'
                RequiresSystem = $true
            }
            @{
                Name = 'wisvc'
                Operation = 'Disable'
                ApplyStartType = 4
                RevertStartType = 3
                Description = 'Windows Insider Service'
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

    # ─────────────────────────────────────────────────────────────────────
    # CPU MITIGATIONS (Spectre/Meltdown)
    # ─────────────────────────────────────────────────────────────────────
    MitigationsCPU = @{
        Name = 'CPU Security Mitigations'
        Description = 'Disable Spectre/Meltdown mitigations for performance (RISKY!)'
        RequiresRestart = $true

        Registry = @(
            @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
                Name = 'FeatureSettingsOverride'
                Type = 'DWord'
                ApplyValue = 3          # Disable mitigations
                RevertValue = $null     # Remove (use defaults)
                Description = 'Override CPU mitigation features'
                RequiresSystem = $true
            }
            @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
                Name = 'FeatureSettingsOverrideMask'
                Type = 'DWord'
                ApplyValue = 3
                RevertValue = $null
                Description = 'Mitigation override mask'
                RequiresSystem = $true
            }
        )

        Services = @()  # No service changes for this category
    }

    # ═══════════════════════════════════════════════════════════════════
    # TODO: Additional categories pending full migration
    # ═══════════════════════════════════════════════════════════════════
    # - WinUpdateServices: Windows Update service management
    # - WinUpdateDrivers: Driver update policies
    # - VBS: Virtualization-based security
    # - Integrity: HVCI/Memory integrity
    # - DefenderRT: Windows Defender real-time protection
    # - ... (per KRAKE-FIX-v1.ps1 Invoke-RevertToDefaults function)
}

# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS (Module-Private)
# ═══════════════════════════════════════════════════════════════════════════

function Get-CategoryData {
    <#
    .SYNOPSIS
        Retrieve tweak category data.

    .PARAMETER Category
        Category name.

    .OUTPUTS
        [hashtable] Category data or $null if not found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Category
    )

    if ($script:TweakCategories.ContainsKey($Category)) {
        return $script:TweakCategories[$Category]
    } else {
        Write-Warning "Category '$Category' not found in Data.psm1"
        return $null
    }
}

function Get-AllCategories {
    <#
    .SYNOPSIS
        List all available tweak categories.

    .OUTPUTS
        [array] Category names.
    #>
    [CmdletBinding()]
    param()

    return $script:TweakCategories.Keys
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

    return [pscustomobject]@{
        ModuleName = 'Data'
        Categories = Get-AllCategories
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# MODULE EXPORT
# ═══════════════════════════════════════════════════════════════════════════

Export-ModuleMember -Function @(
    'Get-CategoryData',
    'Get-AllCategories',
    'Invoke-ModuleEntry'
) -Variable @(
    'TweakCategories'
)


