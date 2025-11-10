# ═══════════════════════════════════════════════════════════════════════════
# Module: TweakR.psm1 - RESET SLUŽEB DO VÝCHOZÍHO STAVU
# ═══════════════════════════════════════════════════════════════════════════
# REŽIM R: RESET SERVICES
# - Resetuje všechny služby do výchozího (Automatic/Running) stavu
# - Pro případ špatného nastavení, když backupy nefungují
# - Používá Invoke-AsSystem pro NT\SYSTEM oprávnění (TrustedInstaller access)
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
    } else {
        Write-Error "CRITICAL: Core.psm1 not found at: $CoreModule"
        throw "Missing dependency: Core.psm1"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# MODULE VARIABLES
# ═══════════════════════════════════════════════════════════════════════════

$script:ModuleVersion = '2.0.0'
$script:ModuleName = 'TweakR'

# ═══════════════════════════════════════════════════════════════════════════
# SERVICE RESET LIST
# ═══════════════════════════════════════════════════════════════════════════

function Get-TweakRServiceList {
    <#
    .SYNOPSIS
        Returns list of services to reset to default state.

    .DESCRIPTION
        Returns collection of PSCustomObject with service configuration.
        Each service will be reset to 'Automatic' startup type and 'Running' status
        (unless explicitly set otherwise in the list).
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    #
    # ZDE UPRAVTE NEBO PŘIDEJTE SLUŽBY, KTERÉ CHCETE OBNOVIT
    #
    # Name:            Přesný název služby (Service Name) nebo pattern s *
    # Status:          Cílový stav ('Running', 'Stopped')
    # StartType:       Cílový typ spouštění ('Automatic', 'Manual', 'Disabled')
    #
    $ServiceList = @(
        [pscustomobject]@{Name = "AarSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "ALG"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "AppIDSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Appinfo"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "AppReadiness"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "AppXSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "VacSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "AudioEndpointBuilder"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Audiosrv"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "autotimesvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "AxInstSV"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Agent"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "BcastDVRUserService_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "BDESVC"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "BFE"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "BITS"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "BluetoothUserService_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "BrokerInfrastructure"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "BTAGService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "BthAvctpSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "bthserv"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Camsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "CaptureService_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "cbdhsvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "CDPSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "CDPUserSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "CertPropSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "ClipSVC"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "CloudBackupRestoreSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "COMSysApp"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "ConsentUxUserSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "CoreMessagingRegistrar"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "IntelCpHeciSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "IntelContentProtectionHdcpService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "CredentialEnrollmentManagerUserSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "CryptSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DcomLaunch"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DcSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "defragsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DeviceAssociationBrokerSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DeviceAssociationService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DeviceInstall"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DevicePickerUserSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DevicesFlowUserSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DevQueryBroker"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Dhcp"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DiagSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DiagTrack"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DispBrokerDesktopSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DisplayEnhancementService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DmEnrollmentSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "dmwappushservice"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Dnscache"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DoSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "dot3svc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DPS"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DsmSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DsSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DusmSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "EAAntiCheatService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "EABackgroundService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Eaphost"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "EasyAntiCheat"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "edgeupdate"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "edgeupdatem"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "EFS"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "embeddedmode"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "EntAppSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "EpicGamesLauncher"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "EpicOnlineServices"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "DPTF"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "ELANService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "EventLog"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "EventSystem"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Fax"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "fdPHost"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "FDResPub"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "fhsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "FontCache"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "FontCache3.0.0.0"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "FrameServer"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "FrameServerMonitor"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "GameInputSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "GoogleChromeElevationService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "gupdate"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "gupdatem"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "gpsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "GraphicsPerfSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "iaStorHfcEvo"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "hidserv"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "HotpatchService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "HPOMENHSAService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "HPSysInfoHSAService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "HvHost"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "IAStorDataMgrSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "icssvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "igccservice"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "igfxCUIService2.0.0.0"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "IKEEXT"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "InstallService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "TpmProvisioningService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "IntcAudioSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PcaSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "iphlpsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "IpxlatCfgSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "jhi_service"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "KeyIso"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "KtmRm"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "LanmanServer"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "LanmanWorkstation"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "lfsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "LicenseManager"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "lltdsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "lmhosts"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "kdc"; Status = "Stopped"; StartType = "Automatic"},
        [pscustomobject]@{Name = "LSM"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "LxpSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "MapsBroker"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "McpManagementService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "MDCoreSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "MessagingService_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "MicrosoftEdgeElevationService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "MpsSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "MSDTC"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "MSiSCSI"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "msiserver"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NgcSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NcaSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NcbService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NcdAutoSetup"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Netlogon"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Netman"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "netprofm"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NetSetupSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NetTcpPortSharing"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NgcCtnrSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NlaSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NPSMSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "nsi"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NVDisplay.ContainerLS"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "OneSyncSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "P9RdrService_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PenService_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PerceptionSimulation"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PerfHost"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PhoneSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PimIndexMaintenanceSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "pla"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PlugPlay"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PolicyAgent"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Power"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PrintNotify"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PrintQueue"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PrintScanBrokerService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PrintWorkflowUserSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "ProfSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "PushToInstall"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "QWAVE"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RasAuto"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RasMan"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "ReFSv1"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RemoteAccess"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RemoteRegistry"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RetailDemo"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RmSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RpcEptMapper"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RpcLocator"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RpcSs"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RstMwService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "RtkAudioUniversalService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SamSs"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SCardSvr"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "ScDeviceEnum"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SCPolicySvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SDRSVC"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "seclogon"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "secomn_ssl"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SecurityHealthService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SEMgrSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SENS"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SensorDataService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SensorService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SensrSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SessionEnv"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SharedAccess"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "ShellHWDetection"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "shpamsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Schedule"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "smphost"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SmsRouter"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SNMPTRAP"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "spacedeskService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Spooler"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "sppsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SSDPSRV"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SstpSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "StateRepository"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Steam Client Service"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "stisvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "StorSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "svsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "swprv"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SysMain"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "SystemEventsBroker"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "TapiSrv"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "TermService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "TabletInputService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Themes"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "TieringEngineService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "TimeBrokerSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "TokenBroker"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "TrkWks"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "TroubleshootingSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "TrustedInstaller"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "tzautoupdate"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "UdkUserSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "UmRdpService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "UnistoreSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "upnphost"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "UserDataSvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "UserManager"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "UsoSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "VaultSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "vds"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "vmicguestinterface"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "vmickvpexchange"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "vmicrdv"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "vmicshutdown"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "vmictimesync"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "vmicvmsession"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "vmicvss"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "vmicheartbeat"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "VSS"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "W32Time"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WaaSMedicSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WalletService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WarpJITSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "wbengine"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WbioSrvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Wcmsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "wcncsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WdiServiceHost"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WdiSystemHost"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "NisSrv"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WebClient"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "webthreatdefsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "webthreatdefusersvc_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Wecsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WEPHOSTSVC"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "wercplsupport"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WerSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WFDSConMgrSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WiaRpc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WinDefend"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WinHttpAutoProxySvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "Winmgmt"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WinRM"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "wisvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WlanSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "wlidsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "wlpasvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WManSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "wmiApSrv"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WpcMonSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WPDBusEnum"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WpnService"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WpnUserService_*"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WSAIFabricSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "wscsvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WSearch"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "wuauserv"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "WwanSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "XblAuthManager"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "XblGameSave"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "XboxGipSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "XboxNetApiSvc"; Status = "Running"; StartType = "Automatic"},
        [pscustomobject]@{Name = "ZTHELPER"; Status = "Running"; StartType = "Automatic"}
    )

    return $ServiceList
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN TWEAK FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

function Invoke-TweakR {
    <#
    .SYNOPSIS
        Resets Windows services to default state.

    .DESCRIPTION
        Resets specified Windows services to their target state and startup type.
        Uses Invoke-WithPrivilege for SYSTEM escalation to handle protected services.

    .NOTES
        Requires Administrator privileges.
        Uses Core.psm1 functions for privilege escalation.
    #>
    [CmdletBinding()]
    param()

    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  TWEAK R - RESET SLUŽEB DO VÝCHOZÍHO STAVU" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Cíl: Obnovit všechny služby do výchozího (Automatic/Running) stavu." -ForegroundColor Yellow
    Write-Host "Upozornění: Toto může změnit mnoho služeb současně." -ForegroundColor Yellow
    Write-Host ""

    $confirmation = Read-Host "Opravdu chcete pokračovat? [Y/N]"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Host "Operace zrušena uživatelem." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "FÁZE 1: NAČÍTÁM SEZNAM SLUŽEB..." -ForegroundColor Yellow
    Write-Host ""

    $serviceList = Get-TweakRServiceList

    if (-not $serviceList -or $serviceList.Count -eq 0) {
        Write-Warning "Seznam služeb (Get-TweakRServiceList) je prázdný. Není co dělat."
        return
    }

    Write-Host "  ✅ Nalezeno $($serviceList.Count) služeb ke konfiguraci" -ForegroundColor Green
    Write-Host ""

    # ───────────────────────────────────────────────────────────────────────
    # FÁZE 2: RESOLVE SERVICE PATTERNS
    # ───────────────────────────────────────────────────────────────────────
    Write-Host "FÁZE 2: ŘEŠÍM PATTERNY SLUŽEB..." -ForegroundColor Yellow
    Write-Host ""

    $allServiceOperations = @()
    $handledCount = 0

    foreach ($serviceItem in $serviceList) {
        $namePattern = $serviceItem.Name
        $targetStartType = $serviceItem.StartType
        $targetStatus = $serviceItem.Status

        $resolvedNames = @()
        if (Get-Command Resolve-ServiceNamePattern -ErrorAction SilentlyContinue) {
            $resolvedNames = Resolve-ServiceNamePattern -NamePattern $namePattern
        }
        else {
            # Fallback: přímé vyhledání
            if ($namePattern -like '*_*') {
                # Pattern s wildcard - hledáme všechny služby odpovídající patternu
                $resolvedNames = @(Get-Service | Where-Object { $_.Name -like $namePattern } | Select-Object -ExpandProperty Name)
            }
            else {
                # Přesný název
                $resolvedNames = @(Get-Service -Name $namePattern -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
            }
        }

        $resolvedNames = @($resolvedNames)

        if (-not $resolvedNames -or $resolvedNames.Count -eq 0) {
            Write-Verbose "  ⚠️  Služba '$namePattern' nebyla nalezena." -Verbose
            continue
        }

        foreach ($resolvedName in ($resolvedNames | Select-Object -Unique)) {
            $allServiceOperations += [pscustomobject]@{
                ServiceName = $resolvedName
                TargetStatus = $targetStatus
                TargetStartType = $targetStartType
            }
            $handledCount++
        }
    }

    Write-Host "  ✅ Vyřešeno: $handledCount instancí služeb" -ForegroundColor Green
    Write-Host ""

    # ───────────────────────────────────────────────────────────────────────
    # FÁZE 3: APLIKUJI KONFIGURACI SLUŽEB (S NT\SYSTEM OPRÁVNĚNÍMI!)
    # ───────────────────────────────────────────────────────────────────────
    Write-Host "FÁZE 3: APLIKUJI KONFIGURACI SLUŽEB..." -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  🔐 Spouštím s SYSTEM oprávněními (NT\SYSTEM / TrustedInstaller)..." -ForegroundColor Cyan

    # ScriptBlock pro SYSTEM kontext (stejný pattern jako scheduled tasks v TweakC)
    $restoreServicesBlock = {
        param($ServiceOperations)
        
        # ═══════════════════════════════════════════════════════════════
        # KROK 1: ZÍSKAT TRUSTEDINSTALLER OPRÁVNĚNÍ!
        # ═══════════════════════════════════════════════════════════════
        
        # Spustit TrustedInstaller službu (pokud není spuštěná)
        try {
            $tiService = Get-Service -Name 'TrustedInstaller' -ErrorAction Stop
            if ($tiService.Status -ne 'Running') {
                Start-Service -Name 'TrustedInstaller' -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                Write-Verbose "TrustedInstaller service started for restoration"
            }
        } catch {
            Write-Warning "Could not start TrustedInstaller service: $($_.Exception.Message)"
        }
        
        # Nastavit Security Descriptor pro TrustedInstaller
        $null = & sc.exe sdset TrustedInstaller "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)" 2>&1
        
        # 🚫 BLACKLIST služeb s problematickými závislostmi (způsobují infinite wait)
        $serviceBlacklist = @(
            'UsoSvc',     # Update Orchestrator Service - čeká na Windows Update závislosti
            'WManSvc',    # Windows Management Service - broken dependency chain
            'DiagTrack',  # Connected User Experiences and Telemetry - může způsobit problémy
            'SysMain'     # Superfetch - může způsobit timeout na některých systémech
        )
        
        $handledCount = 0
        $startedCount = 0
        $stoppedCount = 0
        $skippedCount = 0
        
        foreach ($op in $ServiceOperations) {
            # Přeskočit služby v blacklistu
            if ($op.ServiceName -in $serviceBlacklist) {
                $skippedCount++
                continue
            }
            try {
                # ZASTAVENÍ SLUŽBY (pokud je třeba)
                if ($op.TargetStatus -eq 'Stopped') {
                    try {
                        $svc = Get-Service -Name $op.ServiceName -ErrorAction Stop
                        if ($svc.Status -ne 'Stopped') {
                            try {
                                Stop-Service -Name $op.ServiceName -Force -ErrorAction Stop
                                $stoppedCount++
                            } catch {
                                # Fallback na sc.exe stop
                                $null = & sc.exe stop $op.ServiceName 2>&1
                                if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1062) {
                                    $stoppedCount++
                                }
                            }
                        }
                    } catch {
                        # Ignorovat chyby zastavení
                    }
                }

                # NASTAVENÍ STARTTYPE PŘÍMO V REGISTRY (S SYSTEM OPRÁVNĚNÍMI!)
                if (-not [string]::IsNullOrWhiteSpace($op.TargetStartType)) {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($op.ServiceName)"
                    
                    if (Test-Path $regPath -ErrorAction SilentlyContinue) {
                        # ═══════════════════════════════════════════════════════════
                        # KRITICKÉ: Převzít TrustedInstaller oprávnění před obnovou!
                        # ═══════════════════════════════════════════════════════════
                        
                        # Nastavit Security Descriptor pro plný přístup SYSTEM (BYPASS TrustedInstaller!)
                        $null = & sc.exe sdset $op.ServiceName "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)" 2>&1
                        
                        # Registry hodnoty pro StartType
                        $startValue = switch ($op.TargetStartType) {
                            'Disabled'    { 4 }
                            'Manual'      { 3 }
                            'Automatic'   { 2 }
                            'DelayedAuto' { 2 }
                            default       { 3 }
                        }
                        
                        try {
                            # METODA 1: Set-ItemProperty (rychlé)
                            Set-ItemProperty -Path $regPath -Name "Start" -Value $startValue -Type DWord -Force -ErrorAction Stop
                            $handledCount++
                        } catch {
                            # METODA 2: sc.exe config jako fallback (BYPASS registry)
                            try {
                                $startMode = switch ($op.TargetStartType) {
                                    'Disabled'    { 'disabled' }
                                    'Manual'      { 'demand' }
                                    'Automatic'   { 'auto' }
                                    'DelayedAuto' { 'delayed-auto' }
                                    default       { 'demand' }
                                }
                                
                                $null = & sc.exe config $op.ServiceName start= $startMode 2>&1
                                if ($LASTEXITCODE -eq 0) {
                                    $handledCount++
                                }
                            } catch {
                                # Tiché ignorování - už jsme zkusili vše
                            }
                        }
                    }
                }

                # SPUŠTĚNÍ SLUŽBY (pokud má běžet)
                if ($op.TargetStatus -eq 'Running' -and $op.TargetStartType -ne 'Disabled') {
                    try {
                        $svc = Get-Service -Name $op.ServiceName -ErrorAction Stop
                        if ($svc.Status -ne 'Running' -and $svc.StartType -ne 'Disabled') {
                            try {
                                Start-Service -Name $op.ServiceName -ErrorAction Stop
                                $startedCount++
                            } catch {
                                # Fallback na sc.exe start
                                $null = & sc.exe start $op.ServiceName 2>&1
                                if ($LASTEXITCODE -eq 0) {
                                    $startedCount++
                                }
                            }
                        }
                    } catch {
                        # Ignorovat chyby spuštění
                    }
                }

            }
            catch {
                # Tiché pokračování
            }
        }
        
        return @{
            Handled = $handledCount
            Started = $startedCount
            Stopped = $stoppedCount
            Skipped = $skippedCount
        }
    }

    # Spustit jako SYSTEM (stejně jako TweakC pro scheduled tasks)
    try {
        $result = Invoke-AsSystem -ScriptBlock $restoreServicesBlock -ArgumentList (,$allServiceOperations)
        
        if ($null -ne $result -and $result -is [hashtable]) {
            Write-Host "  ✅ Upraveno: $($result.Handled) služeb (SYSTEM režim)" -ForegroundColor Green
            Write-Host "  ▶️  Zapnuto: $($result.Started) služeb" -ForegroundColor Cyan
            if ($result.Stopped -gt 0) {
                Write-Host "  ⏹️  Zastaveno: $($result.Stopped) služeb" -ForegroundColor Yellow
            }
            if ($result.Skipped -gt 0) {
                Write-Host "  ⚠️  Přeskočeno (blacklist): $($result.Skipped) služeb" -ForegroundColor DarkGray
            }
            
            # Show warning if WU services were skipped
            if ($result.Skipped -gt 0 -and ($allServiceOperations | Where-Object { $_.ServiceName -in @('UsoSvc', 'WManSvc', 'DiagTrack', 'SysMain') })) {
                Write-Host ""
                Write-Host "  ℹ️  Windows Update služby přeskočeny - použij Main Menu → [13] pro obnovu" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  ⚠️  SYSTEM eskalace vrátila neplatný výsledek - zkouším jako Admin..." -ForegroundColor Yellow
            
            # Fallback - zkusit jako běžný Admin
            # 🚫 BLACKLIST služeb s problematickými závislostmi (způsobují infinite wait)
            $serviceBlacklist = @(
                'UsoSvc',     # Update Orchestrator Service - čeká na Windows Update závislosti
                'WManSvc',    # Windows Management Service - broken dependency chain
                'DiagTrack',  # Connected User Experiences and Telemetry - může způsobit problémy
                'SysMain'     # Superfetch - může způsobit timeout na některých systémech
            )
            
            $handledCount = 0
            $startedCount = 0
            $skippedCount = 0
            
            foreach ($op in $allServiceOperations) {
                # Přeskočit služby v blacklistu
                if ($op.ServiceName -in $serviceBlacklist) {
                    $skippedCount++
                    continue
                }
                
                try {
                    if ($op.TargetStatus -eq 'Stopped') {
                        try {
                            Stop-Service -Name $op.ServiceName -Force -ErrorAction SilentlyContinue
                        } catch { }
                    }

                    if (-not [string]::IsNullOrWhiteSpace($op.TargetStartType)) {
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($op.ServiceName)"
                        if (Test-Path $regPath -ErrorAction SilentlyContinue) {
                            $startValue = switch ($op.TargetStartType) {
                                'Disabled' { 4 }
                                'Manual' { 3 }
                                'Automatic' { 2 }
                                'DelayedAuto' { 2 }
                                default { 3 }
                            }
                            try {
                                Set-ItemProperty -Path $regPath -Name "Start" -Value $startValue -Type DWord -Force -ErrorAction SilentlyContinue
                                $handledCount++
                            } catch { }
                        }
                    }

                    if ($op.TargetStatus -eq 'Running' -and $op.TargetStartType -ne 'Disabled') {
                        try {
                            $svc = Get-Service -Name $op.ServiceName -ErrorAction SilentlyContinue
                            if ($svc -and $svc.Status -ne 'Running' -and $svc.StartType -ne 'Disabled') {
                                Start-Service -Name $op.ServiceName -ErrorAction SilentlyContinue
                                $startedCount++
                            }
                        } catch { }
                    }
                } catch { }
            }
            Write-Host "  ✅ Upraveno: $handledCount služeb (Admin režim)" -ForegroundColor Green
            Write-Host "  ▶️  Zapnuto: $startedCount služeb" -ForegroundColor Cyan
            if ($skippedCount -gt 0) {
                Write-Host "  ⚠️  Přeskočeno (blacklist): $skippedCount služeb" -ForegroundColor DarkGray
            }
        }
    }
    catch {
        Write-Host "  ❌ Chyba při obnově služeb: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  🔄 RESTART PC je NUTNÝ pro plný efekt!" -ForegroundColor Cyan
    Write-Host ""

    # ═══════════════════════════════════════════════════════════════════════════
    # UPOZORNĚNÍ: Blacklisted Windows Update služby
    # ═══════════════════════════════════════════════════════════════════════════
    if ($allServiceOperations | Where-Object { $_.ServiceName -in @('UsoSvc', 'WManSvc', 'DiagTrack', 'SysMain') }) {
        Write-Host ""
        Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "║  ⚠️  POZOR: Windows Update služby NEBYLY OBNOVENY!          ║" -ForegroundColor Yellow
        Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  📋 Tyto služby jsou v blacklistu (infinite wait protection):" -ForegroundColor Cyan
        Write-Host "     • UsoSvc (Update Orchestrator)" -ForegroundColor Gray
        Write-Host "     • WManSvc (Windows Management Service)" -ForegroundColor Gray
        Write-Host "     • DiagTrack (Telemetry)" -ForegroundColor Gray
        Write-Host "     • SysMain (Superfetch)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  🔧 Pro správnou obnovu Windows Update:" -ForegroundColor Cyan
        Write-Host "     Spusť Main Menu → [13] Windows Update Management" -ForegroundColor White
        Write-Host ""
        Write-Host "  📋 Dostupné options v menu [13]:" -ForegroundColor Cyan
        Write-Host "     [1] Security Settings (disable drivers, enable updates)" -ForegroundColor Gray
        Write-Host "     [2] Default Settings (full restore)" -ForegroundColor Gray
        Write-Host "     [3] Disable Updates (full disable)" -ForegroundColor Gray
        Write-Host "     [4] Granular Control (services only / drivers only)" -ForegroundColor Gray
        Write-Host "     [5] Repair & Reset (DLL reregister + GPO cleanup)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  ℹ️  Důvod blacklistu:" -ForegroundColor DarkCyan
        Write-Host "     Update služby potřebují SURGICAL GPO cleanup + DLL reregistration." -ForegroundColor DarkGray
        Write-Host "     TweakR provádí pouze SERVICE restore (ne full WU repair)." -ForegroundColor DarkGray
        Write-Host "     Start-Service na UsoSvc/WManSvc způsobuje infinite wait (broken dependencies)." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
        Write-Host ""
        Read-Host "Press Enter to continue"
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✅ RESET SLUŽEB DOKONČEN" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "Doporučení: Po dokončení restartujte počítač pro plnou aplikaci změn." -ForegroundColor Yellow
    Write-Host ""
    Start-Sleep -Seconds 3
}

# ═══════════════════════════════════════════════════════════════════════════
# MODULE ENTRY POINT
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

    Invoke-TweakR
}

# ═══════════════════════════════════════════════════════════════════════════
# MODULE EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

Export-ModuleMember -Function @(
    'Invoke-TweakR',
    'Get-TweakRServiceList',
    'Invoke-ModuleEntry'
)

