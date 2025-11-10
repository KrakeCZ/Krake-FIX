# ===========================================================
# Modul: Network.psm1
# Popis: Síťové optimalizace (DNS, TCP/IP, Reset)
# Autor: KRAKE-FIX Team
# Projekt: KRAKE-FIX v2 Modular
# ===========================================================
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ===========================================================

# Import Core modulu pro privilege management
# Use Core module functions - loaded by Main.ps1, only import if standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $CoreModule = Join-Path $PSScriptRoot 'Core.psm1'
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    }
}

# ===========================================================
# MODULE-LEVEL VARIABLES
# ===========================================================

$script:ModuleName = 'Network'
$script:ModuleVersion = '2.0.0'
$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"

# Backup file pro network tweaky
$script:NetworkBackupFile = Join-Path ([Environment]::GetFolderPath('Desktop')) "KRAKE-Backup\Network_Backup.json"

# ===========================================================
# NETWORK FUNCTIONS (30 functions from clean v1.ps1)
# ===========================================================


function Invoke-WinsockReset {
    Write-Host ""
    Write-Host "  [1] Resetuji Winsock katalog..." -ForegroundColor Yellow
    try {
        $result = Start-Process -FilePath "netsh.exe" -ArgumentList "winsock reset" -Wait -NoNewWindow -PassThru -ErrorAction Stop
        if ($result.ExitCode -eq 0) {
            Write-Host "     [OK] Winsock katalog resetován." -ForegroundColor Green
        } else {
            Write-Warning "     [WARN] netsh winsock reset vrátil kód: $($result.ExitCode)"
        }
    } catch {
        Write-Error "     [ERROR] Chyba: $($_.Exception.Message)"
    }
}

function Invoke-IPReset {
    Write-Host ""
    Write-Host "  [2] Resetuji TCP/IP stack..." -ForegroundColor Yellow
    try {
        $result = Start-Process -FilePath "netsh.exe" -ArgumentList "int ip reset" -Wait -NoNewWindow -PassThru -ErrorAction Stop
        if ($result.ExitCode -eq 0) {
            Write-Host "     [OK] TCP/IP stack resetován." -ForegroundColor Green
        } else {
            Write-Warning "     [WARN] netsh int ip reset vrátil kód: $($result.ExitCode)"
        }
    } catch {
        Write-Error "     [ERROR] Chyba: $($_.Exception.Message)"
    }
}

function Invoke-TCPReset {
    Write-Host ""
    Write-Host "  [3] Resetuji TCP nastavení..." -ForegroundColor Yellow
    try {
        $result = Start-Process -FilePath "netsh.exe" -ArgumentList "int tcp reset" -Wait -NoNewWindow -PassThru -ErrorAction Stop
        if ($result.ExitCode -eq 0) {
            Write-Host "     [OK] TCP nastavení resetováno." -ForegroundColor Green
        } else {
            Write-Warning "     [WARN] netsh int tcp reset vrátil kód: $($result.ExitCode)"
        }
    } catch {
        Write-Error "     [ERROR] Chyba: $($_.Exception.Message)"
    }
}

function Invoke-DNSFlush {
    Write-Host ""
    Write-Host "  [4] Vyčišťuji DNS cache..." -ForegroundColor Yellow
    try {
        $result = Start-Process -FilePath "ipconfig.exe" -ArgumentList "/flushdns" -Wait -NoNewWindow -PassThru -ErrorAction Stop
        if ($result.ExitCode -eq 0) {
            Write-Host "     [OK] DNS cache vyčištěna." -ForegroundColor Green
        } else {
            Write-Warning "     [WARN] ipconfig /flushdns vrátil kód: $($result.ExitCode)"
        }
    } catch {
        Write-Error "     [ERROR] Chyba: $($_.Exception.Message)"
    }
}

function Invoke-IPRelease {
    Write-Host ""
    Write-Host "  [5] Uvolňuji IP adresy..." -ForegroundColor Yellow
    try {
        $job = Start-Job -ScriptBlock { ipconfig /release }
        $completed = Wait-Job -Job $job -Timeout 10

        if ($null -ne $completed) {
            $null = Receive-Job -Job $job
            Remove-Job -Job $job -Force
            Write-Host "     [OK] IP adresy uvolněny." -ForegroundColor Green
        } else {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            Write-Warning "     [WARN] Timeout (10s) - operace trvala příliš dlouho, pokračuji dál..."
        }
    } catch {
        Write-Warning "     [WARN] Chyba (může být normální u statických IP): $($_.Exception.Message)"
    }
}

function Invoke-IPRenew {
    Write-Host ""
    Write-Host "  [6] Obnovuji IP adresy..." -ForegroundColor Yellow
    Write-Host "      (Čekám max. 10 sekund na DHCP server...)" -ForegroundColor Gray
    try {
        $job = Start-Job -ScriptBlock { ipconfig /renew }
        $completed = Wait-Job -Job $job -Timeout 10

        if ($null -ne $completed) {
            $null = Receive-Job -Job $job
            Remove-Job -Job $job -Force
            Write-Host "     [OK] IP adresy obnoveny." -ForegroundColor Green
        } else {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            Write-Warning "     [WARN] Timeout (10s) - DHCP server neodpovídá, pokračuji dál..."
            Write-Host "     [TIP] Zkus restartovat PC nebo použít statickou IP." -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "     [WARN] Chyba (může být normální u statických IP): $($_.Exception.Message)"
    }
}

function Invoke-AdapterResetMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Magenta
        Write-Host "   [RESET] RESET SÍŤOVÝCH ADAPTÉRŮ" -ForegroundColor Magenta
        Write-Host "==================================================" -ForegroundColor Magenta
        Write-Host ""

        # Načtení adaptérů
        $adapterList = @()
        $adapterLetters = @('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h')
        $letterIndex = 0

        try {
            $allAdapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual|VPN|Loopback' })

            if ($allAdapters.Count -gt 0) {
                Write-Host "--- Dostupné adaptéry ---" -ForegroundColor Cyan
                foreach ($adapter in $allAdapters) {
                    $letter = $adapterLetters[$letterIndex]

                    # Typ adaptéru
                    $adapterType = ""
                    switch ($adapter.InterfaceType) {
                        6   { $adapterType = "[LAN]" }
                        71  { $adapterType = "[WiFi]" }
                        243 { $adapterType = "[USB]" }
                        244 { $adapterType = "[USB]" }
                        237 { $adapterType = "[BT]" }
                        default { $adapterType = "[?]" }
                    }

                    # Formátování GUID
                    $guidString = $adapter.InterfaceGuid.ToString()
                    if (-not $guidString.StartsWith("{")) {
                        $adapterGuid = "{" + $guidString + "}"
                    } else {
                        $adapterGuid = $guidString
                    }

                    $adapterList += [PSCustomObject]@{
                        Letter = $letter
                        Adapter = $adapter
                        GUID = $adapterGuid
                        Type = $adapterType
                        Name = $adapter.InterfaceDescription
                    }

                    Write-Host "  [$letter] $adapterType " -NoNewline -ForegroundColor Cyan
                    Write-Host "$($adapter.InterfaceDescription)" -ForegroundColor White
                    Write-Host "      GUID: $adapterGuid" -ForegroundColor Gray

                    $letterIndex++
                    if ($letterIndex -ge $adapterLetters.Count) { break }
                }
                Write-Host ""
            } else {
                Write-Warning "Žádné aktivní síťové adaptéry nebyly nalezeny."
                Write-Host ""
                Write-Host "Stiskněte klávesu pro návrat..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                return
            }
        } catch {
            Write-Warning "Chyba při načítání adaptérů: $($_.Exception.Message)"
            Write-Host ""
            Write-Host "Stiskněte klávesu pro návrat..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }

        Write-Host "--- Volby ---" -ForegroundColor Yellow
        Write-Host "[PÍSMENO] Resetovat konkrétní adaptér (např. 'a', 'b')" -ForegroundColor White
        Write-Host "[A]       Resetovat VŠECHNY adaptéry" -ForegroundColor Green
        Write-Host "[Q]       Zpět do menu Reset Sítě" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        if ($choice -eq 'Q' -or $choice -eq 'q') { return }

        if ($choice -eq 'A' -or $choice -eq 'a') {
            # Resetovat všechny adaptéry
            Write-Host ""
            Write-Host "  [7] Resetuji VŠECHNY síťové adaptéry..." -ForegroundColor Yellow
            foreach ($item in $adapterList) {
                Write-Host "      -> Resetuji: $($item.Name)..." -ForegroundColor Cyan
                try {
                    Disable-NetAdapter -Name $item.Adapter.Name -Confirm:$false -ErrorAction Stop
                    Start-Sleep -Milliseconds 500
                    Enable-NetAdapter -Name $item.Adapter.Name -Confirm:$false -ErrorAction Stop
                    Start-Sleep -Milliseconds 500
                    Write-Host "         [OK] Adaptér resetován." -ForegroundColor Green
                } catch {
                    Write-Warning "         [WARN] Chyba: $($_.Exception.Message)"
                }
            }
            Write-Host ""
            Write-Host "Stiskněte klávesu pro pokračování..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            continue
        }

        # Resetovat konkrétní adaptér podle písmena
        $selectedAdapter = $adapterList | Where-Object { $_.Letter -eq $choice.ToLower() }
        if ($null -ne $selectedAdapter) {
            Write-Host ""
            Write-Host "  [7] Resetuji adaptér: $($selectedAdapter.Name)..." -ForegroundColor Yellow
            try {
                Disable-NetAdapter -Name $selectedAdapter.Adapter.Name -Confirm:$false -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                Enable-NetAdapter -Name $selectedAdapter.Adapter.Name -Confirm:$false -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                Write-Host "     [OK] Adaptér resetován." -ForegroundColor Green
            } catch {
                Write-Warning "     [WARN] Chyba: $($_.Exception.Message)"
            }
            Write-Host ""
            Write-Host "Stiskněte klávesu pro pokračování..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            continue
        } else {
            Write-Warning "Neplatná volba: $choice"
            Start-Sleep -Seconds 2
            continue
        }
    }
}

# ===================================================================
# RESET SÍTĚ - HLAVNÍ MENU
# ===================================================================
function Reset-Network {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Magenta
        Write-Host "   [RESET] RESET SÍTĚ" -ForegroundColor Magenta
        Write-Host "==================================================" -ForegroundColor Magenta
        Write-Host ""

        # Zobrazení dostupných adaptérů
        $adapterLetters = @('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h')
        $letterIndex = 0

        try {
            $allAdapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual|VPN|Loopback' })

            if ($allAdapters.Count -gt 0) {
                Write-Host "--- Dostupné adaptéry ---" -ForegroundColor Cyan
                foreach ($adapter in $allAdapters) {
                    $letter = $adapterLetters[$letterIndex]

                    # Typ adaptéru
                    $adapterType = ""
                    switch ($adapter.InterfaceType) {
                        6   { $adapterType = "[LAN]" }
                        71  { $adapterType = "[WiFi]" }
                        243 { $adapterType = "[USB]" }
                        244 { $adapterType = "[USB]" }
                        237 { $adapterType = "[BT]" }
                        default { $adapterType = "[?]" }
                    }

                    # Formátování GUID
                    $guidString = $adapter.InterfaceGuid.ToString()
                    if (-not $guidString.StartsWith("{")) {
                        $adapterGuid = "{" + $guidString + "}"
                    } else {
                        $adapterGuid = $guidString
                    }

                    Write-Host "  [$letter] $adapterType " -NoNewline -ForegroundColor Cyan
                    Write-Host "$($adapter.InterfaceDescription)" -ForegroundColor White
                    Write-Host "      GUID: $adapterGuid" -ForegroundColor Gray

                    $letterIndex++
                    if ($letterIndex -ge $adapterLetters.Count) { break }
                }
                Write-Host ""
            }
        } catch {
            Write-Warning "Chyba při načítání adaptérů: $($_.Exception.Message)"
            Write-Host ""
        }

        Write-Host "--- Automatické resety ---" -ForegroundColor Yellow
        Write-Host "[A] [FULL] Automatický reset S adaptéry (kroky 1-7)" -ForegroundColor Green
        Write-Host "[B] [QUICK] Automatický reset BEZ adaptérů (kroky 1-6)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "--- Jednotlivé kroky ---" -ForegroundColor Yellow
        Write-Host "[1] netsh winsock reset         → Reset Winsock katalogu" -ForegroundColor White
        Write-Host "[2] netsh int ip reset          → Reset TCP/IP stacku" -ForegroundColor White
        Write-Host "[3] netsh int tcp reset         → Reset TCP nastavení" -ForegroundColor White
        Write-Host "[4] ipconfig /flushdns          → Vyčištění DNS cache" -ForegroundColor White
        Write-Host "[5] ipconfig /release           → Uvolnění IP adresy" -ForegroundColor White
        Write-Host "[6] ipconfig /renew             → Obnovení IP adresy" -ForegroundColor White
        Write-Host "[7] Reset síťových adaptérů     → Výběr adaptéru" -ForegroundColor White
        Write-Host ""
        Write-Host "[Q] Zpět do menu síťových optimalizací" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        switch ($choice) {
            'A' {
                Invoke-NetworkResetCore -IncludeAdapters $true
                continue
            }
            'B' {
                Invoke-NetworkResetCore -IncludeAdapters $false
                continue
            }
            '1' {
                Invoke-WinsockReset
                Write-Host ""
                Write-Host "💡 TIP: Pro úplný efekt je doporučen restart PC." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '2' {
                Invoke-IPReset
                Write-Host ""
                Write-Host "💡 TIP: Pro úplný efekt je doporučen restart PC." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '3' {
                Invoke-TCPReset
                Write-Host ""
                Write-Host "💡 TIP: Pro úplný efekt je doporučen restart PC." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '4' {
                Invoke-DNSFlush
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '5' {
                Invoke-IPRelease
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '6' {
                Invoke-IPRenew
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '7' {
                Invoke-AdapterResetMenu
            }
            'Q' { return }
            default {
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
            }
        }
    }
}

function Invoke-NetworkResetCore {
    param(
        [bool]$IncludeAdapters = $true
    )

    Clear-Host
    Write-Host "==================================================" -ForegroundColor Cyan
    if ($IncludeAdapters) {
        Write-Host "   [FULL] PROVÁDÍM KOMPLETNÍ RESET SÍTĚ..." -ForegroundColor Cyan
    } else {
        Write-Host "   [QUICK] PROVÁDÍM RYCHLÝ RESET SÍTĚ..." -ForegroundColor Cyan
    }
    Write-Host "==================================================" -ForegroundColor Cyan

    # Volání jednotlivých kroků
    Invoke-WinsockReset
    Start-Sleep -Milliseconds 300

    Invoke-IPReset
    Start-Sleep -Milliseconds 300

    Invoke-TCPReset
    Start-Sleep -Milliseconds 300

    Invoke-DNSFlush
    Start-Sleep -Milliseconds 300

    Invoke-IPRelease
    Start-Sleep -Milliseconds 300

    Invoke-IPRenew
    Start-Sleep -Milliseconds 300

    # Krok 7: Reset síťových adaptérů (pouze pokud je požadován)
    if ($IncludeAdapters) {
        Write-Host ""
        Write-Host "  [7] Resetuji VŠECHNY síťové adaptéry..." -ForegroundColor Yellow
        try {
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual|VPN|Loopback' } -ErrorAction Stop

            if ($adapters.Count -gt 0) {
                foreach ($adapter in $adapters) {
                    Write-Host "      -> Resetuji: $($adapter.Name) ($($adapter.InterfaceDescription))..." -ForegroundColor Cyan
                    try {
                        Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
                        Start-Sleep -Milliseconds 500
                        Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
                        Start-Sleep -Milliseconds 500
                        Write-Host "         [OK] Adaptér resetován." -ForegroundColor Green
                    } catch {
                        Write-Warning "         [WARN] Chyba: $($_.Exception.Message)"
                    }
                }
            } else {
                Write-Warning "     [WARN] Nebyl nalezen žádný aktivní síťový adaptér."
            }
        } catch {
            Write-Error "     [ERROR] Chyba při načítání adaptérů: $($_.Exception.Message)"
        }
    } else {
        Write-Host ""
        Write-Host "  [7] Reset adaptérů přeskočen (rychlý režim)" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Green
    if ($IncludeAdapters) {
        Write-Host "   [OK] KOMPLETNÍ RESET SÍTĚ DOKONČEN!" -ForegroundColor Green
    } else {
        Write-Host "   [OK] RYCHLÝ RESET SÍTĚ DOKONČEN!" -ForegroundColor Green
    }
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "[TIP] Pro úplný efekt je doporučen restart PC." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Stiskněte klávesu pro návrat do menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===================================================================
# SÍŤOVÉ OPTIMALIZACE - HLAVNÍ MENU
# ===================================================================
function Show-NetworkOptimizationMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "     [NET] SÍŤOVÉ OPTIMALIZACE" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Vyberte požadovanou akci:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] [DNS] DNS Konfigurace" -ForegroundColor White
        Write-Host "    (Google, Cloudflare, AdGuard, dns0.eu...)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[2] [TCP/IP] TCP/IP Optimalizace" -ForegroundColor White
        Write-Host "    (Auto-Tuning, RSS, Timestamps...)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[3] [RESET] Reset Sítě" -ForegroundColor Magenta
        Write-Host "    (Winsock, TCP/IP, DNS, adaptéry...)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] Zpět do hlavního menu" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        switch ($choice) {
            '1'  { Show-DNSMenu }
            '2'  { Show-TCPOptimizationMenu }
            '3'  { Reset-Network }
            'Q'  { return }
            default {
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
            }
        }
    }
}

function Show-DNSMenu {
    while ($true) {
        Clear-Host

        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "          🌐 DNS KONFIGURACE" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host ""

        # Načtení všech aktivních adaptérů
        $adapterList = @()
        $adapterLetters = @('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h')
        $letterIndex = 0

        try {
            $allAdapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual|VPN|Loopback' })

            if ($allAdapters.Count -gt 0) {
                foreach ($adapter in $allAdapters) {
                    $letter = $adapterLetters[$letterIndex]

                    # Zjistit aktuální DNS adaptéru
                    $adapterDNS = ""
                    try {
                        $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
                        if ($null -ne $dnsServers -and $dnsServers.ServerAddresses.Count -gt 0) {
                            $adapterDNS = $dnsServers.ServerAddresses[0]
                        } else {
                            $adapterDNS = "DHCP"
                        }
                    } catch {
                        $adapterDNS = "N/A"
                    }

                    # Typ adaptéru
                    $adapterType = ""
                    switch ($adapter.InterfaceType) {
                        6   { $adapterType = "[LAN]" }
                        71  { $adapterType = "[WiFi]" }
                        243 { $adapterType = "[USB]" }
                        244 { $adapterType = "[USB]" }
                        237 { $adapterType = "[BT]" }
                        default { $adapterType = "[?]" }
                    }

                    # Formátování GUID
                    $guidString = $adapter.InterfaceGuid.ToString()
                    if (-not $guidString.StartsWith("{")) {
                        $adapterGuid = "{" + $guidString + "}"
                    } else {
                        $adapterGuid = $guidString
                    }

                    $adapterList += [PSCustomObject]@{
                        Letter = $letter
                        Adapter = $adapter
                        InterfaceIndex = $adapter.ifIndex
                        GUID = $adapterGuid
                        Type = $adapterType
                        Name = $adapter.InterfaceDescription
                        DNS = $adapterDNS
                    }

                    $letterIndex++
                    if ($letterIndex -ge $adapterLetters.Count) { break }
                }
            }
        } catch {
            Write-Warning "Chyba při načítání adaptérů: $($_.Exception.Message)"
        }

        Write-Host "Vyberte DNS poskytovatele:" -ForegroundColor Yellow
        Write-Host "  ČÍSLO = Global (všechny adaptéry)" -ForegroundColor Gray
        Write-Host "  ČÍSLO+PÍSMENO = Konkrétní adaptér (např. 1a, 2b)" -ForegroundColor Gray
        Write-Host ""

        # Zobrazení adaptérů s GUID
        if ($null -ne $adapterList -and $adapterList.Count -gt 0) {
            Write-Host "--- Dostupné adaptéry ---" -ForegroundColor Cyan
            foreach ($item in $adapterList) {
                Write-Host "  [$($item.Letter)] $($item.Type) " -NoNewline -ForegroundColor Cyan
                Write-Host "$($item.Name)" -ForegroundColor White
                Write-Host "      GUID: $($item.GUID)" -NoNewline -ForegroundColor Gray
                Write-Host " | DNS: $($item.DNS)" -ForegroundColor Gray
            }
            Write-Host ""
        } else {
            Write-Host "--- Žádné aktivní adaptéry nebyly nalezeny ---" -ForegroundColor Yellow
            Write-Host ""
        }

        Write-Host "=========================================" -ForegroundColor Gray

        # Menu DNS poskytovatelů
        Write-Host "[1]  Google DNS (8.8.8.8)" -ForegroundColor White
        Write-Host "[2]  Cloudflare DNS (1.1.1.1)" -ForegroundColor White
        Write-Host "[3]  Cloudflare Malware Protection (1.1.1.2)" -ForegroundColor White
        Write-Host "[4]  Cloudflare Malware + Adult Protection (1.1.1.3)" -ForegroundColor White
        Write-Host "[5]  OpenDNS (208.67.222.222)" -ForegroundColor White
        Write-Host "[6]  Quad9 (9.9.9.9)" -ForegroundColor White
        Write-Host "[7]  AdGuard Ads + Trackers (94.140.14.14)" -ForegroundColor White
        Write-Host "[8]  AdGuard Ads + Trackers + Malware + Adult (94.140.14.15)" -ForegroundColor White
        Write-Host "[9]  dns0.eu Open (193.110.81.254)" -ForegroundColor White
        Write-Host "[10] dns0.eu ZERO (193.110.81.9)" -ForegroundColor White
        Write-Host "[11] dns0.eu KIDS (193.110.81.1)" -ForegroundColor White

        Write-Host "=====================================================" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[ i ]  Moje DNS (Detailní zobrazení)" -ForegroundColor Cyan
        Write-Host "[X]    Vyčistit DNS Cache" -ForegroundColor Magenta
        Write-Host "[R]    Reset DNS na automatické (DHCP)" -ForegroundColor Yellow
        Write-Host "[Q]    Zpět do menu síťových optimalizací" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        # Zpracování volby: číslo nebo číslo+písmeno
        $provider = $null
        $targetAdapter = $null

        # Speciální volby
        if ($choice -match '^[iI]$') { Show-MyDNS; continue }
        if ($choice -match '^[xX]$') { Clear-DNSCacheMenu; continue }
        if ($choice -eq 'R') { Reset-DNSToAutomatic; continue }
        if ($choice -eq 'Q') { return }

        # Parsování číslo[+písmeno]
        if ($choice -match '^(\d+)([a-h])?$') {
            $dnsNumber = $Matches[1]
            $adapterLetter = $Matches[2]

            # Mapování čísla na poskytovatele
            $provider = switch ($dnsNumber) {
                '1'  { "Google" }
                '2'  { "Cloudflare" }
                '3'  { "Cloudflare_Malware" }
                '4'  { "Cloudflare_Malware_Adult" }
                '5'  { "Open_DNS" }
                '6'  { "Quad9" }
                '7'  { "AdGuard_Ads_Trackers" }
                '8'  { "AdGuard_Ads_Trackers_Malware_Adult" }
                '9'  { "dns0.eu_Open" }
                '10' { "dns0.eu_ZERO" }
                '11' { "dns0.eu_KIDS" }
                default { $null }
            }

            if ($null -ne $provider) {
                # Pokud je specifikováno písmeno, najdi adaptér
                if ($null -ne $adapterLetter -and $adapterLetter -ne '') {
                    $targetAdapter = $adapterList | Where-Object { $_.Letter -eq $adapterLetter }
                    if ($null -eq $targetAdapter) {
                        Write-Warning "Neplatné písmeno adaptéru: $adapterLetter"
                        Start-Sleep -Seconds 2
                        continue
                    }
                }

                # Zavolej Set-CustomDNS
                if ($null -ne $targetAdapter) {
                    Set-CustomDNS -Provider $provider -SpecificAdapter $targetAdapter.InterfaceIndex
                } else {
                    Set-CustomDNS -Provider $provider
                }
            } else {
                Write-Warning "Neplatné číslo DNS poskytovatele: $dnsNumber"
                Start-Sleep -Seconds 2
            }
        } else {
            Write-Warning "Neplatná volba. Použijte formát: ČÍSLO nebo ČÍSLO+PÍSMENO (např. 1, 1a, 2b)"
            Start-Sleep -Seconds 2
        }
    }
}

# ===================================================================
# TCP/IP OPTIMALIZACE - NOVÁ VERZE S PODMENU
# ===================================================================

# --- Pomocná funkce pro pauzu ---
function Wait-ScriptContinue {
    Write-Host ""
    Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# --- Pomocná funkce pro nastavení globálního TCP parametru ---
function Set-TcpGlobalParameter {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ParameterName,

        [Parameter(Mandatory=$true)]
        [string]$Value
    )
    Write-Host "  -> Nastavuji '$ParameterName' na '$Value'..." -ForegroundColor Yellow
    try {
        # Spustíme příkaz netsh
        $process = Start-Process -FilePath "netsh.exe" -ArgumentList "interface tcp set global $ParameterName=$Value" -Wait -NoNewWindow -PassThru -ErrorAction Stop

        if ($process.ExitCode -eq 0) {
            Write-Host "     ✓ Úspěšně nastaveno." -ForegroundColor Green
        } else {
            Write-Warning "     ✗ Příkaz netsh selhal s kódem: $($process.ExitCode)"
        }
    } catch {
        Write-Warning "     ✗ Chyba při spouštění netsh: $($_.Exception.Message)"
    }

    # Malé zpoždění pro viditelnost (bez pauzy)
    Start-Sleep -Milliseconds 300
}

# ===================================================================
# SEKCE: Nagleův Algoritmus (Specifické pro adaptér)
# ===================================================================

# --- Pomocná funkce pro nastavení registru Nagle ---
function Set-NagleInterfaceTweak {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InterfaceGUID,

        [Parameter(Mandatory=$true)]
        [string]$InterfaceName,

        [Parameter(Mandatory=$true)]
        [bool]$EnableTweak # $true = Vypnout Nagle, $false = Obnovit výchozí
    )

    # Cesta v registru vyžaduje GUID se složenými závorkami
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$InterfaceGUID"

    if (-not (Test-Path $regPath)) {
        Write-Warning "  ️ Cesta k registru pro adaptér '$InterfaceName' nebyla nalezena."
        Write-Warning "     Očekávaná cesta: $regPath"
        return
    }

    if ($EnableTweak) {
        Write-Host "  -> Aplikuji tweak (Vypínám Nagle) pro: '$InterfaceName'" -ForegroundColor Yellow
        try {
            Set-ItemProperty -Path $regPath -Name "TcpAckFrequency" -Value 1 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path $regPath -Name "TCPNoDelay" -Value 1 -Type DWord -ErrorAction Stop
            Write-Host "     Úspěšně nastaveno: TcpAckFrequency=1, TCPNoDelay=1" -ForegroundColor Green
        } catch {
            Write-Error "     Chyba při zápisu do registru pro '$InterfaceName': $($_.Exception.Message)"
        }
    } else {
        Write-Host "  -> Obnovuji výchozí (Zapínám Nagle) pro: '$InterfaceName'" -ForegroundColor Yellow
        try {
            # Odstranění hodnot obnoví výchozí chování systému
            if (Get-ItemProperty -Path $regPath -Name "TcpAckFrequency" -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $regPath -Name "TcpAckFrequency" -ErrorAction Stop
                Write-Host "     Hodnota 'TcpAckFrequency' odstraněna." -ForegroundColor Green
            }
            if (Get-ItemProperty -Path $regPath -Name "TCPNoDelay" -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $regPath -Name "TCPNoDelay" -ErrorAction Stop
                Write-Host "     Hodnota 'TCPNoDelay' odstraněna." -ForegroundColor Green
            }
            Write-Host "    -> Výchozí stav obnoven."
        } catch {
            Write-Error "     Chyba při mazání hodnot z registru pro '$InterfaceName': $($_.Exception.Message)"
        }
    }
}

# --- Menu pro Nagleův Algoritmus (S VYLEPŠENOU IDENTIFIKACÍ) ---
function Show-NagleTweakMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Magenta
        Write-Host "   TCP/IP - Optimalizace Nagle (Latency Tweak)    " -ForegroundColor Magenta
        Write-Host "==================================================" -ForegroundColor Magenta
        Write-Host "Vypnutí Nagle (TcpAckFrequency=1, TCPNoDelay=1) donutí systém"
        Write-Host "odesílat malé pakety okamžitě. Kritické pro e-sports."
        Write-Host ""
        Write-Host "Načítám aktivní síťové adaptéry (Status = 'Up')..." -ForegroundColor Gray

        $adapterList = @()
        $menuIndex = 1

        try {
            # Použití Get-NetAdapter pro moderní a přesnou detekci
            $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} -ErrorAction Stop

            if ($null -eq $adapters -or $adapters.Count -eq 0) {
                Write-Warning "Nebyl nalezen žádný aktivní síťový adaptér (Status = 'Up')."
                Write-Warning "Zkontrolujte, zda je síťový kabel připojen."
                Write-Host "[Q] Zpět" -ForegroundColor Red
                $choice = Read-Host -Prompt "Zadejte svou volbu"
                if ($choice -eq 'Q') { return }
                continue
            }

            Write-Host "--- Vyberte adaptér pro optimalizaci ---" -ForegroundColor Yellow

            # Vytvoření seznamu adaptérů pro menu
            foreach ($adapter in $adapters) {

                # ------ NOVÁ IDENTIFIKACE TYPU ADAPTÉRU ------
                $adapterType = ""
                # Kódy IANA Interface Type
                switch ($adapter.InterfaceType) {
                    6   { $adapterType = "[LAN Ethernet]" }
                    71  { $adapterType = "[WiFi]" }
                    243 { $adapterType = "[USB]" } # Běžné pro USB Tethering
                    244 { $adapterType = "[USB]" } # Běžné pro USB Tethering
                    237 { $adapterType = "[Bluetooth]" }
                    default { $adapterType = "[Ostatní typ: $($adapter.InterfaceType)]" }
                }
                # ---------------------------------------------

                # Explicitní formátování GUID na string se složenými závorkami pro registr
                $guidString = $adapter.InterfaceGuid.ToString()
                if (-not $guidString.StartsWith("{")) {
                    $registryGuid = "{" + $guidString + "}"
                } else {
                    $registryGuid = $guidString
                }

                $adapterList += [PSCustomObject]@{
                    Index = $menuIndex
                    Name  = $adapter.InterfaceDescription
                    GUID  = $registryGuid
                }

                # Zjištění stavu Nagle pro zobrazení
                $nagleStatus = ""
                try {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$registryGuid"
                    $tcpAckFreq = Get-ItemProperty -Path $regPath -Name "TcpAckFrequency" -ErrorAction SilentlyContinue
                    $tcpNoDelay = Get-ItemProperty -Path $regPath -Name "TCPNoDelay" -ErrorAction SilentlyContinue

                    if ($null -ne $tcpAckFreq -and $tcpAckFreq.TcpAckFrequency -eq 1 -and $null -ne $tcpNoDelay -and $tcpNoDelay.TCPNoDelay -eq 1) {
                        $nagleStatus = " ✓ [GAMING TWEAK]"
                    }
                } catch { }

                # ZOBRAZENÍ VYLEPŠENÉHO NÁZVU SE STAVEM
                if ($nagleStatus -ne "") {
                    Write-Host "[$menuIndex] $adapterType $($adapter.InterfaceDescription)" -NoNewline -ForegroundColor White
                    Write-Host "$nagleStatus" -ForegroundColor Green
                } else {
                    Write-Host "[$menuIndex] $adapterType $($adapter.InterfaceDescription)" -ForegroundColor White
                }
                $menuIndex++
            }
        } catch {
            Write-Error "Chyba při načítání síťových adaptérů: $($_.Exception.Message)"
            Wait-ScriptContinue
            return
        }

        Write-Host ""
        Write-Host "--- Hromadné akce ---" -ForegroundColor Cyan
        Write-Host "[A] Aplikovat tweak (Vypnout Nagle) na VŠECHNY výše uvedené" -ForegroundColor Green
        Write-Host "[R] Obnovit výchozí (Zapnout Nagle) pro VŠECHNY výše uvedené" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[B] Obnovit seznam adaptérů (refresh)" -ForegroundColor Cyan
        Write-Host "[Q] Zpět do TCP/IP menu" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu (číslo, A, R, B nebo Q)"

        switch ($choice) {
            'A' {
                Write-Host ""
                Write-Host "Aplikuji tweak na VŠECHNY adaptéry..." -ForegroundColor Green
                foreach ($item in $adapterList) {
                    Set-NagleInterfaceTweak -InterfaceGUID $item.GUID -InterfaceName $item.Name -EnableTweak $true
                }
                Wait-ScriptContinue
                continue # Znovu načte menu
            }
            'a' {
                Write-Host ""
                Write-Host "Aplikuji tweak na VŠECHNY adaptéry..." -ForegroundColor Green
                foreach ($item in $adapterList) {
                    Set-NagleInterfaceTweak -InterfaceGUID $item.GUID -InterfaceName $item.Name -EnableTweak $true
                }
                Wait-ScriptContinue
                continue # Znovu načte menu
            }
            'R' {
                Write-Host ""
                Write-Host "Obnovuji výchozí nastavení pro VŠECHNY adaptéry..." -ForegroundColor Yellow
                foreach ($item in $adapterList) {
                    Set-NagleInterfaceTweak -InterfaceGUID $item.GUID -InterfaceName $item.Name -EnableTweak $false
                }
                Wait-ScriptContinue
                continue # Znovu načte menu
            }
            'r' {
                Write-Host ""
                Write-Host "Obnovuji výchozí nastavení pro VŠECHNY adaptéry..." -ForegroundColor Yellow
                foreach ($item in $adapterList) {
                    Set-NagleInterfaceTweak -InterfaceGUID $item.GUID -InterfaceName $item.Name -EnableTweak $false
                }
                Wait-ScriptContinue
                continue # Znovu načte menu
            }
            'B' {
                Write-Host ""
                Write-Host "Obnovuji seznam adaptérů..." -ForegroundColor Cyan
                Start-Sleep -Milliseconds 500
                continue # Znovu načte menu s aktuálními adaptéry
            }
            'b' {
                Write-Host ""
                Write-Host "Obnovuji seznam adaptérů..." -ForegroundColor Cyan
                Start-Sleep -Milliseconds 500
                continue # Znovu načte menu s aktuálními adaptéry
            }
            'Q' { return }
            'q' { return }

            default {
                # Pokus o zpracování číselné volby
                $selectedAdapter = $adapterList | Where-Object { $_.Index -eq $choice }

                if ($null -ne $selectedAdapter) {
                    # Zobrazení podmenu pro konkrétní adaptér
                    $shouldExit = $false
                    while (-not $shouldExit) {
                        Clear-Host
                        Write-Host "==================================================" -ForegroundColor Magenta
                        Write-Host "Vybrán adaptér: $($selectedAdapter.Name)" -ForegroundColor White
                        Write-Host "GUID: $($selectedAdapter.GUID)" -ForegroundColor Gray
                        Write-Host "==================================================" -ForegroundColor Magenta
                        Write-Host ""

                        # Zjištění aktuálního stavu Nagle
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($selectedAdapter.GUID)"
                        $currentStatus = "❓ Neznámý"
                        $tcpAckFreqValue = "N/A"
                        $tcpNoDelayValue = "N/A"

                        try {
                            $tcpAckFreq = Get-ItemProperty -Path $regPath -Name "TcpAckFrequency" -ErrorAction SilentlyContinue
                            $tcpNoDelay = Get-ItemProperty -Path $regPath -Name "TCPNoDelay" -ErrorAction SilentlyContinue

                            # Zjištění hodnot
                            if ($null -ne $tcpAckFreq) {
                                $tcpAckFreqValue = $tcpAckFreq.TcpAckFrequency
                            } else {
                                $tcpAckFreqValue = "Neexistuje (výchozí)"
                            }

                            if ($null -ne $tcpNoDelay) {
                                $tcpNoDelayValue = $tcpNoDelay.TCPNoDelay
                            } else {
                                $tcpNoDelayValue = "Neexistuje (výchozí)"
                            }

                            # Určení celkového stavu
                            if ($null -ne $tcpAckFreq -and $tcpAckFreq.TcpAckFrequency -eq 1 -and $null -ne $tcpNoDelay -and $tcpNoDelay.TCPNoDelay -eq 1) {
                                $currentStatus = "✓ VYPNUTO (Gaming tweak aktivní)"
                                Write-Host "Celkový stav Nagle: " -NoNewline -ForegroundColor Yellow
                                Write-Host "$currentStatus" -ForegroundColor Green
                            } elseif ($null -eq $tcpAckFreq -and $null -eq $tcpNoDelay) {
                                $currentStatus = "✓ ZAPNUTO (Výchozí systémové nastavení)"
                                Write-Host "Celkový stav Nagle: " -NoNewline -ForegroundColor Yellow
                                Write-Host "$currentStatus" -ForegroundColor Cyan
                            } else {
                                $currentStatus = "⚠️ Částečně nakonfigurováno"
                                Write-Host "Celkový stav Nagle: " -NoNewline -ForegroundColor Yellow
                                Write-Host "$currentStatus" -ForegroundColor Yellow
                            }
                        } catch {
                            Write-Host "Celkový stav Nagle: " -NoNewline -ForegroundColor Yellow
                            Write-Host "$currentStatus" -ForegroundColor Gray
                        }

                        # Detailní zobrazení hodnot
                        Write-Host ""
                        Write-Host "--- Detailní hodnoty registru ---" -ForegroundColor Cyan
                        Write-Host "  TcpAckFrequency: " -NoNewline -ForegroundColor Gray
                        if ($tcpAckFreqValue -eq 1) {
                            Write-Host "$tcpAckFreqValue" -ForegroundColor Green -NoNewline
                            Write-Host " (Gaming)" -ForegroundColor Gray
                        } elseif ($tcpAckFreqValue -eq "Neexistuje (výchozí)") {
                            Write-Host "$tcpAckFreqValue" -ForegroundColor Cyan
                        } else {
                            Write-Host "$tcpAckFreqValue" -ForegroundColor Yellow
                        }

                        Write-Host "  TCPNoDelay:      " -NoNewline -ForegroundColor Gray
                        if ($tcpNoDelayValue -eq 1) {
                            Write-Host "$tcpNoDelayValue" -ForegroundColor Green -NoNewline
                            Write-Host " (Gaming)" -ForegroundColor Gray
                        } elseif ($tcpNoDelayValue -eq "Neexistuje (výchozí)") {
                            Write-Host "$tcpNoDelayValue" -ForegroundColor Cyan
                        } else {
                            Write-Host "$tcpNoDelayValue" -ForegroundColor Yellow
                        }

                        Write-Host ""
                        Write-Host "--- Základní akce ---" -ForegroundColor Yellow
                        Write-Host "[1] Aplikovat tweak (Vypnout Nagle - OBĚ hodnoty = 1)" -ForegroundColor Green
                        Write-Host "[2] Obnovit výchozí (Zapnout Nagle - SMAZAT OBĚ hodnoty)" -ForegroundColor Yellow
                        Write-Host ""
                        Write-Host "--- Pokročilé akce (samostatně) ---" -ForegroundColor Magenta
                        Write-Host "[F] Přepnout TcpAckFrequency (1 / smazat)" -ForegroundColor White
                        Write-Host "[D] Přepnout TCPNoDelay (1 / smazat)" -ForegroundColor White
                        Write-Host ""
                        Write-Host "[Q] Zpět na výběr adaptérů" -ForegroundColor Red
                        Write-Host ""
                        $subChoice = Read-Host -Prompt "Zadejte volbu"

                        switch ($subChoice) {
                            '1' {
                                Set-NagleInterfaceTweak -InterfaceGUID $selectedAdapter.GUID -InterfaceName $selectedAdapter.Name -EnableTweak $true
                                Wait-ScriptContinue
                                # Zůstaneme v menu pro zobrazení změny
                            }
                            '2' {
                                Set-NagleInterfaceTweak -InterfaceGUID $selectedAdapter.GUID -InterfaceName $selectedAdapter.Name -EnableTweak $false
                                Wait-ScriptContinue
                                # Zůstaneme v menu pro zobrazení změny
                            }
                            'F' {
                                # Přepnutí TcpAckFrequency
                                Write-Host ""
                                Write-Host "  -> Přepínám TcpAckFrequency..." -ForegroundColor Yellow
                                try {
                                    $currentVal = Get-ItemProperty -Path $regPath -Name "TcpAckFrequency" -ErrorAction SilentlyContinue
                                    if ($null -ne $currentVal -and $currentVal.TcpAckFrequency -eq 1) {
                                        # Je nastaveno na 1, smažeme
                                        Remove-ItemProperty -Path $regPath -Name "TcpAckFrequency" -ErrorAction Stop
                                        Write-Host "     ✓ TcpAckFrequency odstraněn (vráceno na výchozí)" -ForegroundColor Cyan
                                    } else {
                                        # Není nastaveno nebo má jinou hodnotu, nastavíme na 1
                                        Set-ItemProperty -Path $regPath -Name "TcpAckFrequency" -Value 1 -Type DWord -ErrorAction Stop
                                        Write-Host "     ✓ TcpAckFrequency nastaven na 1 (Gaming)" -ForegroundColor Green
                                    }
                                } catch {
                                    Write-Warning "     ✗ Chyba při změně TcpAckFrequency: $($_.Exception.Message)"
                                }
                                Wait-ScriptContinue
                            }
                            'f' {
                                # Přepnutí TcpAckFrequency (malé písmeno)
                                Write-Host ""
                                Write-Host "  -> Přepínám TcpAckFrequency..." -ForegroundColor Yellow
                                try {
                                    $currentVal = Get-ItemProperty -Path $regPath -Name "TcpAckFrequency" -ErrorAction SilentlyContinue
                                    if ($null -ne $currentVal -and $currentVal.TcpAckFrequency -eq 1) {
                                        # Je nastaveno na 1, smažeme
                                        Remove-ItemProperty -Path $regPath -Name "TcpAckFrequency" -ErrorAction Stop
                                        Write-Host "     ✓ TcpAckFrequency odstraněn (vráceno na výchozí)" -ForegroundColor Cyan
                                    } else {
                                        # Není nastaveno nebo má jinou hodnotu, nastavíme na 1
                                        Set-ItemProperty -Path $regPath -Name "TcpAckFrequency" -Value 1 -Type DWord -ErrorAction Stop
                                        Write-Host "     ✓ TcpAckFrequency nastaven na 1 (Gaming)" -ForegroundColor Green
                                    }
                                } catch {
                                    Write-Warning "     ✗ Chyba při změně TcpAckFrequency: $($_.Exception.Message)"
                                }
                                Wait-ScriptContinue
                            }
                            'D' {
                                # Přepnutí TCPNoDelay
                                Write-Host ""
                                Write-Host "  -> Přepínám TCPNoDelay..." -ForegroundColor Yellow
                                try {
                                    $currentVal = Get-ItemProperty -Path $regPath -Name "TCPNoDelay" -ErrorAction SilentlyContinue
                                    if ($null -ne $currentVal -and $currentVal.TCPNoDelay -eq 1) {
                                        # Je nastaveno na 1, smažeme
                                        Remove-ItemProperty -Path $regPath -Name "TCPNoDelay" -ErrorAction Stop
                                        Write-Host "     ✓ TCPNoDelay odstraněn (vráceno na výchozí)" -ForegroundColor Cyan
                                    } else {
                                        # Není nastaveno nebo má jinou hodnotu, nastavíme na 1
                                        Set-ItemProperty -Path $regPath -Name "TCPNoDelay" -Value 1 -Type DWord -ErrorAction Stop
                                        Write-Host "     ✓ TCPNoDelay nastaven na 1 (Gaming)" -ForegroundColor Green
                                    }
                                } catch {
                                    Write-Warning "     ✗ Chyba při změně TCPNoDelay: $($_.Exception.Message)"
                                }
                                Wait-ScriptContinue
                            }
                            'd' {
                                # Přepnutí TCPNoDelay (malé písmeno)
                                Write-Host ""
                                Write-Host "  -> Přepínám TCPNoDelay..." -ForegroundColor Yellow
                                try {
                                    $currentVal = Get-ItemProperty -Path $regPath -Name "TCPNoDelay" -ErrorAction SilentlyContinue
                                    if ($null -ne $currentVal -and $currentVal.TCPNoDelay -eq 1) {
                                        # Je nastaveno na 1, smažeme
                                        Remove-ItemProperty -Path $regPath -Name "TCPNoDelay" -ErrorAction Stop
                                        Write-Host "     ✓ TCPNoDelay odstraněn (vráceno na výchozí)" -ForegroundColor Cyan
                                    } else {
                                        # Není nastaveno nebo má jinou hodnotu, nastavíme na 1
                                        Set-ItemProperty -Path $regPath -Name "TCPNoDelay" -Value 1 -Type DWord -ErrorAction Stop
                                        Write-Host "     ✓ TCPNoDelay nastaven na 1 (Gaming)" -ForegroundColor Green
                                    }
                                } catch {
                                    Write-Warning "     ✗ Chyba při změně TCPNoDelay: $($_.Exception.Message)"
                                }
                                Wait-ScriptContinue
                            }
                            'Q' { $shouldExit = $true } # Návrat z podmenu
                            'q' { $shouldExit = $true } # Návrat z podmenu (malé písmeno)
                            default { Write-Warning "Neplatná volba."; Start-Sleep -Seconds 2 }
                        }
                    }
                } else {
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
                }
            }
        }
    }
}


# ===================================================================
# SEKCE: Globální NETSH parametry (Manuální podmenu)
# ===================================================================

# --- Menu pro Auto-Tuning Level ---
function Show-AutoTuningLevelMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "      TCP/IP - Auto-Tuning Level" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "Řídí, jak systém automaticky upravuje velikost TCP přijímacího okna."
        Write-Host ""
        Write-Host "Možné hodnoty:" -ForegroundColor Yellow
        Write-Host "[1] disabled         - Vypnuto (Nedoporučeno pro rychlé sítě)" -ForegroundColor White
        Write-Host "[2] highlyrestricted - Velmi omezené" -ForegroundColor White
        Write-Host "[3] restricted       - Omezené" -ForegroundColor White
        Write-Host "[4] normal           - Normální (Výchozí, doporučeno pro většinu)" -ForegroundColor Green
        Write-Host "[5] experimental     - Experimentální (Může zvýšit výkon, ale i nestabilitu)" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "[Q] Zpět do menu manuálních úprav" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $value = $null

        switch ($choice) {
            '1' { $value = "disabled" }
            '2' { $value = "highlyrestricted" }
            '3' { $value = "restricted" }
            '4' { $value = "normal" }
            '5' { $value = "experimental" }
            'Q' { return }
            default { Write-Warning "Neplatná volba."; Start-Sleep -Seconds 2; continue }
        }

        if ($null -ne $value) {
        Write-Host ""
            Set-TcpGlobalParameter -ParameterName "autotuninglevel" -Value $value
            Write-Host ""
            Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return # Vracíme se po nastavení
        }
    }
}

# --- Menu pro ECN Capability ---
function Show-ECNCapabilityMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "      TCP/IP - ECN Capability                     " -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "Explicit Congestion Notification - umožňuje routerům signalizovat přetížení."
        Write-Host ""
        Write-Host "Možné hodnoty:" -ForegroundColor Yellow
        Write-Host "[1] enabled    - Povoleno" -ForegroundColor White
        Write-Host "[2] disabled   - Zakázáno (Častý gaming tweak, může pomoci se starými routery)" -ForegroundColor Green
        Write-Host "[3] default    - Řízeno systémem (Obvykle disabled)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] Zpět do menu manuálních úprav" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $value = $null

        switch ($choice) {
            '1' { $value = "enabled" }
            '2' { $value = "disabled" }
            '3' { $value = "default" }
            'Q' { return }
            default { Write-Warning "Neplatná volba."; Start-Sleep -Seconds 2; continue }
        }

        if ($null -ne $value) {
        Write-Host ""
            Set-TcpGlobalParameter -ParameterName "ecncapability" -Value $value
        Write-Host ""
            Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
    }
}

# --- Menu pro Timestamps ---
function Show-TimestampsMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "      TCP/IP - Timestamps" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "TCP Timestamps (RFC 1323) - používá se pro měření RTT a PAWS."
        Write-Host ""
        Write-Host "Možné hodnoty:" -ForegroundColor Yellow
        Write-Host "[1] enabled    - Povoleno (Mírně vyšší overhead)" -ForegroundColor White
        Write-Host "[2] disabled   - Zakázáno (Mírně nižší overhead, častý gaming tweak)" -ForegroundColor Green
        Write-Host "[3] default    - Řízeno systémem (Obvykle allowed/enabled)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] Zpět do menu manuálních úprav" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $value = $null

        switch ($choice) {
            '1' { $value = "enabled" } # V dokumentaci MS je 'allowed', ale 'enabled' funguje
            '2' { $value = "disabled" }
            '3' { $value = "default" }
            'Q' { return }
            default { Write-Warning "Neplatná volba."; Start-Sleep -Seconds 2; continue }
        }

        if ($null -ne $value) {
            # Poznámka: 'netsh' používá 'enabled'/'disabled', i když 'show global' může ukazovat 'allowed'
            Write-Host ""
            Set-TcpGlobalParameter -ParameterName "timestamps" -Value $value
            Write-Host ""
            Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
    }
}

# --- Menu pro RSC ---
function Show-RSCMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "      TCP/IP - Receive Segment Coalescing (RSC)   " -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "Slučuje malé příchozí pakety do větších pro snížení zátěže CPU."
    Write-Host ""
        Write-Host "Možné hodnoty:" -ForegroundColor Yellow
        Write-Host "[1] enabled    - Povoleno (Doporučeno pro vysoké rychlosti)" -ForegroundColor Green
        Write-Host "[2] disabled   - Zakázáno" -ForegroundColor White
        Write-Host "[3] default    - Řízeno systémem (Obvykle enabled)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] Zpět do menu manuálních úprav" -ForegroundColor Red
    Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $value = $null

        switch ($choice) {
            '1' { $value = "enabled" }
            '2' { $value = "disabled" }
            '3' { $value = "default" }
            'Q' { return }
            default { Write-Warning "Neplatná volba."; Start-Sleep -Seconds 2; continue }
        }

        if ($null -ne $value) {
            Write-Host ""
            Set-TcpGlobalParameter -ParameterName "rsc" -Value $value
            Write-Host ""
            Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
    }
}

# --- Menu pro Hystart ---
function Show-HystartMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "      TCP/IP - HyStart                            " -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "Algoritmus pro rychlejší nalezení dostupné šířky pásma (vylepšený slow start)."
        Write-Host ""
        Write-Host "Možné hodnoty:" -ForegroundColor Yellow
        Write-Host "[1] enabled    - Povoleno (Moderní, doporučeno)" -ForegroundColor Green
        Write-Host "[2] disabled   - Zakázáno" -ForegroundColor White
        Write-Host "[3] default    - Řízeno systémem (Obvykle enabled)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] Zpět do menu manuálních úprav" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $value = $null

        switch ($choice) {
            '1' { $value = "enabled" }
            '2' { $value = "disabled" }
            '3' { $value = "default" }
            'Q' { return }
            default { Write-Warning "Neplatná volba."; Start-Sleep -Seconds 2; continue }
        }

        if ($null -ne $value) {
            Write-Host ""
            Set-TcpGlobalParameter -ParameterName "hystart" -Value $value
            Write-Host ""
            Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
    }
}

# --- Menu pro PRR ---
function Show-PRRMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "    TCP/IP - Proportional Rate Reduction (PRR)    " -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "Algoritmus pro rychlejší zotavení po ztrátě paketů."
        Write-Host ""
        Write-Host "Možné hodnoty:" -ForegroundColor Yellow
        Write-Host "[1] enabled    - Povoleno (Moderní, doporučeno)" -ForegroundColor Green
        Write-Host "[2] disabled   - Zakázáno" -ForegroundColor White
        Write-Host "[3] default    - Řízeno systémem (Obvykle enabled)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] Zpět do menu manuálních úprav" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $value = $null

        switch ($choice) {
            '1' { $value = "enabled" }
            '2' { $value = "disabled" }
            '3' { $value = "default" }
            'Q' { return }
            default { Write-Warning "Neplatná volba."; Start-Sleep -Seconds 2; continue }
        }

        if ($null -ne $value) {
        Write-Host ""
            Set-TcpGlobalParameter -ParameterName "prr" -Value $value
            Write-Host ""
            Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
    }
}

# --- Menu pro Pacing Profile ---
function Show-PacingProfileMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "           TCP/IP - Pacing Profile                    " -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "Řízení 'vyhlazování' odchozího provozu (užitečné pro média, nevhodné pro gaming)."
        Write-Host ""
        Write-Host "Možné hodnoty:" -ForegroundColor Yellow
        Write-Host "[1] off      - Vypnuto (Doporučeno pro gaming)" -ForegroundColor Green
        Write-Host "[2] on       - Zapnuto" -ForegroundColor White
        Write-Host "[3] default  - Řízeno systémem (Obvykle off)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] Zpět do menu manuálních úprav" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $value = $null

        switch ($choice) {
            '1' { $value = "off" }
            '2' { $value = "on" }
            '3' { $value = "default" }
            'Q' { return }
            default { Write-Warning "Neplatná volba."; Start-Sleep -Seconds 2; continue }
        }

        if ($null -ne $value) {
    Write-Host ""
            Set-TcpGlobalParameter -ParameterName "pacingprofile" -Value $value
            Write-Host ""
            Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
    }
}

# --- Menu pro RSS ---
function Show-RSSMenu {
    while ($true) {
        Clear-Host
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host "      TCP/IP - Receive Side Scaling (RSS)               " -ForegroundColor Cyan
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host "Rozděluje zpracování příchozích paketů na více jader CPU."
    Write-Host ""
        Write-Host "Možné hodnoty:" -ForegroundColor Yellow
        Write-Host "[1] enabled    - Povoleno (Nutnost pro vícejádrové CPU a rychlé sítě)" -ForegroundColor Green
        Write-Host "[2] disabled   - Zakázáno (Pouze pro diagnostiku nebo velmi starý HW)" -ForegroundColor Red
        Write-Host "[3] default    - Řízeno systémem (Obvykle enabled)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] Zpět do menu manuálních úprav" -ForegroundColor Red
    Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $value = $null

        switch ($choice) {
            '1' { $value = "enabled" }
            '2' { $value = "disabled" }
            '3' { $value = "default" }
            'Q' { return }
            default { Write-Warning "Neplatná volba."; Start-Sleep -Seconds 2; continue }
        }

        if ($null -ne $value) {
        Write-Host ""
            Set-TcpGlobalParameter -ParameterName "rss" -Value $value
        Write-Host ""
            Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
    }
}

# ===================================================================
# Podmenu pro manuální NETSH parametry
# ===================================================================
function Show-ManualNetshMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "    Manuální nastavení globálních TCP (NETSH)    " -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host ""

        # Zobrazení současného stavu (opětovné)
        Write-Host "--- Současný stav globálních TCP parametrů ---" -ForegroundColor Yellow
        try {
            $tcpSettingsOutput = netsh interface tcp show global | Out-String
            Write-Host $tcpSettingsOutput -ForegroundColor Gray
        } catch {
            Write-Warning "Nepodařilo se načíst aktuální TCP nastavení pomocí 'netsh'."
        }
        Write-Host "--------------------------------------------------" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Vyberte parametr k úpravě:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] Změnit Auto-Tuning Level" -ForegroundColor White
        Write-Host "[2] Změnit ECN Capability" -ForegroundColor White
        Write-Host "[3] Změnit Timestamps" -ForegroundColor White
        Write-Host "[4] Změnit Receive Segment Coalescing (RSC)" -ForegroundColor White
        Write-Host "[5] Změnit HyStart" -ForegroundColor White
        Write-Host "[6] Změnit Proportional Rate Reduction (PRR)" -ForegroundColor White
        Write-Host "[7] Změnit Pacing Profile" -ForegroundColor White
        Write-Host "[8] Změnit Receive Side Scaling (RSS)" -ForegroundColor White
        Write-Host ""
        Write-Host "[Q] Zpět do hlavního TCP/IP menu" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        switch ($choice) {
            '1' { Show-AutoTuningLevelMenu }
            '2' { Show-ECNCapabilityMenu }
            '3' { Show-TimestampsMenu }
            '4' { Show-RSCMenu }
            '5' { Show-HystartMenu }
            '6' { Show-PRRMenu }
            '7' { Show-PacingProfileMenu }
            '8' { Show-RSSMenu }
            'Q' { return }
            default {
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
            }
        }
    }
}

# ===================================================================
# HLAVNÍ MENU TCP/IP OPTIMALIZACE (REFAKTOROVÁNO)
# ===================================================================

# --- Hlavní menu pro TCP/IP Optimalizaci ---
function Show-TCPOptimizationMenu {
    while ($true) {
        Clear-Host
        Write-Host "=====================================================" -ForegroundColor Cyan
        Write-Host "      TCP/IP OPTIMALIZACE" -ForegroundColor Cyan
        Write-Host "=====================================================" -ForegroundColor Cyan
        Write-Host ""

        # Zobrazení současného stavu
        Write-Host "--- Současný stav globálních TCP parametrů ---" -ForegroundColor Yellow
        try {
            # Použijeme zachycení výstupu do proměnné
            $tcpSettingsOutput = netsh interface tcp show global | Out-String
            Write-Host $tcpSettingsOutput -ForegroundColor Gray
    } catch {
            Write-Warning "Nepodařilo se načíst aktuální TCP nastavení pomocí 'netsh'."
        }
        Write-Host "-----------------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Vyberte požadovanou akci:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] Aplikovat GAMING optimalizace (Globální)" -ForegroundColor Green
        Write-Host "    (Přednastavené hodnoty pro nízkou latenci)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[2] Obnovit VÝCHOZÍ nastavení Windows (Globální)" -ForegroundColor Yellow
        Write-Host "    (Všechny globální hodnoty na 'default')" -ForegroundColor Gray
        Write-Host ""
        Write-Host "--- Pokročilé úpravy ---" -ForegroundColor Cyan
        Write-Host "[3] Manuální nastavení globálních parametrů (NETSH)" -ForegroundColor White
        Write-Host ""
        Write-Host "--- Nastavení specifické pro adaptér (Registry) ---" -ForegroundColor Magenta
        Write-Host "[4] Optimalizace Nagle (TcpAckFrequency/TCPNoDelay)" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "[Q] Zpět do menu síťových optimalizací" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"

        switch ($choice) {
            '1'  { Set-GamingTCPSettings }
            '2'  { Restore-DefaultTCPSettings }
            '3'  { Show-ManualNetshMenu }
            '4'  { Show-NagleTweakMenu }
            'Q'  { return }
            default {
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
            }
        }
    }
}

# --- Funkce pro aplikaci přednastavených Gaming hodnot ---
function Set-GamingTCPSettings {
    Clear-Host
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host "   🎮 APLIKUJI GLOBÁLNÍ GAMING TCP/IP OPTIMALIZACE" -ForegroundColor Green
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Nastavuji 8 parametrů pro minimální latenci..." -ForegroundColor Cyan
    Write-Host ""

    # Použití pomocné funkce pro konzistenci (běží autonomně)
    Set-TcpGlobalParameter -ParameterName "rss" -Value "enabled"
    Set-TcpGlobalParameter -ParameterName "autotuninglevel" -Value "normal"
    Set-TcpGlobalParameter -ParameterName "ecncapability" -Value "disabled"
    Set-TcpGlobalParameter -ParameterName "timestamps" -Value "disabled"
    Set-TcpGlobalParameter -ParameterName "rsc" -Value "enabled"
    Set-TcpGlobalParameter -ParameterName "hystart" -Value "enabled"
    Set-TcpGlobalParameter -ParameterName "prr" -Value "enabled"
    Set-TcpGlobalParameter -ParameterName "pacingprofile" -Value "off"

    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host " ✅ GLOBÁLNÍ GAMING OPTIMALIZACE ÚSPĚŠNĚ APLIKOVÁNY!" -ForegroundColor Green
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "💡 TIP: Nezapomeňte také zkontrolovat 'Optimalizace Nagle' [4]" -ForegroundColor Yellow
    Write-Host "   pro specifické adaptéry (TcpAckFrequency, TCPNoDelay)!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# --- Funkce pro obnovu výchozích hodnot ---
function Restore-DefaultTCPSettings {
    Clear-Host
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Yellow
    Write-Host "  🔄 OBNOVUJI GLOBÁLNÍ VÝCHOZÍ TCP/IP NASTAVENÍ WINDOWS" -ForegroundColor Yellow
    Write-Host "=======================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Resetuji všech 8 parametrů na výchozí hodnoty..." -ForegroundColor Cyan
    Write-Host ""

    Set-TcpGlobalParameter -ParameterName "rss" -Value "default"
    Set-TcpGlobalParameter -ParameterName "autotuninglevel" -Value "default"
    Set-TcpGlobalParameter -ParameterName "ecncapability" -Value "default"
    Set-TcpGlobalParameter -ParameterName "timestamps" -Value "default"
    Set-TcpGlobalParameter -ParameterName "rsc" -Value "default"
    Set-TcpGlobalParameter -ParameterName "hystart" -Value "default"
    Set-TcpGlobalParameter -ParameterName "prr" -Value "default"
    Set-TcpGlobalParameter -ParameterName "pacingprofile" -Value "default"

    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Green
    Write-Host "   ✅ GLOBÁLNÍ VÝCHOZÍ NASTAVENÍ ÚSPĚŠNĚ OBNOVENO!" -ForegroundColor Green
    Write-Host "=======================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "⚠️  POZNÁMKA: Toto neobnovuje specifické tweaky adaptérů (Nagle)." -ForegroundColor Yellow
    Write-Host "   Použijte menu [4] pro reset Nagle na konkrétních adaptérech." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Stiskněte klávesu pro návrat do menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-MyDNS {
    Clear-Host
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "          📋 MOJE DNS - DETAILNÍ ZOBRAZENÍ" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ""

    try {
        $allAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

        if ($allAdapters.Count -eq 0) {
            Write-Warning "Žádné aktivní síťové adaptéry nebyly nalezeny."
        } else {
            foreach ($adapter in $allAdapters) {
                Write-Host "Adaptér: " -NoNewline -ForegroundColor Yellow
                Write-Host "$($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor White
                Write-Host "Status: " -NoNewline -ForegroundColor Yellow
                Write-Host "$($adapter.Status)" -ForegroundColor Green
        Write-Host ""

                # IPv4 DNS
                $dnsIPv4 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
                if ($null -ne $dnsIPv4 -and $dnsIPv4.ServerAddresses.Count -gt 0) {
                    Write-Host "  IPv4 DNS servery:" -ForegroundColor Cyan
                    foreach ($dns in $dnsIPv4.ServerAddresses) {
                        Write-Host "    - $dns" -ForegroundColor White
                    }
                } else {
                    Write-Host "  IPv4 DNS: " -NoNewline -ForegroundColor Cyan
                    Write-Host "DHCP (Automaticky)" -ForegroundColor Gray
                }

                # IPv6 DNS
                $dnsIPv6 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue
                if ($null -ne $dnsIPv6 -and $dnsIPv6.ServerAddresses.Count -gt 0) {
                    Write-Host "  IPv6 DNS servery:" -ForegroundColor Cyan
                    foreach ($dns in $dnsIPv6.ServerAddresses) {
                        Write-Host "    - $dns" -ForegroundColor White
                    }
                }

                Write-Host "--------------------------------------------------" -ForegroundColor Gray
                Write-Host ""
            }
        }

        # DNS Cache statistiky
        Write-Host "DNS Cache statistiky:" -ForegroundColor Yellow
        try {
            $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
            if ($null -ne $dnsCache) {
                $cacheCount = ($dnsCache | Measure-Object).Count
                Write-Host "  Počet záznamu v cache: $cacheCount" -ForegroundColor White
            }
    } catch {
            Write-Host "  Není dostupné" -ForegroundColor Gray
        }

    } catch {
        Write-Warning "Chyba při získávání DNS informací: $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Gray
    Write-Host "[C]  Vyčistit DNS Cache" -ForegroundColor Magenta
    Write-Host "[Q]  Zpět do DNS menu" -ForegroundColor Red
    Write-Host ""

    $choice = Read-Host -Prompt "Zadejte svou volbu"

    if ($choice -eq 'C' -or $choice -eq 'c') {
        Clear-DNSCacheMenu
        # Po vyčištění znovu zobraz aktuální stav
        Show-MyDNS
    }
}

function Clear-DNSCacheMenu {
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Magenta
    Write-Host "          🗑️  VYČISTIT DNS CACHE" -ForegroundColor Magenta
    Write-Host "==================================================" -ForegroundColor Magenta
    Write-Host ""

    try {
        # Zjisti počet záznamů před vyčištěním
        $cacheBefore = Get-DnsClientCache -ErrorAction SilentlyContinue
        $countBefore = 0
        if ($null -ne $cacheBefore) {
            $countBefore = ($cacheBefore | Measure-Object).Count
        }

        Write-Host "Aktuální počet záznamů v cache: " -NoNewline -ForegroundColor Yellow
        Write-Host "$countBefore" -ForegroundColor White
        Write-Host ""

        if ($countBefore -eq 0) {
            Write-Host "DNS cache je již prázdná." -ForegroundColor Green
        } else {
            Write-Host "Opravdu chcete vyčistit DNS cache?" -ForegroundColor Yellow
            Write-Host "[A] Ano - Vyčistit cache" -ForegroundColor Green
            Write-Host "[N] Ne - Zrušit" -ForegroundColor Red
            Write-Host ""

            $confirmation = Read-Host -Prompt "Zadejte svou volbu"

            if ($confirmation -eq 'A' -or $confirmation -eq 'a') {
                Write-Host ""
                Write-Host "Vyčišťuji DNS cache..." -ForegroundColor Cyan

                Clear-DnsClientCache -ErrorAction Stop

                # Počkej chvíli a znovu zkontroluj
                Start-Sleep -Milliseconds 500
                $cacheAfter = Get-DnsClientCache -ErrorAction SilentlyContinue
                $countAfter = 0
                if ($null -ne $cacheAfter) {
                    $countAfter = ($cacheAfter | Measure-Object).Count
                }

                Write-Host ""
                Write-Host "==================================================" -ForegroundColor Green
                Write-Host "✅ DNS CACHE BYLA ÚSPĚŠNĚ VYČIŠTĚNA!" -ForegroundColor Green
                Write-Host "==================================================" -ForegroundColor Green
                Write-Host ""
                Write-Host "Před vyčištěním: $countBefore záznamů" -ForegroundColor White
                Write-Host "Po vyčištění: $countAfter záznamů" -ForegroundColor White
                Write-Host ""
                Write-Host "POZNÁMKA: Nové DNS dotazy budou trvat o něco déle," -ForegroundColor Yellow
                Write-Host "          než se cache znovu naplní." -ForegroundColor Yellow
            } else {
                Write-Host ""
                Write-Host "Vyčištění DNS cache bylo zrušeno." -ForegroundColor Yellow
            }
        }

    } catch {
        Write-Warning "Chyba při vyčištění DNS cache: $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "Stiskněte klávesu pro pokračování..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Set-CustomDNS {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Provider,

        [Parameter(Mandatory=$false)]
        [int]$SpecificAdapter = -1
    )

    Write-Host ""
    if ($SpecificAdapter -ne -1) {
        Write-Host "Nastavuji DNS pro: $Provider (konkrétní adaptér)..." -ForegroundColor Yellow
    } else {
        Write-Host "Nastavuji DNS pro: $Provider (všechny adaptéry)..." -ForegroundColor Yellow
    }

    # Embedded DNS data
    $dnsJsonData = @'
{
    "Google":{
        "Primary": "8.8.8.8",
        "Secondary": "8.8.4.4",
        "Primary6": "2001:4860:4860::8888",
        "Secondary6": "2001:4860:4860::8844"
    },
    "Cloudflare":{
        "Primary": "1.1.1.1",
        "Secondary": "1.0.0.1",
        "Primary6": "2606:4700:4700::1111",
        "Secondary6": "2606:4700:4700::1001"
    },
    "Cloudflare_Malware":{
        "Primary": "1.1.1.2",
        "Secondary": "1.0.0.2",
        "Primary6": "2606:4700:4700::1112",
        "Secondary6": "2606:4700:4700::1002"
    },
    "Cloudflare_Malware_Adult":{
        "Primary": "1.1.1.3",
        "Secondary": "1.0.0.3",
        "Primary6": "2606:4700:4700::1113",
        "Secondary6": "2606:4700:4700::1003"
    },
    "Open_DNS":{
        "Primary": "208.67.222.222",
        "Secondary": "208.67.220.220",
        "Primary6": "2620:119:35::35",
        "Secondary6": "2620:119:53::53"
    },
    "Quad9":{
        "Primary": "9.9.9.9",
        "Secondary": "149.112.112.112",
        "Primary6": "2620:fe::fe",
        "Secondary6": "2620:fe::9"
    },
    "AdGuard_Ads_Trackers":{
        "Primary": "94.140.14.14",
        "Secondary": "94.140.15.15",
        "Primary6": "2a10:50c0::ad1:ff",
        "Secondary6": "2a10:50c0::ad2:ff"
    },
    "AdGuard_Ads_Trackers_Malware_Adult":{
        "Primary": "94.140.14.15",
        "Secondary": "94.140.15.16",
        "Primary6": "2a10:50c0::bad1:ff",
        "Secondary6": "2a10:50c0::bad2:ff"
    },
    "dns0.eu_Open":{
        "Primary": "193.110.81.254",
        "Secondary": "185.253.5.254",
        "Primary6": "2a0f:fc80::ffff",
        "Secondary6": "2a0f:fc81::ffff"
    },
    "dns0.eu_ZERO":{
        "Primary": "193.110.81.9",
        "Secondary": "185.253.5.9",
        "Primary6": "2a0f:fc80::9",
        "Secondary6": "2a0f:fc81::9"
    },
    "dns0.eu_KIDS":{
        "Primary": "193.110.81.1",
        "Secondary": "185.253.5.1",
        "Primary6": "2a0f:fc80::1",
        "Secondary6": "2a0f:fc81::1"
    }
}
'@

    try {
        $dnsData = $dnsJsonData | ConvertFrom-Json

        if (-not $dnsData.PSObject.Properties[$Provider]) {
            Write-Warning "Provider '$Provider' nebyl nalezen v konfiguraci!"
            Write-Host "Stisknete klavesu pro pokracovani..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }

        $selectedDNS = $dnsData.$Provider
        $primaryDNS = $selectedDNS.Primary
        $secondaryDNS = $selectedDNS.Secondary

        # Ziskej aktivni sitove adaptery
        $adapters = @()

        if ($SpecificAdapter -ne -1) {
            # Použij jen specifický adaptér
            $adapters = @(Get-NetAdapter | Where-Object { $_.ifIndex -eq $SpecificAdapter })
            if ($adapters.Count -eq 0) {
                Write-Warning "Adaptér s InterfaceIndex $SpecificAdapter nebyl nalezen!"
                Write-Host "Stisknete klavesu pro pokracovani..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                return
            }
        } else {
            # Použij všechny aktivní adaptéry
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual|VPN|Loopback' }

        if ($adapters.Count -eq 0) {
            Write-Warning "Nebyly nalezeny zadne aktivni sitove adaptery!"
            Write-Host "Stisknete klavesu pro pokracovani..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
            }
        }

        foreach ($adapter in $adapters) {
            Write-Host "  Nastavuji DNS pro adapter: $($adapter.Name)..." -ForegroundColor Cyan

            # Nastav IPv4 DNS
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($primaryDNS, $secondaryDNS) -ErrorAction SilentlyContinue

            Write-Host "    IPv4 DNS: $primaryDNS, $secondaryDNS" -ForegroundColor Green
        }

        # Vyprazdni DNS cache
        Write-Host "  Prazdnim DNS cache..." -ForegroundColor Cyan
        Clear-DnsClientCache -ErrorAction SilentlyContinue

        Write-Host ""
        Write-Host "DNS uspesne nastaveno na: $Provider" -ForegroundColor Green
        Write-Host "  Primarni: $primaryDNS" -ForegroundColor White
        Write-Host "  Sekundarni: $secondaryDNS" -ForegroundColor White

    }
    catch {
        Write-Warning "Chyba pri nastavovani DNS: $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "Stisknete klavesu pro pokracovani..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Reset-DNSToAutomatic {
    Write-Host ""
    Write-Host "Resetuji DNS na automaticke (DHCP)..." -ForegroundColor Yellow

    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual|VPN|Loopback' }

        if ($adapters.Count -eq 0) {
            Write-Warning "Nebyly nalezeny zadne aktivni sitove adaptery!"
            Write-Host "Stisknete klavesu pro pokracovani..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }

        foreach ($adapter in $adapters) {
            Write-Host "  Resetuji DNS pro adapter: $($adapter.Name)..." -ForegroundColor Cyan
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        }

        # Vyprazdni DNS cache
        Write-Host "  Prazdnim DNS cache..." -ForegroundColor Cyan
        Clear-DnsClientCache -ErrorAction SilentlyContinue

        Write-Host ""
        Write-Host "DNS uspesne resetovano na automaticke (DHCP)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Chyba pri resetovani DNS: $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "Stisknete klavesu pro pokracovani..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
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

    Show-NetworkOptimizationMenu
}

Export-ModuleMember -Function @(
    'Show-DNSMenu', 'Show-MyDNS', 'Clear-DNSCacheMenu', 'Set-CustomDNS', 'Reset-DNSToAutomatic', 'Invoke-DNSFlush',
    'Show-TCPOptimizationMenu', 'Set-GamingTCPSettings', 'Restore-DefaultTCPSettings', 'Set-TcpGlobalParameter',
    'Show-AutoTuningLevelMenu', 'Show-ECNCapabilityMenu', 'Show-TimestampsMenu', 'Show-RSCMenu',
    'Show-HystartMenu', 'Show-PRRMenu', 'Show-PacingProfileMenu', 'Show-ManualNetshMenu',
    'Show-RSSMenu', 'Set-NagleInterfaceTweak', 'Show-NagleTweakMenu',
    'Invoke-WinsockReset', 'Invoke-IPReset', 'Invoke-TCPReset', 'Invoke-IPRelease', 'Invoke-IPRenew',
    'Invoke-AdapterResetMenu', 'Reset-Network', 'Invoke-NetworkResetCore', 'Show-NetworkOptimizationMenu',
    'Invoke-ModuleEntry'
)


