<p align="center">
  <img src="Screenshots/Logo.jpg" width="520" alt="Screenshot 5"/>


# Krake-FIX 🚀: Expertní Optimalizátor Systému Windows pro Herní Výkon
[![Version](https://img.shields.io/badge/Version-2.0-blue.svg)](https://github.com/KrakeCZ/Krake-FIX/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://learn.microsoft.com/en-us/powershell/)
[![Windows 10/11](https://img.shields.io/badge/Windows-10%2F11-green.svg)](https://www.microsoft.com/en-us/windows)
[![GitHub Issues](https://img.shields.io/github/issues/KrakeCZ/Krake-FIX.svg)](https://github.com/KrakeCZ/Krake-FIX/issues)
============================================================
**Krake-FIX 🚀** je expertní skript určený pro agresivní debloat a optimalizaci systému Windows. Je navržen specificky pro pokročilé uživatele, administrátory připravující referenční image, nebo pro nasazení na specializovaných herních (esports) stanicích, kde je vyžadována minimalizace systémových procesů a dosažení maximálního výkonu s minimální latencí.

Ultimátní optimalizační toolkit pro Windows zaměřený na kompetitivní hraní, minimální latenci a konzistentní FPS. Tento nástroj je navržen pro maximální výkon na herních a testovacích stanicích. 
============================================================
> -  👉🌐 https://krakecz.github.io/Krake-FIX/ 🌐👈
>
> -  info📚 : https://notebooklm.google.com/notebook/e9f6f421-47e4-4839-80e6-b5ccae4149bb 👈
 
> - ## ⚠️❗️ Upozornění na PsExec (Microsoft Sysinternals)⚠️❗️

> - Krake-FIX 🚀 obsahuje soubor psexec64.exe 👈 jedná se o oficiální nástroj z Microsoft Sysinternals.
- Originál stáhní:👉🌐 https://learn.microsoft.com/cs-cz/sysinternals/downloads/psexec ❗️
- instalace kopiruj pouze "psexec64.exe" z balíku SysInternals z webu Microsoft !
              └──do místa->/Modules/Bin/PsExec/Psexec64.exe
  
> - Některé antiviry a služby (např. VirusTotal) mohou PsExec označit jako „HackTool“💡❗️.
> - Jde o běžnou heuristiku u nástrojů s vyššími oprávněními; neznamená to automaticky, že je Krake-FIX škodlivý.

> ⚠️ Krake-FIX používá Psexec64.exe výhradně k získání oprávnění TrustedInstaller a k provedení systémových úkonů (správa služeb, úloh,WinUpdate, aplikace konfigurací).
> -  Bez této elevace nelze získat potřebný token(oprávnění Ntsystem TrustedInstaller).
> -  viz zdrojový kód v [/Core.psm1](https://github.com/KrakeCZ/Krake-FIX/blob/main/Modules/Core.psm1).

> - Pokud jste Krake-FIX stáhli z oficiálního GitHub repozitáře, jsou tato upozornění očekávatelná. 
> - Pro Vaši jistotu si stáhněte originální "PsExec64.exe" z odkazu výše
> - 👉 nahraďte pouze "psexec64.exe" ve složce "Modules/Bin/PsExec/PsExec64.exe".

Doporučení:
> -  Stahujte jen z oficiálních zdrojů.
> -  Pokud antivir hlásí „HackTool“, nepanikařte — často jde o falešný poplach.
> -  Máte-li pochybnosti, nahraďte "psexec64.exe" oficiální verzí❗️👇
> -  🌐 👉https://learn.microsoft.com/cs-cz/sysinternals/downloads/psexec 👈✅️

> -  ⚠️❗️**NENÍ určen pro pracovní počítače nebo systémy s citlivými daty.**⚠️❗️
> - **⚡ POUŽÍVEJ NA VLASTNÍ RIZIKO ⚡**
> -  Tento nástroj je určený pro: Herní PC (e-sports, competitive, casual), Testovací prostředí, Dual-boot systémy s testovacím OS, Pokročilé uživatele, kteří rozumí rizikům.
> - ⚠️❗️ **NENÍ doporučený pro:** ⚠️❗️
> -  ❗️🛡️ Pracovní počítače, Systémy s citlivými daty, Sdílené/veřejné počítače, Systémy vyžadující maximální zabezpečení.❗️
> -
==================================================================

## Funkce
- **🎮 Herní optimalizace**: Snížení input lagu, stabilní nebo zvýšení FPS, optimalizace CPU/GPU.  
- **🗑️ Windows debloating**: Odstranění bloatwaru, vypnutí telemetrie, čištění AppX balíčků.  
- **🌐 Síťové úpravy**: TCP/IP optimalizace, konfigurace DNS, ladění Nagle algoritmu.  
- **🔒 Kontrola soukromí**: Vypnutí trackingu, telemetrie, kontrola Windows Update.  
- **⚡ Zvýšení výkonu**: H.I.D,W32Prio,FSutil, MMCSS ladění, optimalizace paměti a disku.  
- **🛡️ Bezpečnostní možnosti**: CPU mitigace OFF/on, Kontrola VBS/HVCI, správa Defenderu, LSA, TSX Protection,Hpet.
      
<p align="center">
  <img src="Screenshots/shot001.png" width="400" alt="Screenshot 5"/>
  
==================================================================
# STRUKTURA
```
KRAKE-FIX (Root)
│
├──{ *** Execution Policy (Bypass required)***}
│
├── Main.ps1 (Spouštěcí soubor)
│
└>[ Modules/ ]  (Funkce a  Core)  
          │
          ├──> [ Bin/ (Externí binární exekutory)
          │        └ [PsExec/]
          │           ├──> PsExec64.exe  -> (Klíčový nástroj pro TrustedInstaller elevaci)
          │           └── PSEXEC64 info.txt  -> (Dokumentace k  původu)
          │             
          │                         *  CORE & SYSTEM INFRASTRUCTURE *
          ├── Core.psm1        -> (Knihovna funkcí, oprávnění, logování) 
          ├── PreTweak.ps1     -> (Validace závislostí: PsExec, LanmanServer pro TweakR)
          │
          │        * ((MODULY: jdou jednoduše uživatelsky upravit))*
          │ 
          │                 *  WINDOWS TWEAKS & DEBLOAT *
          ├── Tweak0.psm1      -> (Safe: Pouze registry, bez mazání AppX) (edit:Register)
          ├── TweakA.psm1      -> (Light: OEM Debloat + Safe registry) ( edit: Reg/AppxPackage )
          ├── TweakB.psm1      -> (Medium: Bloatware removal + Tweaks)(edit: Reg/AppX /task)
          ├── TweakC.psm1      -> (Heavy:Agresivní 90+ balíčků - Expert only)(EAppx /task/services)
          ├── TweakR.psm1      -> (Rollback: Obnova služeb do defaultu)/ (edit:services dle potřeby) 
          ├── TweakV.psm1      -> (Legacy: Windows Photo Viewer restore)
          ├── TweakT.psm1      -> (RollBack Task / úloh dle C / B )
          ├── TweakD.psm1      -> (Disk Optim Nvme Redistry + FSutil )
          │
          │     .    * HARDWARE OPTIMIZATION (GPU) *
          ├── GPU.psm1          -> (Univerzální GPU optimalizace)
          ├── GPU_Advanced.psm1 -> (HAGS, MPO, ReBAR, Game Mode)
          ├── GPU_NVIDIA.psm1   -> (NVIDIA Latency & Performance tweaks)
          ├── GPU_AMD.psm1      -> (Radeon Performance & Stability)
          ├── GPU_Intel.psm1    -> (Arc/UHD specific optimization)
          │
          │           * GAMING & LOW LATENCY *
          ├── System.psm1       -> (Win32Priority, HID Tuning, Mouse/KB Latency) (edit or add)
          ├── Gaming.psm1       -> (IO Page Lock,Universal, if not use tweak0/C, Input Lag Fix)
          ├── MMCSS.psm1        -> (Multimedia Class Scheduler & Affinity Audio/Game/Display)
          ├── PowerPlan.psm1    -> (Ultimate Performance, Unpark Cores) ( edit:  JsonPlan)
          ├── CoreParking.psm1  -> (Core Parking Access & Stability)  
          │
          │           * SECURITY & NETWORK *
          ├── Security.psm1    -> (Mitigace off: Spectre/Meltdown, VBS, Defender)
          ├── RevertHazard.psm1-> (Security Rollback)
          ├── Telemetry.psm1   -> (Data collection block, HOSTS tuning)
          ├── MEBlock.psm1     -> (Microsoft Edge IFEO/ACL Restriction)
          ├── Network.psm1     -> (TCP/IP tuning, Nagle's Algorithm off, DNS)
          │
          │           * MAINTENANCE & REPAIR *
          ├── Restore.psm1     -> (SFC, DISM, CHKDSK - Systémová integrita)
          ├── Updates.psm1     -> (Windows Update Management)
          ├── Utils.psm1       -> (Pomocné operace pro zálohování)
          ├── Data.psm1        -> (Univerzální  herní  konfigurace/Pomocné Gaming.psm1)
          └── Diagnostics.psm1 -> (Crash dump analýza, HW Health Check)
```
Každý modul má zdrojový kód v [/Modules](https://github.com/KrakeCZ/Krake-FIX/tree/main/Modules).

=====================================================   




    
> **⚠️ DŮLEŽITÁ VAROVÁNÍ**  
> Tento nástroj provádí hloubkové změny v konfiguraci systému Windows.
> Je určen výhradně pro expertní uživatele na osobních (herních/testovacích) počítačích.
 
> - **VYPÍNÁ BEZPEČNOST**: Modul Security (chráněný heslem) je navržen tak, aby vypnul systémové ochrany jako CPU Mitigace (Spectre/Meltdown), VBS, HVCI (Integrita jádra), LSA Protection. Defender , Aktualizace... 
 
> - **AGRESIVNÍ DEBLOAT**: Režim Tweak C trvale odstraní základní systémové aplikace, včetně Xbox aplikací, Kalkulačky a Fotek (využij [RestoreOLD_Windows_Photo_Viewer_CURRENT_USER.reg](RestoreOLD_Windows_Photo_Viewer_CURRENT_USER.reg) pro obnovu Photo Vieweru).
 
> - **BLOKACE SYSTÉMU**: Modul MEBlock (Microsoft Edge Block) používá ACL zámky k zakázání (DENY) přístupu pro SYSTEM a TrustedInstaller, aby se zabránilo automatické opravě Edge.
 
> - **VYTVOŘTE ZÁLOHU**: Před použitím vždy vytvořte bod obnovení systému nebo kompletní bitovou kopii disku. Ideálně vytvoření bootovacího USB klíče s Acronis True Image 2021 690mb ke stažení 👇 Práce pro RUFUS liveUSB.. 
   👉🌐<a href="https://dl.acronis.com/u/AcronisTrueImage2021.iso">https://dl.acronis.com/u/AcronisTrueImage2021.iso</a>
   
> - **POUŽÍVÁTE NA VLASTNÍ RIZIKO**: Autor nenese žádnou odpovědnost za ztrátu dat nebo poškození systému.  
> - **MS Store obnova**: Instalace Xbox app z MS webu vyvolá závislost instalace MS Store! Odebral jsem odinstalaci MS Store, ale pokud potřebuješ, edituj tweakC (přidej název Packages) , pak v případě potřeby – reinstaluj z webu MS Xbox app.
 
> - ⚠️** HOSTS blokování **: Pokud použiješ HOSTS – Tvůj antivirus může falešně ohlasit tuto akci jako nebezpečnou! Důvod: Blokování Microsoft domén (a-msedge.net, activity.windows.com atd., a 0.0.0.0). Historicky populární metoda, ale v moderních Windows ji Defender detekuje jako SettingsModifier:Win32/HostsFileHijack. Doporučuji registry/služby místo HOSTS. Výchozí obsah HOSTS pro obnovu: (zde plný text výchozího HOSTS souboru).
=====================================================    
❗️ **Tento nástroj mění základní systémová nastavení!!!**  
❗️ **NE pro produkční systémy** - Pouze pro herní/testovací počítače.  
❗️ **Bezpečnostní funkce vypnuty** - Některé moduly vypínají Windows Defender, VBS, HVCI.  
❗️ **Změny systému** - Registry, služby, bcdedit operace, ACL změny.  
💡 **Vytvoř zálohy** - Vždy vytvořte bod obnovení systému před použitím.  
❗️ **Restart nutný** - Většina úprav vyžaduje restart PC.  
❗️ **Antivirus vypnutý** - Některé konfigurace vypínají ochranu v reálném čase viz security sekce! 

> - **⚡ POUŽÍVEJ NA VLASTNÍ RIZIKO ⚡** - Tento nástroj je určený pro: Herní PC (e-sports, competitive, casual), Testovací prostředí, Dual-boot systémy s testovacím OS, Pokročilé uživatele, kteří rozumí rizikům.
>   
> -⚠️❗️ **NENÍ doporučený pro:** Pracovní počítače, Systémy s citlivými daty, Sdílené/veřejné počítače, Systémy vyžadující maximální zabezpečení.❗️
=====================================================   
> - 👇💡
> - **POZOR hPET**⏱️: Není vhodný pro moderní CPU!!! Pokud bude Win slowmo, dej zpět – nastavil si to v sekci 7!
>   👆💡
>   
> -BUG/chyba Terminal/ PowerShell
> **Změňte condrv typ spouštění služby (pokročilí uživatele)**:
> Chyba je často spojena s tím, že condrv se služba nespustí automaticky, když je potřeba. Otevřete Editor registru zadáním regedit vyhledávacího dotazu do nabídky Start a spuštěním jako správce.
> -  Přejděte k následující klávese: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv.
> -  V pravém podokně vyhledejte Start položku. Dvakrát klikněte Start a změňte jeho hodnotu z 3 (manuální) na 2 (automatické).
> -  Restartujte počítač, aby se změna projevila.
> -  
Pokud Použiješ HOSTS -> Tvuj antivirus muze FALESNE ohlasit tuto akci jako nebezpecnou!
Duvod: ## Blokování Microsoft domén
<details>
<summary>Klikněte pro zobrazení seznamu 40+ Microsoft domén blokovaných v HOSTS file</summary>

 Blokovani 40+ Microsoft domen v HOSTS file
Tyto domény jsou nastaveny na 0.0.0.0 a nebudou moci komunikovat:
Historicky populární metodou blokování telemetrie byla úprava souboru hosts (C:\Windows\System32\drivers\etc\hosts) za účelem přesměrování telemetrických serverů Microsoftu na lokální adresu 127.0.0.1. Tato metoda je však v moderních verzích Windows již z velké části neúčinná a problematická. Systém je schopen soubor hosts obejít a, co je důležitější, Microsoft Defender nyní aktivně detekuje takovéto úpravy jako bezpečnostní hrozbu SettingsModifier:Win32/HostsFileHijack. To nutí uživatele buď povolit "hrozbu" (čímž se oslabí legitimní bezpečnostní funkce) nebo se smířit s tím, že jeho změny budou vráceny zpět. Z těchto důvodů se dnes doporučuje upřednostnit spolehlivější a systémem tolerované metody deaktivace telemetrie prostřednictvím registru, služeb a naplánovaných úloh. Pro uživatele, kteří potřebují obnovit původní stav souboru hosts, je níže uveden jeho výchozí obsah.


Výchozí obsah souboru hosts:
 Copyright (c) 1993-2006 Microsoft Corp.

 This is a sample HOSTS file used by Microsoft TCP/IP for Windows.

 This file contains the mappings of IP addresses to host names. Each# entry should be kept on an individual line. The IP address should
 be placed in the first column followed by the corresponding host name.
 The IP address and the host name should be separated by at least one
 space.
 Additionally, comments (such as these) may be inserted on individual
 lines or following the machine name denoted by a '#' symbol.

 For example:

      102.54.94.97     rhino.acme.com          # source server
       38.25.63.10     x.acme.com              # x client host

 localhost name resolution is handle within DNS itself.
       127.0.0.1       localhost
       ::1             localhost
]

```
a-msedge.net
activity.windows.com
ad.doubleclick.net
bingads.microsoft.com
c.msn.com
cdn.optimizely.com
choice.microsoft.com
compatexchange.cloudapp.net
corp.sts.microsoft.com
diagnostics.support.microsoft.com
feedback.microsoft-hohm.com
feedback.search.microsoft.com
feedback.windows.com
flex.msn.com
g.msn.com
oca.telemetry.microsoft.com
pre.footprintpredict.com
rad.msn.com
redir.metaservices.microsoft.com
schemas.microsoft.akadns.net
settings-win.data.microsoft.com
sls.update.microsoft.com.akadns.net
sqm.df.telemetry.microsoft.com
sqm.telemetry.microsoft.com
statsfe1.ws.microsoft.com
statsfe2.update.microsoft.com.akadns.net
statsfe2.ws.microsoft.com
survey.watson.microsoft.com
telecommand.telemetry.microsoft.com
telemetry.appex.bing.net
telemetry.microsoft.com
telemetry.urs.microsoft.com
vortex-bn2.metron.live.com.nsatc.net
vortex-cy2.metron.live.com.nsatc.net
vortex.data.microsoft.com
vortex-win.data.microsoft.com
watson.microsoft.com
watson.ppe.telemetry.microsoft.com
watson.telemetry.microsoft.com
wes.df.telemetry.microsoft.com
134.170.30.202
137.116.81.24
157.56.106.189
184.86.53.99
204.79.197.200
23.218.212.69
65.39.117.230
65.55.108.23
64.4.54.254
```
</details>

## Moduly
Skript je modulární – všechny moduly jsou v [/Modules](https://github.com/KrakeCZ/Krake-FIX/tree/main/Modules). Zde je přehled:
```
| Modul Název | Popis |
|-------------|-------|
| Core.psm1 | Základní knihovna funkcí, oprávnění, logování. |
| CoreParking.psm1 | Zpřístupnění nabídky parkování jader v plánu napajení |
| Data.psm1 | Centrálni knihovna  pro systemová nastavení Gamming modulu. |
| Diagnostics.psm1 | Systémová diagnostika, CPU/RAM/GPU info, dump analýza. |
| GPU.psm1 | Obecné GPU optimalizace. |
| GPU_AMD.psm1 | Optimalizace pro AMD GPU (latency, performance, stability tweaks). |
| GPU_Advanced.psm1 | Podpora HAGS, Game Mode, MPO, ReBAR. |
| GPU_Intel.psm1 | Registry tweaks pro Intel GPU. |
| GPU_NVIDIA.psm1 | Registry tweaks pro NVIDIA GPU. |
| Gaming.psm1 | IO page lock, priorita procesů, fix input lagu. |
| MEBlock.psm1 | Blokace MS Edge (registry/IFEO/ACL). |
| MMCSS.psm1 | Optimalizace Multimedia Class Scheduler (Affinity pro Game/Audio/Display). |
| Network.psm1 | TCP/IP optimalizace, vypnutí Nagle, DNS. |
| PowerPlan.psm1 | Aktivace Ultimate Performance planu jako Vysoký výkon, Úsporný režim atd. |
| PreTweak.psm1 | Kontrola systému závislostí před aplikací tweaků (PsExec/LanmanServer). |
| Restore.psm1 | Nástroje pro opravu Windows (DISM, SFC, CHKDSK). |
| RevertHazard.psm1 | Obnova nastavení modulu Security.psm1. |
| Security.psm1 | Vypnutí Spectre/Meltdown, TSX/LSA, VBS, Hyper-V, Defender, WinUpdate |
| Telemetrie.psm1 | Blokace sběru dat a diagnostiky (HOSTS). |
| Tweak0.psm1 | Tweak pouze  registry bez mazání app. |
| TweakD.psm1 | Optimalizace NVMe + SSD samostatně  |
| TweakA.psm1 | Debloat úrovně (light), registry tweaks, OEM mazání app. |
| TweakB.psm1 | Debloat úrovně (medium), registry tweaks, OEM+BLOAT mazání app. |
| TweakC.psm1 | Debloat úrovně (heavy), registry tweaks,OEM+90 bez mazání app. možno přidat vlastní packages |
| TweakV.psm1 | Obnovení starého Windows Photo Vieweru. |
| TweakT.psm1 | Obnova Úloh / Task dle Tweak C   obnovi i z B  |
| TweakR.psm1 | Obnova služeb do výchozího stavu/Obsahuje všechny služby-jednoduše si uprav jak chceš|
| System.psm1 | Win32PrioritySeparation, optimalizace HID klávesnice/myši. |
| Updates.psm1 | Správa Windows Update (vypnutí/zapnutí/přizpůsobení). |
| Utils.psm1 | Pomocné funkce pro zálohovací operace.  |
```
Celkem 28 modulů s 277+ tweaky. Každý modul má zdrojový kód v [/Modules](https://github.com/KrakeCZ/Krake-FIX/tree/main/Modules).
=====================================================

## Systémové Požadavky
- **OS**: Windows 10 (1903+) nebo Windows 11 (25H2+).  
- **PowerShell**: 5.1 nebo novější.  
- **Oprávnění**: Plná administrátorská oprávnění.  
- **Doporučeno**: Bootovací USB s Acronis True Image pro zálohu.  
- **PsExec**: Skript používá psexec64.exe k získání tokenu pro nastavení služeb. Uživatel může stáhnout z webu https://learn.microsoft.com/cs-cz/sysinternals/downloads/psexec a nahradit ho Modules/Bin/Psexec64.exe.

## Instalace a Použití
1. **Stáhnout Repozitář**:  
git clone https://github.com/KrakeCZ/Krake-FIX.git
cd Krake-FIX


Nebo stáhni ZIP z [GitHubu](https://github.com/KrakeCZ/Krake-FIX).
stahni a extrahuj PsExec64.exe z [Microsoft](https://learn.microsoft.com/cs-cz/sysinternals/downloads/psexec)
 kopiruj pouze "psexec64.exe" z balíku do > /Modules/Bin/PsExec/Psexec64.exe 

2. **Příprava**:  
- Vytvoř bod obnovy: `rstrui.exe`.  
- Nastav Execution Policy (jako Admin):
- `Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope CurrentUser -Force`
- `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force`


Po použití vrať zpět: `Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force`.  
Pro lokální skripty: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force`.

3. **Spuštění**:  
=====================================================
- Zkopíruj `Main.ps1` a složku `Modules` na `C:\`.  
- Spusť Terminál / Powershell jako Admin: `C:\.\Main.ps1`.  
- Proveďaplikaci tweaku dle libosti Tweak0 jen registry atd.. 
=====================================================

4. **Příklady Aplikace Tweaks**:  
=====================================================
- [1] Obecné tweaky: Vyber variantu A/B/C.  
- [2] GPU tweaky: Vyber podle výrobce (NVIDIA/AMD/Intel).  
- [12] Síťové optimalizace: DNS, Nagle dle adaptéru, TCP/IP.  
- [17] Nastavení priorit pro hry a audio.  
- [3] Win32PrioritySeparation: Esports/Gaming.  
- [7] Security Hazard Tweaks: Heslo pro přístup.  
- Po aplikaci **restartuj PC**.
============================================================

## Obnova Změn
===============================================================
- **Rychlá Obnova**: Použij bod obnovy systému.  
- V skriptu:  
- [6] Obnovit bezpečné výchozí nastavení (Security [7]).  
- [1] → [R] Reset služeb všech Oem Windows.  
- [13] → [6] Oprava Windows Update.  
- [16] → [R] Odblokování Edge (ACL unlock).  
- Další: `RestoreOLD_Windows_Photo_Viewer_CURRENT_USER.reg` pro Photo Viewer.  
- Pro condrv službu: Uprav registry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv, změň Start z 3 na 2.
- 
===========================================================================================
## FAQ
```
- **Plánovač Úloh** - Některé Win10/11 sestavení- mohou u win update disable VYPNOUT Planovač úloh-
- FIX-CMD jako spravce :
 sc config Schedule start= auto
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Schedule" /v Start /t REG_DWORD /d 2 /f

- **Antivirus blokuje HOSTS?** Ano, falešný poplach kvůli blokaci MS domén. Přidej výjimku nebo dočasně vypni.  
- **Chyba s `condrv` službou?** Spusť [Restore_Pt] pro opravu.  
- **Proč vypnout Defender?** Pro nulovou latenci v hrách – ale jen na izolovaném PC!  
- **Kompatibilita s LTSC/Server?** Ano, testováno na Windows LTSC a Server 2022/2025, ale otestuj Pre-Check.  
- **Více info?** Podívej se na [Modules](https://github.com/KrakeCZ/Krake-FIX/tree/main/Modules) nebo web.
```

## Licence
MIT License – software poskytován „jak je“, bez záruk. Viz [LICENSE](LICENSE).


## 📄 License

```
MIT License

Copyright (c) 2025 KRAKE-FIX Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 📸 Screenshots první dva možná chyba a oprava 

<p align="center">
  <img src="Screenshots/shot-x1.png" width="400" alt="Screenshot 1"/>
  <img src="Screenshots/shot-x2.png" width="400" alt="Screenshot 2"/>
</p>

<p align="center">
  <img src="Screenshots/shot0.png" width="400" alt="Screenshot 3"/>
  <img src="Screenshots/shot000.png" width="400" alt="Screenshot 4"/>
</p>

<p align="center">
  <img src="Screenshots/shot001.png" width="400" alt="Screenshot 5"/>
  <img src="Screenshots/shot002.png" width="400" alt="Screenshot 6"/>
</p>

<p align="center">
  <img src="Screenshots/shot003.png" width="400" alt="Screenshot 7"/>
  <img src="Screenshots/shot004.png" width="400" alt="Screenshot 8"/>
</p>

<p align="center">
  <img src="Screenshots/shot005.png" width="400" alt="Screenshot 9"/>
  <img src="Screenshots/shot006.png" width="400" alt="Screenshot 10"/>
</p>

<p align="center">
  <img src="Screenshots/shot007.png" width="400" alt="Screenshot 11"/>
  <img src="Screenshots/shot008.png" width="400" alt="Screenshot 12"/>
</p>

<p align="center">
  <img src="Screenshots/shot009.png" width="400" alt="Screenshot 13"/>
  <img src="Screenshots/shot010.png" width="400" alt="Screenshot 14"/>
</p>

<p align="center">
  <img src="Screenshots/shot011.png" width="400" alt="Screenshot 15"/>
  <img src="Screenshots/shot012.png" width="400" alt="Screenshot 16"/>
</p>
<p align="center">
  <img src="Screenshots/shot033.png" width="400" alt="Screenshot 17"/>
</p>

<p align="center">
  <img src="Screenshots/shot013.png" width="400" alt="Screenshot 18"/>
  <img src="Screenshots/shot014.png" width="400" alt="Screenshot 19"/>
</p>

<p align="center">
  <img src="Screenshots/shot015.png" width="400" alt="Screenshot 20"/>
  <img src="Screenshots/shot016.png" width="400" alt="Screenshot 21"/>
</p>

<p align="center">
  <img src="Screenshots/shot017.png" width="400" alt="Screenshot 22"/>
  <img src="Screenshots/shot018.png" width="400" alt="Screenshot 23"/>
</p>

<p align="center">
  <img src="Screenshots/shot019.png" width="400" alt="Screenshot 24"/>
  <img src="Screenshots/shot020.png" width="400" alt="Screenshot 25"/>
</p>

<p align="center">
  <img src="Screenshots/shot021.png" width="400" alt="Screenshot 26"/>
  <img src="Screenshots/shot022.png" width="400" alt="Screenshot 27"/>
</p>

<p align="center">
  <img src="Screenshots/shot023.png" width="400" alt="Screenshot 28"/>
  <img src="Screenshots/shot024.png" width="400" alt="Screenshot 29"/>
</p>

<p align="center">
  <img src="Screenshots/shot025.png" width="400" alt="Screenshot 30"/>
  <img src="Screenshots/shot026.png" width="400" alt="Screenshot 31"/>
</p>

<p align="center">
  <img src="Screenshots/shot027.png" width="400" alt="Screenshot 32"/>
  <img src="Screenshots/shot028.png" width="400" alt="Screenshot 33"/>
</p>

<p align="center">
  <img src="Screenshots/shot029.png" width="400" alt="Screenshot 34"/>
  <img src="Screenshots/shot030.png" width="400" alt="Screenshot 35"/>
</p>

<p align="center">
  <img src="Screenshots/shot031.png" width="400" alt="Screenshot 36"/>
  <img src="Screenshots/shot032.png" width="400" alt="Screenshot 37"/>
</p>

<p align="center">
  <img src="Screenshots/shot034.png" width="400" alt="Screenshot 38"/>
</p>


---
 👉🌐 https://krakecz.github.io/Krake-FIX/ 🌐👈
