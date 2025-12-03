# Krake-FIX: Expertní Optimalizátor Systému Windows pro Herní Výkon

[![Version](https://img.shields.io/badge/Version-2.0-blue.svg)](https://github.com/KrakeCZ/Krake-FIX/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://learn.microsoft.com/en-us/powershell/)
[![Windows 10/11](https://img.shields.io/badge/Windows-10%2F11-green.svg)](https://www.microsoft.com/en-us/windows)
[![GitHub Issues](https://img.shields.io/github/issues/KrakeCZ/Krake-FIX.svg)](https://github.com/KrakeCZ/Krake-FIX/issues)
=============================================================
**Krake-FIX** je expertní skript určený pro agresivní debloat a optimalizaci systému Windows. Je navržen specificky pro pokročilé uživatele, administrátory připravující referenční image, nebo pro nasazení na specializovaných herních (esports) stanicích, kde je vyžadována minimalizace systémových procesů a dosažení maximálního výkonu s minimální latencí.

Ultimátní optimalizační toolkit pro Windows zaměřený na kompetitivní hraní, minimální latenci a konzistentní FPS. Tento nástroj je navržen pro maximální výkon na herních a testovacích stanicích. 
⚠️❗️**NENÍ určen pro pracovní počítače nebo systémy s citlivými daty.**⚠️❗️

 **⚡ POUŽÍVEJ NA VLASTNÍ RIZIKO ⚡** - Tento nástroj je určený pro: Herní PC (e-sports, competitive, casual), Testovací prostředí, Dual-boot systémy s testovacím OS, Pokročilé uživatele, kteří rozumí rizikům.
> - 
> -⚠️❗️ **NENÍ doporučený pro:** ⚠️❗️
❗️Pracovní počítače, Systémy s citlivými daty, Sdílené/veřejné počítače, Systémy vyžadující maximální zabezpečení.❗️

## Funkce
- **🎮 Herní optimalizace**: Snížení input lagu, zvýšení FPS, optimalizace CPU/GPU.  
- **🗑️ Windows debloating**: Odstranění bloatwaru, vypnutí telemetrie, čištění AppX balíčků.  
- **🌐 Síťové úpravy**: TCP/IP optimalizace, konfigurace DNS, ladění Nagle algoritmu.  
- **🔒 Kontrola soukromí**: Vypnutí trackingu, telemetrie, kontrola Windows Update.  
- **⚡ Zvýšení výkonu**: CPU mitigace OFF, MMCSS ladění, optimalizace paměti.  
- **🛡️ Bezpečnostní možnosti**: Kontrola VBS/HVCI, správa Defenderu, LSA, TSX Protection.


=============================================================
> **⚠️ DŮLEŽITÁ VAROVÁNÍ**  
> Tento nástroj provádí hloubkové změny v konfiguraci systému Windows.
> Je určen výhradně pro expertní uživatele na osobních (herních/testovacích) počítačích.
> 
> - **VYPÍNÁ BEZPEČNOST**: Modul Security (chráněný heslem) je navržen tak, aby vypnul systémové ochrany jako CPU Mitigace (Spectre/Meltdown), VBS, HVCI (Integrita jádra), LSA Protection.
> - 
> - **AGRESIVNÍ DEBLOAT**: Režim Tweak C trvale odstraní základní systémové aplikace, včetně Xbox aplikací, Kalkulačky a Fotek (využij [RestoreOLD_Windows_Photo_Viewer_CURRENT_USER.reg](RestoreOLD_Windows_Photo_Viewer_CURRENT_USER.reg) pro obnovu Photo Vieweru).
> - 
> - **BLOKACE SYSTÉMU**: Modul MEBlock (Microsoft Edge Block) používá ACL zámky k zakázání (DENY) přístupu pro SYSTEM a TrustedInstaller, aby se zabránilo automatické opravě Edge.
> - 
> - **VYTVOŘTE ZÁLOHU**: Před použitím vždy vytvořte bod obnovení systému nebo kompletní bitovou kopii disku. Ideálně vytvoření bootovacího USB klíče s Acronis True Image 2021. Práce pro RUFUS.
> - 
> - **POUŽÍVÁTE NA VLASTNÍ RIZIKO**: Autor nenese žádnou odpovědnost za ztrátu dat nebo poškození systému.  
> - **MS Store obnova**: Instalace Xbox app z MS webu vyvolá závislost instalace MS Store! Odebral jsem odinstalaci MS Store, ale pokud potřebuješ – reinstaluj z webu MS Xbox app.
> - 
> - **HOSTS blokování**: Pokud použiješ HOSTS – Tvůj antivirus může falešně ohlasit tuto akci jako nebezpečnou! Důvod: Blokování Microsoft domén (a-msedge.net, activity.windows.com atd., a 0.0.0.0). Historicky populární metoda, ale v moderních Windows ji Defender detekuje jako SettingsModifier:Win32/HostsFileHijack. Doporučuji registry/služby místo HOSTS. Výchozí obsah HOSTS pro obnovu: (zde plný text výchozího HOSTS souboru).
> - 
> - **Tento nástroj mění základní systémová nastavení!!!**  
> - **NE pro produkční systémy** - Pouze pro herní/testovací počítače.  
> - **Bezpečnostní funkce vypnuty** - Některé moduly vypínají Windows Defender, VBS, HVCI.  
> - **Změny systému** - Registry, služby, bcdedit operace, ACL změny.  
> - **Vytvoř zálohy** - Vždy vytvořte bod obnovení systému před použitím.  
> - **Restart nutný** - Většina úprav vyžaduje restart PC.  
> - **Antivirus vypnutý** - Některé konfigurace vypínají ochranu v reálném čase viz security sekce!
> - 
> - **⚡ POUŽÍVEJ NA VLASTNÍ RIZIKO ⚡** - Tento nástroj je určený pro: Herní PC (e-sports, competitive, casual), Testovací prostředí, Dual-boot systémy s testovacím OS, Pokročilé uživatele, kteří rozumí rizikům.
> - 
> -⚠️❗️ **NENÍ doporučený pro:** Pracovní počítače, Systémy s citlivými daty, Sdílené/veřejné počítače, Systémy vyžadující maximální zabezpečení.❗️
>
> - 
> - **POZOR hPET**: Není vhodný pro moderní CPU!!! Pokud bude Win slowmo, dej zpět – nastavil si to v sekci 7!
> - 
> - **Změňte condrv typ spouštění služby (pokročilí uživatele)**: Chyba je často spojena s tím, že condrv se služba nespustí automaticky, když je potřeba. Otevřete Editor registru zadáním regedit vyhledávacího dotazu do nabídky Start a spuštěním jako správce.
> -  Přejděte k následující klávese: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv. V pravém podokně vyhledejte Start položku. Dvakrát klikněte Start a změňte jeho hodnotu z 3 (manuální) na 2 (automatické). Restartujte počítač, aby se změna projevila.

- 
Pokud Použiješ HOSTS - Tvuj antivirus muze FALESNE ohlasit tuto akci jako nebezpecnou!
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

 
> - **Tento nástroj mění základní systémová nastavení!!!**  
> - **NE pro produkční systémy** - Pouze pro herní/testovací počítače.  
> - **Bezpečnostní funkce vypnuty** - Některé moduly vypínají Windows Defender, VBS, HVCI.  
> - **Změny systému** - Registry, služby, bcdedit operace, ACL změny.  
> - **Vytvoř zálohy** - Vždy vytvořte bod obnovení systému před použitím.  
> - **Restart nutný** - Většina úprav vyžaduje restart PC.  
> - **Antivirus vypnutý** - Některé konfigurace vypínají ochranu v reálném čase viz security sekce!
> - 
> - **⚡ POUŽÍVEJ NA VLASTNÍ RIZIKO ⚡** - Tento nástroj je určený pro: Herní PC (e-sports, competitive, casual), Testovací prostředí, Dual-boot systémy s testovacím OS, Pokročilé uživatele, kteří rozumí rizikům.  
> - **NENÍ doporučený pro:** Pracovní počítače, Systémy s citlivými daty, Sdílené/veřejné počítače, Systémy vyžadující maximální zabezpečení.  
> - **POZOR hPET**: Není vhodný pro moderní CPU!!! Pokud bude Win slowmo, dej zpět – nastavil si to v sekci 7!  
> - **Změňte condrv typ spouštění služby (pokročilí uživatele)**: Chyba je často spojena s tím, že condrv se služba nespustí automaticky, když je potřeba. Otevřete Editor registru zadáním regedit vyhledávacího dotazu do nabídky Start a spuštěním jako správce. Přejděte k následující klávese: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv. V pravém podokně vyhledejte Start položku. Dvakrát klikněte Start a změňte jeho hodnotu z 3 (manuální) na 2 (automatické). Restartujte počítač, aby se změna projevila.

## Moduly
Skript je modulární – všechny moduly jsou v [/Modules](https://github.com/KrakeCZ/Krake-FIX/tree/main/Modules). Zde je přehled:
```
| Modul Název | Popis |
|-------------|-------|
| AMD_Opt.psm1 | Optimalizace pro AMD GPU (latency, performance, stability tweaks). |
| Core.psm1 | Základní knihovna funkcí, oprávnění, logování. |
| Debloat.psm1 | Debloat úrovně (light/medium/heavy), registry tweaks bez mazání app. |
| Diagnostics.psm1 | Systémová diagnostika, CPU/RAM/GPU info, dump analýza. |
| Edge_Block.psm1 | Blokace MS Edge (registry/IFEO/ACL). |
| Gaming_Core.psm1 | IO page lock, priorita procesů, fix input lagu. |
| GPU_Adv.psm1 | Podpora HAGS, Game Mode, MPO, ReBAR. |
| GPU_Base.psm1 | Obecné GPU optimalizace. |
| Intel_Opt.psm1 | Registry tweaks pro Intel GPU. |
| MMCSS_Tuner.psm1 | Optimalizace Multimedia Class Scheduler (Affinity pro Game/Audio/Display). |
| Net_Stack.psm1 | TCP/IP optimalizace, vypnutí Nagle, DNS. |
| No_Track.psm1 | Blokace sběru dat a diagnostiky (HOSTS). |
| NVIDIA_Opt.psm1 | Registry tweaks pro NVIDIA GPU. |
| Photo_Viewer.psm1 | Obnovení starého Windows Photo Vieweru. |
| Power_Ult.psm1 | Aktivace Ultimate Performance planu, unpark jader. |
| PreTweak.psm1 | Kontrola systému před aplikací tweaků (PsExec/LanmanServer). |
| Restore_Pt.psm1 | Nástroje pro opravu Windows (DISM, SFC, CHKDSK). |
| Sec_Core.psm1 | Vypnutí Spectre/Meltdown, VBS, Hyper-V, Defender. |
| Svc_Reset.psm1 | Obnova služeb do výchozího stavu. |
| Sys_Opt.psm1 | Win32PrioritySeparation, optimalizace klávesnice/myši. |
| Win_Update.psm1 | Správa Windows Update (vypnutí/zapnutí/přizpůsobení). |
```
Celkem 28 modulů s 277+ tweaky. Každý modul má zdrojový kód v [/Modules](https://github.com/KrakeCZ/Krake-FIX/tree/main/Modules).

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

2. **Příprava**:  
- Vytvoř bod obnovy: `rstrui.exe`.  
- Nastav Execution Policy (jako Admin):
- `Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope CurrentUser -Force`
- `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force`


Po použití vrať zpět: `Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force`.  
Pro lokální skripty: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force`.

3. **Spuštění**:  
=============================================================
- Zkopíruj `Main.ps1` a složku `Modules` na `C:\`.  
- Spusť jako Admin: `C:\Main.ps1`.  
- Proveď **Pre-Tweak kontrolu** (volba [0]).
=============================================================

4. **Příklady Aplikace Tweaks**:  
=============================================================
- [1] Obecné tweaky: Vyber variantu A/B/C.  
- [2] GPU tweaky: Vyber podle výrobce (NVIDIA/AMD/Intel).  
- [12] Síťové optimalizace: Nagle, TCP/IP.  
- [17] Nastavení priorit pro hry a audio.  
- [3] Win32PrioritySeparation: Esports/Gaming.  
- [7] Security Hazard Tweaks: Heslo pro přístup.  
- Po aplikaci **restartuj PC**.
=============================================================

## Obnova Změn
=============================================================
- **Rychlá Obnova**: Použij bod obnovy systému.  
- V skriptu:  
- [6] Obnovit bezpečné výchozí nastavení (Security).  
- [1] → [R] Reset služeb.  
- [13] → [6] Oprava Windows Update.  
- [16] → [R] Odblokování Edge (ACL unlock).  
- Další: `RestoreOLD_Windows_Photo_Viewer_CURRENT_USER.reg` pro Photo Viewer.  
- Pro condrv službu: Uprav registry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv, změň Start z 3 na 2.
=============================================================

## FAQ
```
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

---
