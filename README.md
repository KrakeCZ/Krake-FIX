🚀 Krake-FIX ⚡
expertní skript určený pro agresivní debloat a optimalizaci systému Windows. Je navržen specificky pro pokročilé uživatele, administrátory připravující referenční image, nebo pro nas[...]  

Ultimátní optimalizační toolkit pro Windows zaměřený na kompetitivní hraní, minimální latenci a konzistentnim FPS.  

Tento nástroj je navržen pro maximální výkon na herních a testovacích stanicích.  
NENÍ určen pro pracovní počítače nebo systémy s citlivými daty.  

🛡️ VYPÍNÁ BEZPEČNOST: Modul Security  (chráněný heslem) je navržen tak, aby vypnul systémové ochrany jako CPU Mitigace (Spectre/Meltdown), VBS, HVCI (Integrita jádra), LSA Protection[...]  

🗑️ AGRESIVNÍ DEBLOAT: Režim Tweak C  trvale odstraní základní systémové aplikace, včetně Microsoft Store(na vyžadaní,odebral jsem to), Xbox aplikací, Kalkulačky a Fotek (využij [...]  

⛔ BLOKACE SYSTÉMU: Modul MEBlock (Microsoft Edge Block) používá ACL zámky k zakázání (DENY) přístupu pro SYSTEM a TrustedInstaller , aby se zabránilo automatické opravě Edge.  

💾 VYTVOŘTE ZÁLOHU: Před použitím vždy vytvořte bod obnovení systému nebo kompletní bitovou kopii disku.  
ideálně "Vytvoření bootovacího USB klíče s Acronis True Image 2021. Práce pro RUFUS."  

⚡ Používáte na vlastní riziko. Autor nenese žádnou odpovědnost za ztrátu dat nebo poškození systému. ⚡  

Upozornění: Tento nástroj provádí hloubkové změny v konfiguraci systému Windows. Je určen výhradně pro expertní uživatele na osobních (herních/testovacích) počítačích. Před po[...]  

## ⚠️ **DŮLEŽITÁ VAROVÁNÍ**  
ms store obov - instalaci xboxapp z Mswebu , vyvolá závislost instalace MsStore!  
Odebral jsem odinstalaci MsStore.. ale kdyby-...  

### **TENTO NÁSTROJ MĚNÍ ZÁKLADNÍ SYSTÉMOVÁ NASTAVENÍ!!!**  
- ❌ **NE pro produkční systémy** - Pouze pro herní/testovací počítače  
- ⚠️ **Bezpečnostní funkce vypnuty** - Některé moduly vypínají Windows Defender, VBS, HVCI  
- 🔧 **Změny systému** - Registry, služby, bcdedit operace, ACL změny  
- 💾 **Vytvoř zálohy** - Vždy vytvořte bod obnovení systému před použitím  
- 🔄 **Restart nutný** - Většina úprav vyžaduje restart PC  
- 🛡️ **Antivirus vypnutý** - Některé konfigurace vypínají ochranu v reálném čase viz security sekce!   

### **⚡ POUŽÍVEJ NA VLASTNÍ RIZIKO ⚡**  
Tento nástroj je určený pro:  
- ✅ Herní PC (e-sports, competitive, casual)  
- ✅ Testovací prostředí  
- ✅ Dual-boot systémy s testovacím OS  
- ✅ Pokročilé uživatele, kteří rozumí rizikům  

**NENÍ doporučený pro:**  
- ❌ Pracovní počítače  
- ❌ Systémy s citlivými daty  
- ❌ Sdílené/veřejné počítače  
- ❌ Systémy vyžadující maximální zabezpečení  
## 🎯 Funkce  
### **Základní schopnosti**  
- 🎮 **Herní optimalizace** - Snížení input lagu, zvýšení FPS, optimalizace CPU/GPU  
- 🗑️ **Windows debloating** - Odstranění bloatwaru, vypnutí telemetrie, čištění AppX balíčků  
- 🌐 **Síťové úpravy** - TCP/IP optimalizace, konfigurace DNS, ladění Nagle algoritmu  
- 🔒 **Kontrola soukromí** - Vypnutí trackingu, telemetrie, kontrola Windows Update  
- ⚡ **Zvýšení výkonu** - CPU mitigace OFF, MMCSS ladění, optimalizace paměti  
- 🛡️ **Bezpečnostní možnosti** - Kontrola VBS/HVCI, správa Defenderu, LSA,TSX Protection  
-POZOR hPET- neni vhodny pro moderní CPU!!! pokud bude win slowmo dej zpět :D nastavil si to v sekci 7!  
---  
## 💻 Systémové požadavky OS: Windows 10 (1903+) nebo Windows 11 (25H2+). PowerShell: 5.1 nebo novější.  
*Oprávnění: Plná administrátorská oprávnění.   
```
1        Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope CurrentUser -Force  
2        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force  
 Zruší pravidlo pro uživatele (1) a poté povolí spuštění všech skriptů pro celý počítač (2).  
3. po Tweaku můžes vrátit práva zpět   
         Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force  
Pokud chcete mít možnost spouštět vlastní lokální skripty (ale stále blokovat ty stažené z internetu) :  
         Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force  
```  
Prostředí: Důrazně doporučeno na čisté instalaci Windows po aktualním Update ,  
použivám svůj nastroj  po aplikaci nástroje Winutil k blokaci telemetrie/služeb manualně atd..  
===============================================================================  
⚡ Jak Použít (Rychlý Start)  
```
Vytvořte Bod Obnovy: Než začnete, vytvořte bod obnovení systému!  
Spusťte Terminal / powershell  jako Administrátor.  
 Invoke-Expression "rstrui.exe"  
 po zaloze  umistění kde je Main.ps1 a složka modules , kopiruju na C:\  
cd C:\  
udělit opravnění *  
C:\.\Main.ps1  
Proveďte Pre-Tweak Kontrolu: V hlavním menu vyberte [0] PRE-TWEAK Kontrola závislostí . Tím zajistíte, že eskalace oprávnění bude fungovat správně.  
Aplikujte Debloat: Vyberte [1] Aplikovat obecné tweaky a zvolte úroveň (doporučeno Tweak A/B ] pro většinu hráčů, Tweak C  pro experty).  
```

=========================================================================================
Aplikujte Herní Tweaky:  
```
[2] GPU Tweaky -> Vyberte svého výrobce (NVIDIA, AMD, Intel) a aplikujte profily Latence nebo Výkonu.  
[12] Síťové optimalizace -> TCP/IP -> [4] Optimalizace Nagle (vypněte Nagle pro váš herní adaptér).  
[17] GAME + AUDIO Priority (MMCSS) -> [1] Upravit GAMES Profil a nastavte vysokou prioritu .  
[3] Win32PrioritySeparation -> Zvolte profil [1] (Ultra Esports) nebo [3] (Ultra Gaming) .  
(Volitelné) Aplikujte Hazard Tweaky: Pokud jste si vědomi rizik, vstupte do [7] Security Hazard Tweaks (heslo: extreme ) a vypněte CPU Mitigace, HVCI a VBS.  

Restartujte Počítač: Většina hloubkových změn vyžaduje restart.  
```  
============================================================================================================================

🎯 Filozofie: Nulový Overhead (Žádné "Watchdogy")  
Tento nástroj je navržen pro kompetitivní hráče. Na rozdíl od jiných optimalizačních nástrojů,  
KRAKE-FIX neinstaluje žádné služby na pozadí, "watchdogy" nebo agenty, které běží 24/7.!!!  
Filozofie je jednoduchá:  
Aplikuj (Apply): Provedete jednorázovou, hloubkovou konfiguraci systému (registry, ACL, služby).  
Restartuj (Reboot): Systém se spustí v optimalizovaném stavu.  
Hraj (Play): Užijte si 0% CPU overhead, 0 MB využité RAM a nulový I/O dopad od samotného nástroje během hraní.  
Jedná se o statickou konfiguraci, nikoli o proces běžící na pozadí, který by mohl způsobit micro-stuttering nebo krást systémové prostředky během hry .  
 
============================================================================================================================

🔄 Proces Obnovy (Jak vrátit změny)  
```
Pokud narazíte na problémy nebo chcete systém vrátit do výchozího stavu:  
Použijte Bod Obnovy Systému (System Restore Point): Toto je nejjednodušší a nejbezpečnější metoda.  
Obnovte Bezpečnostní Tweaky:  
Spusťte Main.ps1 -> [6] Obnovit bezpečné výchozí nastavení Windows (RevertHazard.psm1) .  
Tím se obnoví všechny tweaky z modulu Security (VBS, HVCI, Defender atd.) na jejich výchozí (zapnutý) stav.  
Obnovte Služby:  
Spusťte Main.ps1 -> [1] Aplikovat obecné tweaky -> [R] TWEAK R - Reset služeb (TweakR.psm1) .  
Tím se obnoví a spustí 277+ systémových služeb do výchozího stavu.  
Opravte Windows Update:  
Pokud WU nefunguje, použijte Main.ps1 -> [13] Windows Update Management -> [6] Repair & Reset (Updates.psm1) .  
Odblokujte Edge:  
Pokud jste použili Hardcore blokaci, musíte nejprve spustit Main.ps1 -> [16] Edge Blockade -> [R] ACL UNLOCK (tím se odstraní DENY pravidla) .  
Poté spusťte [U] UNLOCK/REVERT pro odstranění IFEO a Firewallu .  
```  

==========================================================================================================

## 📄 License

This project is licensed under the **MIT License**.

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

## 📸 Screenshots

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
  <img src="Screenshots/shot013.png" width="400" alt="Screenshot 17"/>
  <img src="Screenshots/shot014.png" width="400" alt="Screenshot 18"/>
</p>

<p align="center">
  <img src="Screenshots/shot015.png" width="400" alt="Screenshot 19"/>
  <img src="Screenshots/shot016.png" width="400" alt="Screenshot 20"/>
</p>

<p align="center">
  <img src="Screenshots/shot017.png" width="400" alt="Screenshot 21"/>
  <img src="Screenshots/shot018.png" width="400" alt="Screenshot 22"/>
</p>

<p align="center">
  <img src="Screenshots/shot019.png" width="400" alt="Screenshot 23"/>
  <img src="Screenshots/shot020.png" width="400" alt="Screenshot 24"/>
</p>

<p align="center">
  <img src="Screenshots/shot021.png" width="400" alt="Screenshot 25"/>
  <img src="Screenshots/shot022.png" width="400" alt="Screenshot 26"/>
</p>

<p align="center">
  <img src="Screenshots/shot023.png" width="400" alt="Screenshot 27"/>
  <img src="Screenshots/shot024.png" width="400" alt="Screenshot 28"/>
</p>

<p align="center">
  <img src="Screenshots/shot025.png" width="400" alt="Screenshot 29"/>
  <img src="Screenshots/shot026.png" width="400" alt="Screenshot 30"/>
</p>

<p align="center">
  <img src="Screenshots/shot027.png" width="400" alt="Screenshot 31"/>
  <img src="Screenshots/shot028.png" width="400" alt="Screenshot 32"/>
</p>

<p align="center">
  <img src="Screenshots/shot029.png" width="400" alt="Screenshot 33"/>
  <img src="Screenshots/shot030.png" width="400" alt="Screenshot 34"/>
</p>

<p align="center">
  <img src="Screenshots/shot031.png" width="400" alt="Screenshot 35"/>
  <img src="Screenshots/shot032.png" width="400" alt="Screenshot 36"/>
</p>

---