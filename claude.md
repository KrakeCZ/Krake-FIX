CLAUDE.md — Krakefix Engineering & AI Agent Guidelines

přečti si AGENTS.md aby jsi pochopil nastroj Krake-Fix

Tento soubor slouží jako závazná technická specifikace a instrukční sada pro AI agenty (Claude Code, Cursor, Aider) i vývojáře pracující na projektu Krakefix. Cílem je udržet nejvyšší úroveň softwarového inženýrství (Senior/Principal standard) a striktně chránit kritickou byznys logiku v jádru systému.

1. Architektonický přehled a Core Systém (CRITICAL ZONE)

Projekt Krakefix je postaven na principech čisté architektury (Clean Architecture / Hexagonal Architecture) s důrazem na deterministické chování, vysokou propustnost a nulovou toleranci k regresím v jádru.

⚠️ Pravidla pro složku /core (High-Risk Area) _

Jádro systému (/src/core nebo /core) obsahuje vysoce komplexní doménovou logiku, stavové automaty, výpočetní algoritmy a kritické transakční toky.

Zákaz slepého refaktoringu: Nikdy neměň logiku uvnitř /core bez explicitního zadání a předchozí analýzy dopadů (Impact Analysis).

Idempotence a Determinismus: Veškeré operace v Core musí být deterministické. Vedlejší efekty (Side Effects – DB volání, HTTP requesty, I/O) jsou v čisté doménové vrstvě striktně zakázány; musí být abstrahovány přes rozhraní (Ports/Adapters).

Žádné "Quick Fix" záplaty: Pokud narazíš na chybu v Core, nehledej zkratky v aplikační vrstvě. Analyzuj kořenovou příčinu (Root Cause) a navrhni systémové řešení.

Invarianty: Před jakoukoliv úpravou v Core si zmapuj všechny doménové invarianty a ověř, že je tvůj kód neporušuje.

2. Vývojářský Workflow (Senior Standard)

Před napsáním jediného řádku kódu dodržuj následující postup:

Průzkum kontextu (Read-Before-Write):

Přečti si související soubory, rozhraní, typy a existující testy v daném modulu.

Zkontroluj, zda podobný problém již není v projektu vyřešen (DODRŽUJ DRY, ale ne na úkor zbytečné abstrakce – preferuj WET před špatnou abstrakcí).

Návrh řešení (Plan Mode):

U netriviálních úkolů nejprve vypiš stručný architektonický plán (dotčené soubory, změny v datových strukturách, edge-cases) a vyčkej na potvrzení, pokud zadání není 100% jednoznačné.

Implementace & Verifikace:

Piš kód s ohledem na čitelnost, udržovatelnost a výkon (Big-O komplexita).

Po dokončení změn vždy spusť type-checking, linter a relevantní testovací sady.

3. Kódovací standardy a konvence

Typová bezpečnost a Datové modely

Strict Mode: Vždy používej nejpřísnější typovou kontrolu. Jakékoliv obcházení typů (any, @ts-ignore, # type: ignore, nebezpečné přetypování) je přísně zakázáno.

Parse, don't validate: Vstupní data z externích zdrojů (API, fronty, DB) musí být na hranicích systému validována a parsována do striktních doménových typů/Value Objectů.

Immutabilita: Preferuj neměnné datové struktury (readonly, const, frozen), zejména při práci se stavy v rámci Core.

Error Handling & Observabilita

Explicitní chyby: Nikdy polykání výjimek (catch (e) {}). Každá chyba musí být buď smysluplně zpracována, obohacena o kontext a poslána výše, nebo zalogována se strukturovanými metadaty.

Doménové chyby vs. Technické chyby: Rozlišuj mezi očekávaným byznysovým selháním (např. InsufficientBalanceError, InvalidStateTransitionError) a infrastrukturním selháním (výpadek sítě/DB).

Strukturované logování: Logy musí obsahovat kontext (např. correlationId, entityId, operation), nikoliv jen prostý text. Nikdy neloguj citlivá data (PII, tokeny, hesla).

4. Testovací strategie (Zero-Regression Policy)

Kód bez testů se považuje za nedokončený.

Core vrstva: Vyžaduje 100% pokrytí unit testy pro veškerou novou či upravenou logiku, včetně hraničních případů (boundary conditions, null/empty stavy, race conditions).

Struktura testů: Dodržuj vzor AAA (Arrange, Act, Assert). Názvy testů musí jasně popisovat testovaný scénář a očekávaný výsledek (např. should_throw_InvalidTransitionError_when_order_is_already_closed).

Mockování: V Core testech nemockuj interní doménové třídy – testuj reálné chování domény. Mockuj pouze externí porty (repozitáře, externí služby).

5. Pravidla pro komunikaci AI Agenta

Stručnost a preciznost: Komunikuj jako zkušený Staff/Principal Engineer. Vynech zbytečnou omáčku, soustřeď se na technická fakta, architektonické kompromisy (trade-offs) a konkrétní implementaci.

Upozornění na rizika: Pokud požadavek uživatele směřuje k anti-patternu, bezpečnostní zranitelnosti nebo degradaci výkonu Core systému, aktivně na to upozorni a navrhni bezpečnější alternativu.

Žádné halucinace API: Pokud si nejsi jistý signaturou interní metody nebo knihovny v projektu, ověř ji přímo v kódu / package.json (nebo ekvivalentu).

6. Často používané příkazy (Doplň dle konkrétního stacku)

Poznámka pro tým: Upravte následující příkazy podle reálného build systému projektu Krakefix.

Build: npm run build / cargo build / go build ./...

Testy (vše): npm test

Testy (pouze Core): npm run test:core

Linter & Typecheck: npm run lint && npm run typecheck
