# 
# Module: PowerPlan.psm1
# Project:      KRAKE-FIX
# ===========================================================
# Description:  Windows Power Plan Management
#               - Apply UltimatePerformance as High Performance
#               - Balanced, PowerSaver tweaks
#               - Custom power plan management
#               - Plan duplication and restoration
# Category:     Power Management
# Dependencies: None (standalone)
# Admin Rights: Required
# ===========================================================
#  SECURITY & COMPLIANCE NOTICE
# ===========================================================
#  This module modifies Windows power management settings.
#  Designed for educational and testing purposes only.
#  Author assumes no liability for misuse outside academic context.
#  Always create system restore point before use.
# ===========================================================
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ===========================================================
#Requires -Version 5.1
#Requires -RunAsAdministrator
# ---------------------------------------------------------------------------
# MODULE INITIALIZATION
# ---------------------------------------------------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Module-level variables (private)
$script:ModuleName = 'PowerPlan'
$script:ModuleVersion = '2.0.0'
$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"
# ---------------------------------------------------------------------------
# POWER PLAN GUIDs
# ---------------------------------------------------------------------------
$script:HighPerfGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
$script:BalancedGUID = "381b4222-f694-41f0-9685-ff5bb260df2e"
$script:PowerSaverGUID = "a1841308-3541-4fab-bc81-f71556f20b4a"
$script:UltimatePerformanceGUID_in_JSON = "e9a42b02-d5df-448d-aa00-03f14749eb61"
$script:embeddedJsonData = @'
[
    {
        "PlanName":  "UltimatePerformance",
        "PlanGUID":  "e9a42b02-d5df-448d-aa00-03f14749eb61",
        "Settings":  [
                         {
                             "SubGroupGUID":  "0012ee47-9041-4b5d-9b77-535fba8b1442",
                             "SettingGUID":  "6738e2c4-e8a5-4a42-b16a-e040e769756e",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "0012ee47-9041-4b5d-9b77-535fba8b1442",
                             "SettingGUID":  "6738e2c4-e8a5-4a42-b16a-e040e769756e",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "0d7dbae2-4294-402a-ba8e-26777e8488cd",
                             "SettingGUID":  "309dce9b-bef4-4119-9921-a851fb12f0f4",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "0d7dbae2-4294-402a-ba8e-26777e8488cd",
                             "SettingGUID":  "309dce9b-bef4-4119-9921-a851fb12f0f4",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "19cbb8fa-5279-450e-9fac-8a3d5fedd0c1",
                             "SettingGUID":  "12bbebe6-58d6-4636-95bb-3217ef867c1a",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "19cbb8fa-5279-450e-9fac-8a3d5fedd0c1",
                             "SettingGUID":  "12bbebe6-58d6-4636-95bb-3217ef867c1a",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000e10"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000e10"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "7bc4a2f9-d8fc-4469-b07b-33eb785aaca0",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000078"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "7bc4a2f9-d8fc-4469-b07b-33eb785aaca0",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000078"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "94ac6d29-73ce-41a6-809f-6363ba21b47e",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "94ac6d29-73ce-41a6-809f-6363ba21b47e",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "9d7815a6-7ee4-497e-8888-515a05f02364",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "9d7815a6-7ee4-497e-8888-515a05f02364",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00002a30"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "2a737441-1930-4402-8d77-b2bebba308a3",
                             "SettingGUID":  "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "2a737441-1930-4402-8d77-b2bebba308a3",
                             "SettingGUID":  "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "44f3beca-a7c0-460e-9df2-bb8b99e0cba6",
                             "SettingGUID":  "3619c3f2-afb2-4afc-b0e9-e7fef372de36",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "44f3beca-a7c0-460e-9df2-bb8b99e0cba6",
                             "SettingGUID":  "3619c3f2-afb2-4afc-b0e9-e7fef372de36",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "4f971e89-eebd-4455-a8de-9e59040e7347",
                             "SettingGUID":  "a7066653-8d6c-40a8-910e-a1f54b84c7e5",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "4f971e89-eebd-4455-a8de-9e59040e7347",
                             "SettingGUID":  "a7066653-8d6c-40a8-910e-a1f54b84c7e5",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "501a4d13-42af-4429-9fd1-a8218c268e20",
                             "SettingGUID":  "ee12f906-d277-404b-b6da-e5fa1a576df5",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "501a4d13-42af-4429-9fd1-a8218c268e20",
                             "SettingGUID":  "ee12f906-d277-404b-b6da-e5fa1a576df5",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "0cc5b647-c1df-4637-891a-dec35c318583",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "0cc5b647-c1df-4637-891a-dec35c318583",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "893dee8e-2bef-41e0-89c6-b55d0929964c",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "893dee8e-2bef-41e0-89c6-b55d0929964c",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "94d3a615-a899-4ac5-ae2b-e4d8f634367f",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "94d3a615-a899-4ac5-ae2b-e4d8f634367f",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "bc5038f7-23e0-4960-96da-33abaf5935ec",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "bc5038f7-23e0-4960-96da-33abaf5935ec",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "be337238-0d82-4146-a960-4f3749d470c7",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "be337238-0d82-4146-a960-4f3749d470c7",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "ea062031-0e34-4ff1-9b6d-eb1059334028",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "ea062031-0e34-4ff1-9b6d-eb1059334028",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000258"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e",
                             "Mode":  "DC",
                             "ValueIndex":  "0x0000003c"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "aded5e82-b909-4619-9949-f5d71dac0bcb",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000062"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "aded5e82-b909-4619-9949-f5d71dac0bcb",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000062"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "f1fbfde2-a960-4165-9f88-50667911ce96",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000032"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "f1fbfde2-a960-4165-9f88-50667911ce96",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000032"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "fbd9aa66-9553-4097-ba44-ed6e9d65eab8",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "fbd9aa66-9553-4097-ba44-ed6e9d65eab8",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "10778347-1370-4ee0-8bbd-33bdacaade49",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "10778347-1370-4ee0-8bbd-33bdacaade49",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "637ea02f-bbcb-4015-8e2c-a1c7b9c0b546",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "637ea02f-bbcb-4015-8e2c-a1c7b9c0b546",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "8183ba9a-e910-48da-8769-14ae6dc1170a",
                             "Mode":  "AC",
                             "ValueIndex":  "0x0000000a"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "8183ba9a-e910-48da-8769-14ae6dc1170a",
                             "Mode":  "DC",
                             "ValueIndex":  "0x0000000a"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000005"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000005"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "bcded951-187b-4d05-bccc-f7e51960c258",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "bcded951-187b-4d05-bccc-f7e51960c258",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "d8742dcb-3e6a-4b3c-b3fe-374623cdcf06",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "d8742dcb-3e6a-4b3c-b3fe-374623cdcf06",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "f3c5027d-cd16-4930-aa6b-90db844a8f00",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000007"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "f3c5027d-cd16-4930-aa6b-90db844a8f00",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000007"
                         }
                     ]
    },
    {
        "PlanName":  "Rovnováha",
        "PlanGUID":  "381b4222-f694-41f0-9685-ff5bb260df2e",
        "Settings":  [
                         {
                             "SubGroupGUID":  "0012ee47-9041-4b5d-9b77-535fba8b1442",
                             "SettingGUID":  "6738e2c4-e8a5-4a42-b16a-e040e769756e",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "0012ee47-9041-4b5d-9b77-535fba8b1442",
                             "SettingGUID":  "6738e2c4-e8a5-4a42-b16a-e040e769756e",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "0d7dbae2-4294-402a-ba8e-26777e8488cd",
                             "SettingGUID":  "309dce9b-bef4-4119-9921-a851fb12f0f4",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "0d7dbae2-4294-402a-ba8e-26777e8488cd",
                             "SettingGUID":  "309dce9b-bef4-4119-9921-a851fb12f0f4",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "19cbb8fa-5279-450e-9fac-8a3d5fedd0c1",
                             "SettingGUID":  "12bbebe6-58d6-4636-95bb-3217ef867c1a",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "19cbb8fa-5279-450e-9fac-8a3d5fedd0c1",
                             "SettingGUID":  "12bbebe6-58d6-4636-95bb-3217ef867c1a",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000e10"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000e10"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "7bc4a2f9-d8fc-4469-b07b-33eb785aaca0",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000078"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "7bc4a2f9-d8fc-4469-b07b-33eb785aaca0",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000078"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "94ac6d29-73ce-41a6-809f-6363ba21b47e",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "94ac6d29-73ce-41a6-809f-6363ba21b47e",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "9d7815a6-7ee4-497e-8888-515a05f02364",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00002a30"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "9d7815a6-7ee4-497e-8888-515a05f02364",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00002a30"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "2a737441-1930-4402-8d77-b2bebba308a3",
                             "SettingGUID":  "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "2a737441-1930-4402-8d77-b2bebba308a3",
                             "SettingGUID":  "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "44f3beca-a7c0-460e-9df2-bb8b99e0cba6",
                             "SettingGUID":  "3619c3f2-afb2-4afc-b0e9-e7fef372de36",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "44f3beca-a7c0-460e-9df2-bb8b99e0cba6",
                             "SettingGUID":  "3619c3f2-afb2-4afc-b0e9-e7fef372de36",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "4f971e89-eebd-4455-a8de-9e59040e7347",
                             "SettingGUID":  "a7066653-8d6c-40a8-910e-a1f54b84c7e5",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "4f971e89-eebd-4455-a8de-9e59040e7347",
                             "SettingGUID":  "a7066653-8d6c-40a8-910e-a1f54b84c7e5",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "501a4d13-42af-4429-9fd1-a8218c268e20",
                             "SettingGUID":  "ee12f906-d277-404b-b6da-e5fa1a576df5",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "501a4d13-42af-4429-9fd1-a8218c268e20",
                             "SettingGUID":  "ee12f906-d277-404b-b6da-e5fa1a576df5",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "0cc5b647-c1df-4637-891a-dec35c318583",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000023"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "0cc5b647-c1df-4637-891a-dec35c318583",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000014"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "893dee8e-2bef-41e0-89c6-b55d0929964c",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000005"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "893dee8e-2bef-41e0-89c6-b55d0929964c",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000005"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "94d3a615-a899-4ac5-ae2b-e4d8f634367f",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "94d3a615-a899-4ac5-ae2b-e4d8f634367f",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "bc5038f7-23e0-4960-96da-33abaf5935ec",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000062"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "bc5038f7-23e0-4960-96da-33abaf5935ec",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000062"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "be337238-0d82-4146-a960-4f3749d470c7",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "be337238-0d82-4146-a960-4f3749d470c7",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "ea062031-0e34-4ff1-9b6d-eb1059334028",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "ea062031-0e34-4ff1-9b6d-eb1059334028",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000258"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e",
                             "Mode":  "DC",
                             "ValueIndex":  "0x0000003c"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "aded5e82-b909-4619-9949-f5d71dac0bcb",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000042"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "aded5e82-b909-4619-9949-f5d71dac0bcb",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000042"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "f1fbfde2-a960-4165-9f88-50667911ce96",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000032"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "f1fbfde2-a960-4165-9f88-50667911ce96",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000032"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "fbd9aa66-9553-4097-ba44-ed6e9d65eab8",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "fbd9aa66-9553-4097-ba44-ed6e9d65eab8",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "10778347-1370-4ee0-8bbd-33bdacaade49",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "10778347-1370-4ee0-8bbd-33bdacaade49",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "637ea02f-bbcb-4015-8e2c-a1c7b9c0b546",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "637ea02f-bbcb-4015-8e2c-a1c7b9c0b546",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "8183ba9a-e910-48da-8769-14ae6dc1170a",
                             "Mode":  "AC",
                             "ValueIndex":  "0x0000000a"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "8183ba9a-e910-48da-8769-14ae6dc1170a",
                             "Mode":  "DC",
                             "ValueIndex":  "0x0000000a"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000005"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000005"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "bcded951-187b-4d05-bccc-f7e51960c258",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "bcded951-187b-4d05-bccc-f7e51960c258",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "d8742dcb-3e6a-4b3c-b3fe-374623cdcf06",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "d8742dcb-3e6a-4b3c-b3fe-374623cdcf06",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "f3c5027d-cd16-4930-aa6b-90db844a8f00",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000007"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "f3c5027d-cd16-4930-aa6b-90db844a8f00",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000007"
                         }
                     ]
    },
    {
        "PlanName":  "Úsporný režim",
        "PlanGUID":  "a1841308-3541-4fab-bc81-f71556f20b4a",
        "Settings":  [
                         {
                             "SubGroupGUID":  "0012ee47-9041-4b5d-9b77-535fba8b1442",
                             "SettingGUID":  "6738e2c4-e8a5-4a42-b16a-e040e769756e",
                             "Mode":  "AC",
                             "ValueIndex":  "0x000004b0"
                         },
                         {
                             "SubGroupGUID":  "0012ee47-9041-4b5d-9b77-535fba8b1442",
                             "SettingGUID":  "6738e2c4-e8a5-4a42-b16a-e040e769756e",
                             "Mode":  "DC",
                             "ValueIndex":  "0x0000012c"
                         },
                         {
                             "SubGroupGUID":  "0d7dbae2-4294-402a-ba8e-26777e8488cd",
                             "SettingGUID":  "309dce9b-bef4-4119-9921-a851fb12f0f4",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "0d7dbae2-4294-402a-ba8e-26777e8488cd",
                             "SettingGUID":  "309dce9b-bef4-4119-9921-a851fb12f0f4",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "19cbb8fa-5279-450e-9fac-8a3d5fedd0c1",
                             "SettingGUID":  "12bbebe6-58d6-4636-95bb-3217ef867c1a",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "19cbb8fa-5279-450e-9fac-8a3d5fedd0c1",
                             "SettingGUID":  "12bbebe6-58d6-4636-95bb-3217ef867c1a",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000003"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000384"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000258"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "7bc4a2f9-d8fc-4469-b07b-33eb785aaca0",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000078"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "7bc4a2f9-d8fc-4469-b07b-33eb785aaca0",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000078"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "94ac6d29-73ce-41a6-809f-6363ba21b47e",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "94ac6d29-73ce-41a6-809f-6363ba21b47e",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "9d7815a6-7ee4-497e-8888-515a05f02364",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00002a30"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "9d7815a6-7ee4-497e-8888-515a05f02364",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00002a30"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                             "SettingGUID":  "bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "2a737441-1930-4402-8d77-b2bebba308a3",
                             "SettingGUID":  "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "2a737441-1930-4402-8d77-b2bebba308a3",
                             "SettingGUID":  "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "44f3beca-a7c0-460e-9df2-bb8b99e0cba6",
                             "SettingGUID":  "3619c3f2-afb2-4afc-b0e9-e7fef372de36",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "44f3beca-a7c0-460e-9df2-bb8b99e0cba6",
                             "SettingGUID":  "3619c3f2-afb2-4afc-b0e9-e7fef372de36",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "4f971e89-eebd-4455-a8de-9e59040e7347",
                             "SettingGUID":  "a7066653-8d6c-40a8-910e-a1f54b84c7e5",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "4f971e89-eebd-4455-a8de-9e59040e7347",
                             "SettingGUID":  "a7066653-8d6c-40a8-910e-a1f54b84c7e5",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "501a4d13-42af-4429-9fd1-a8218c268e20",
                             "SettingGUID":  "ee12f906-d277-404b-b6da-e5fa1a576df5",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000003"
                         },
                         {
                             "SubGroupGUID":  "501a4d13-42af-4429-9fd1-a8218c268e20",
                             "SettingGUID":  "ee12f906-d277-404b-b6da-e5fa1a576df5",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000003"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "0cc5b647-c1df-4637-891a-dec35c318583",
                             "Mode":  "AC",
                             "ValueIndex":  "0x0000002d"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "0cc5b647-c1df-4637-891a-dec35c318583",
                             "Mode":  "DC",
                             "ValueIndex":  "0x0000002d"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "893dee8e-2bef-41e0-89c6-b55d0929964c",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000005"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "893dee8e-2bef-41e0-89c6-b55d0929964c",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000005"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "94d3a615-a899-4ac5-ae2b-e4d8f634367f",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "94d3a615-a899-4ac5-ae2b-e4d8f634367f",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "bc5038f7-23e0-4960-96da-33abaf5935ec",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000038"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "bc5038f7-23e0-4960-96da-33abaf5935ec",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000038"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "be337238-0d82-4146-a960-4f3749d470c7",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "be337238-0d82-4146-a960-4f3749d470c7",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "ea062031-0e34-4ff1-9b6d-eb1059334028",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "54533251-82be-4824-96c1-47b60b740d00",
                             "SettingGUID":  "ea062031-0e34-4ff1-9b6d-eb1059334028",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000064"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000258"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000128"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "aded5e82-b909-4619-9949-f5d71dac0bcb",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000046"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "aded5e82-b909-4619-9949-f5d71dac0bcb",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000046"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "f1fbfde2-a960-4165-9f88-50667911ce96",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000032"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "f1fbfde2-a960-4165-9f88-50667911ce96",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000032"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "fbd9aa66-9553-4097-ba44-ed6e9d65eab8",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "7516b95f-f776-4464-8c53-06167f40cc99",
                             "SettingGUID":  "fbd9aa66-9553-4097-ba44-ed6e9d65eab8",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "10778347-1370-4ee0-8bbd-33bdacaade49",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "10778347-1370-4ee0-8bbd-33bdacaade49",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "9596fb26-9850-41fd-ac3e-f7c3c00afd4b",
                             "SettingGUID":  "34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "637ea02f-bbcb-4015-8e2c-a1c7b9c0b546",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "637ea02f-bbcb-4015-8e2c-a1c7b9c0b546",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000002"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "8183ba9a-e910-48da-8769-14ae6dc1170a",
                             "Mode":  "AC",
                             "ValueIndex":  "0x0000000a"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "8183ba9a-e910-48da-8769-14ae6dc1170a",
                             "Mode":  "DC",
                             "ValueIndex":  "0x0000000a"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000005"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000005"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "bcded951-187b-4d05-bccc-f7e51960c258",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "bcded951-187b-4d05-bccc-f7e51960c258",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000001"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "d8742dcb-3e6a-4b3c-b3fe-374623cdcf06",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "d8742dcb-3e6a-4b3c-b3fe-374623cdcf06",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000000"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "f3c5027d-cd16-4930-aa6b-90db844a8f00",
                             "Mode":  "AC",
                             "ValueIndex":  "0x00000007"
                         },
                         {
                             "SubGroupGUID":  "e73a048d-bf27-4f12-9731-8b2076e8891f",
                             "SettingGUID":  "f3c5027d-cd16-4930-aa6b-90db844a8f00",
                             "Mode":  "DC",
                             "ValueIndex":  "0x00000007"
                         }
                     ]
    }
]
'@
# -------------------------------------------------------------------
# Parse Embedded JSON Data
# -------------------------------------------------------------------
try {
    # 4a. Parsování vložených dat
    $script:allPlansData = $script:embeddedJsonData | ConvertFrom-Json
    # 4b. Extrahujeme seznamy nastavení z JSONu
    $script:UltimatePerformanceSettings = ($script:allPlansData | Where-Object { $_.PlanGUID -eq $script:UltimatePerformanceGUID_in_JSON }).Settings
    $script:BalancedSettings = ($script:allPlansData | Where-Object { $_.PlanGUID -eq $script:BalancedGUID }).Settings
    $script:PowerSaverSettings = ($script:allPlansData | Where-Object { $_.PlanGUID -eq $script:PowerSaverGUID }).Settings
    if ($null -eq $script:UltimatePerformanceSettings -or $null -eq $script:BalancedSettings -or $null -eq $script:PowerSaverSettings) {
        throw "Vložená data jsou poškozená nebo neobsahují potřebné plány (UltimatePerformance, Rovnováha, Úsporný režim)."
    }
}
catch {
    Write-Error "KRITICKÁ CHYBA: Nepodařilo se parsovat data plánů napájení. Funkce [9] nebude dostupná. Chyba: $($_.Exception.Message)"
    Write-Error "Skript bude ukončen."
    Start-Sleep -Seconds 10
    exit 1
}
# ===========================================================
# POWER PLAN MANAGEMENT FUNCTIONS
# ===========================================================
function Set-PlanSettings {
    #OKOKO-----LINTER -
    param (
        [Parameter(Mandatory = $true)]
        [System.Array]$SettingsList,
        [Parameter(Mandatory = $true)]
        [string]$TargetGUID,
        [Parameter(Mandatory = $true)]
        [string]$TargetName
    )
    Write-Host "---"
    Write-Host "Zahajuji replikaci pro: '$TargetName'" -ForegroundColor Yellow
    # -------------------------------------------------------------------
    # Robustní ověření existence cílového GUID
    # -------------------------------------------------------------------
    $targetExists = $false
    try {
        $powercfgListOutput = powercfg /list | Out-String
        if ($powercfgListOutput -match [regex]::Escape($TargetGUID)) {
            $targetExists = $true
        }
    }
    catch {
        Write-Warning "Nepodařilo se spustit 'powercfg /list': $($_.Exception.Message)"
        # Assume it doesn't exist and try to recover
    }
    if (-not $targetExists) {
        Write-Warning "Cílové schéma '$TargetName' (GUID: $TargetGUID) na tomto systému neexistuje."
        Write-Host "Pokouším se automaticky obnovit výchozí schémata Windows..." -ForegroundColor Yellow
        try {
            powercfg -restoredefaultschemes | Out-Null
            Write-Host "Výchozí schémata byla obnovena." -ForegroundColor Green
            Start-Sleep -Milliseconds 500 # Explicitní krátká pauza
            # Re-check existence
            $powercfgListOutput = powercfg /list | Out-String
            if ($powercfgListOutput -match [regex]::Escape($TargetGUID)) {
                $targetExists = $true
            }
        }
        catch {
            Write-Error "KRITICKÁ CHYBA: Automatická obnova výchozích schémat selhala. Zkontrolujte oprávnění. Chyba: $($_.Exception.Message)"
            # Cannot proceed without the target plan
            Read-Host "Stiskněte Enter pro návrat..."
            return
        }
        # -------------------------------------------------------------------
        # POKUS O DUPLIKACI (Pro 'Vysoký výkon', 'Úsporný režim', nebo 'Ultimate Performance')
        # -------------------------------------------------------------------
        $isUltimatePerformance = ($TargetGUID -eq $script:UltimatePerformanceGUID_in_JSON)
        $isDuplicatable = ($TargetGUID -eq $script:HighPerfGUID) -or ($TargetGUID -eq $script:PowerSaverGUID) -or $isUltimatePerformance
        if (-not $targetExists -and $isDuplicatable) {
            if ($isUltimatePerformance) {
                # ===== SPECIÁLNÍ LOGIKA PRO ULTIMATE PERFORMANCE =====
                Write-Host "Cílový plán 'Ultimate Performance' neexistuje. Pokouším se jej vytvořit..." -ForegroundColor Yellow
                # Ultimate Performance má svůj vlastní source GUID pro duplikaci
                $ultimateSourceGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61"
                try {
                    # Duplikace Ultimate Performance plánu (vytvoří nový GUID automaticky)
                    $duplicateOutput = powercfg /duplicatescheme $ultimateSourceGUID
                    # Extrakce nově vytvořeného GUID z outputu
                    $newGUID = $null
                    foreach ($line in $duplicateOutput) {
                        if ($line -match "\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b") {
                            $newGUID = $matches[0]
                            break
                        }
                    }
                    if ($newGUID) {
                        Start-Sleep -Milliseconds 200
                        # Přejmenování plánu
                        powercfg /changename $newGUID "Ultimate Performance" "Maximální výkon - vytvořeno automaticky" | Out-Null
                        Start-Sleep -Milliseconds 200
                        Write-Host "Ultimate Performance plán byl úspěšně vytvořen s GUID: $newGUID" -ForegroundColor Green
                        # Aktualizace TargetGUID pro další použití
                        $TargetGUID = $newGUID
                        $targetExists = $true
                    }
                    else {
                        Write-Warning "Nepodařilo se extrahovat GUID nově vytvořeného plánu."
                    }
                }
                catch {
                    Write-Warning "Nepodařilo se vytvořit Ultimate Performance plán. Chyba: $($_.Exception.Message)"
                }
            }
            else {
                # ===== STANDARDNÍ LOGIKA PRO HIGH PERF A POWER SAVER =====
                Write-Host "Cílový plán '$TargetName' se neobnovil. Pokouším se jej vytvořit duplikací 'Rovnováha'..." -ForegroundColor Yellow
                $balancedExists = $false
                try {
                    $powercfgListOutput = powercfg /list | Out-String
                    if ($powercfgListOutput -match [regex]::Escape($script:BalancedGUID)) {
                        $balancedExists = $true
                    }
                }
                catch { Write-Warning "Nepodařilo se ověřit existenci plánu Rovnováha." }
                if ($balancedExists) {
                    try {
                        # 1. Duplikovat 'Rovnováha' s GUID cíle
                        powercfg -duplicatescheme $script:BalancedGUID $TargetGUID | Out-Null
                        Start-Sleep -Milliseconds 200 # Pause after duplication
                        # 2. Přejmenovat nově vytvořený plán
                        powercfg -changename $TargetGUID $TargetName | Out-Null
                        Start-Sleep -Milliseconds 200 # Pause after rename
                        Write-Host "Plán '$TargetName' byl úspěšně vytvořen duplikací." -ForegroundColor Green
                        $targetExists = $true # Manuálně nastavíme flag, že nyní existuje
                    }
                    catch {
                        Write-Warning "Nepodařilo se duplikovat 'Rovnováha' pro vytvoření '$TargetName'. Chyba: $($_.Exception.Message)"
                        # $targetExists remains false
                    }
                }
                else {
                    Write-Error "KRITICKÁ CHYBA: Nelze vytvořit '$TargetName', protože zdrojový plán 'Rovnováha' (Balanced) také chybí a nelze jej obnovit."
                    Write-Error "Spusťte volbu [4] manuálně a zkuste to znovu, nebo zkontrolujte systém."
                    Read-Host "Stiskněte Enter pro návrat..."
                    return
                }
            }
        }
        # Finální kontrola (po případné obnově a duplikaci)
        if (-not $targetExists) {
            # Re-check one last time just in case
            try {
                $powercfgListOutput = powercfg /list | Out-String
                if ($powercfgListOutput -match [regex]::Escape($TargetGUID)) {
                    $targetExists = $true
                }
            }
            catch {}
            if (-not $targetExists) {
                Write-Error "KRITICKÁ CHYBA: Cílové schéma '$TargetName' nebylo nalezeno ani po pokusu o obnovu a duplikaci."
                Write-Error "Je možné, že tato verze Windows (např. IoT, LTSC) tento plán nativně neobsahuje, nebo došlo k jiné systémové chybě."
                Read-Host "Stiskněte Enter pro návrat..."
                return
            }
        }
    }
    Write-Host "Cílové schéma nalezeno. Aplikuji $($SettingsList.Count) optimalizovaných nastavení..."
    # -------------------------------------------------------------------
    # Aplikace nastavení
    # -------------------------------------------------------------------
    $totalSettings = $SettingsList.Count
    $appliedCount = 0
    $errorCount = 0
    # Initialize progress bar outside the loop for cleaner updates
    Write-Progress -Activity "Replikuji plán '$TargetName'" -Status "Probíhá příprava..." -PercentComplete 0 -Id 1
    for ($i = 0; $i -lt $totalSettings; $i++) {
        $setting = $SettingsList[$i]
        $currentProgress = (($i + 1) / $totalSettings) * 100
        Write-Progress -Activity "Replikuji plán '$TargetName'" -Status "Nastavení ($($i+1)/$totalSettings): $($setting.SettingGUID) $($setting.Mode)" -PercentComplete $currentProgress -Id 1
        # Use splatting for cleaner parameter passing to powercfg
        $powercfgArgs = @(
            $TargetGUID,
            $setting.SubGroupGUID,
            $setting.SettingGUID,
            $setting.ValueIndex
        )
        try {
            if ($setting.Mode -eq "AC") {
                # powercfg /setacvalueindex expects arguments space-separated
                Start-Process -FilePath "powercfg.exe" -ArgumentList "/setacvalueindex $($powercfgArgs -join ' ')" -Wait -NoNewWindow -ErrorAction Stop
            }
            elseif ($setting.Mode -eq "DC") {
                Start-Process -FilePath "powercfg.exe" -ArgumentList "/setdcvalueindex $($powercfgArgs -join ' ')" -Wait -NoNewWindow -ErrorAction Stop
            }
            $appliedCount++
        }
        catch {
            Write-Warning "Nepodařilo se nastavit hodnotu pro $($setting.SettingGUID) ($($setting.Mode)) index $($setting.ValueIndex). Chyba: $($_.Exception.Message)"
            $errorCount++
        }
    }
    Write-Progress -Activity "Replikace dokončena" -Completed -Id 1
    if ($errorCount -eq 0) {
        Write-Host "ÚSPĚCH: Všech $appliedCount nastavení bylo replikováno do '$TargetName'." -ForegroundColor Green
    }
    else {
        Write-Warning "VAROVÁNÍ: $appliedCount z $totalSettings nastavení bylo aplikováno. Vyskytlo se $errorCount chyb."
    }
    # -------------------------------------------------------------------
    # Dotaz na aktivaci
    # -------------------------------------------------------------------
    $choice = Read-Host "Přejete si schéma '$TargetName' nastavit jako AKTIVNÍ? (A/N)"
    if ($choice -match '^a') {
        # More flexible check for 'Ano' or 'a'
        try {
            powercfg /setactive $TargetGUID | Out-Null
            Write-Host "Schéma '$TargetName' je nyní aktivní." -ForegroundColor Green
        }
        catch {
            Write-Error "Nepodařilo se aktivovat schéma '$TargetName'. Chyba: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Schéma '$TargetName' nebylo aktivováno."
    }
}
# ===================================================================
function Show-CustomPowerPlans {
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "          UŽIVATELSKÉ NAPÁJECÍ PLÁNY" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    try {
        # Ziskej vsechny plany
        $allPlans = powercfg /list | Out-String
        $planLines = $allPlans -split "`r?`n" | Where-Object { $_ -match "Power Scheme GUID:" }
        # Standardni Windows GUIDs
        $standardGUIDs = @(
            "381b4222-f694-41f0-9685-ff5bb260df2e",  # Balanced
            "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",  # High Performance
            "a1841308-3541-4fab-bc81-f71556f20b4a"   # Power Saver
        )
        $customPlans = @()
        foreach ($line in $planLines) {
            if ($line -match "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\s+\(([^)]+)\)") {
                $guid = $matches[1]
                $name = $matches[2]
                $isActive = $line -match "\*$"
                # Preskoc standardni plany
                if ($standardGUIDs -notcontains $guid) {
                    $customPlans += [PSCustomObject]@{
                        GUID     = $guid
                        Name     = $name
                        IsActive = $isActive
                    }
                }
            }
        }
        if ($customPlans.Count -eq 0) {
            Write-Host "Zadne uzivatelske napajecí plany nenalezeny." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "System obsahuje pouze standardni Windows plany:" -ForegroundColor Gray
            Write-Host "  - Balanced (Rovnovaha)" -ForegroundColor Gray
            Write-Host "  - High Performance (Vysoky vykon)" -ForegroundColor Gray
            Write-Host "  - Power Saver (Usporny rezim)" -ForegroundColor Gray
        }
        else {
            Write-Host "Nalezeno $($customPlans.Count) uzivatelskeho planu:" -ForegroundColor Green
            Write-Host ""
            $index = 1
            foreach ($plan in $customPlans) {
                $activeMarker = if ($plan.IsActive) { " [AKTIVNI]" } else { "" }
                Write-Host "  [$index] $($plan.Name)$activeMarker" -ForegroundColor $(if ($plan.IsActive) { "Green" } else { "White" })
                Write-Host "      GUID: $($plan.GUID)" -ForegroundColor Gray
                $index++
            }
        }
    }
    catch {
        Write-Warning "Chyba pri nacteni napajecich planu: $($_.Exception.Message)"
    }
    Write-Host ""
    Write-Host "Stisknete klavesu pro pokracovani..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
function Remove-CustomPowerPlan {
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Red
    Write-Host "          ODSTRANENI UZIVATELSKEHO NAPAJECIHO PLANU" -ForegroundColor Red
    Write-Host "============================================================================" -ForegroundColor Red
    Write-Host ""
    try {
        # Ziskej vsechny plany
        $allPlans = powercfg /list | Out-String
        $planLines = $allPlans -split "`r?`n" | Where-Object { $_ -match "Power Scheme GUID:" }
        # Standardni Windows GUIDs
        $standardGUIDs = @(
            "381b4222-f694-41f0-9685-ff5bb260df2e",  # Balanced
            "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",  # High Performance
            "a1841308-3541-4fab-bc81-f71556f20b4a"   # Power Saver
        )
        $customPlans = @()
        foreach ($line in $planLines) {
            if ($line -match "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\s+\(([^)]+)\)") {
                $guid = $matches[1]
                $name = $matches[2]
                $isActive = $line -match "\*$"
                # Preskoc standardni plany
                if ($standardGUIDs -notcontains $guid) {
                    $customPlans += [PSCustomObject]@{
                        GUID     = $guid
                        Name     = $name
                        IsActive = $isActive
                    }
                }
            }
        }
        if ($customPlans.Count -eq 0) {
            Write-Host "Zadne uzivatelske napajecí plany nenalezeny." -ForegroundColor Yellow
            Write-Host "Nelze odstranit standardni Windows plany." -ForegroundColor Gray
            Write-Host ""
            Write-Host "Stisknete klavesu pro pokracovani..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
        Write-Host "Nalezeno $($customPlans.Count) uzivatelskeho planu:" -ForegroundColor Yellow
        Write-Host ""
        $index = 1
        foreach ($plan in $customPlans) {
            $activeMarker = if ($plan.IsActive) { " [AKTIVNI - NELZE ODSTRANIT]" } else { "" }
            $color = if ($plan.IsActive) { "Red" } else { "White" }
            Write-Host "  [$index] $($plan.Name)$activeMarker" -ForegroundColor $color
            Write-Host "      GUID: $($plan.GUID)" -ForegroundColor Gray
            $index++
        }
        Write-Host ""
        Write-Host "Zadejte cislo planu k odstraneni (nebo Enter pro zruseni): " -NoNewline -ForegroundColor Yellow
        $choice = Read-Host
        if ([string]::IsNullOrWhiteSpace($choice)) {
            Write-Host "Operace zrusena." -ForegroundColor Gray
            Start-Sleep -Seconds 1
            return
        }
        $choiceNum = 0
        if (-not [int]::TryParse($choice, [ref]$choiceNum) -or $choiceNum -lt 1 -or $choiceNum -gt $customPlans.Count) {
            Write-Warning "Neplatna volba!"
            Start-Sleep -Seconds 2
            return
        }
        $selectedPlan = $customPlans[$choiceNum - 1]
        if ($selectedPlan.IsActive) {
            Write-Warning "Nelze odstranit aktivni napajecí plan!"
            Write-Host "Nejprve aktivujte jiny plan." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Stisknete klavesu pro pokracovani..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
        Write-Host ""
        Write-Host "Opravdu chcete odstranit plan '$($selectedPlan.Name)'? (Y/N)" -ForegroundColor Red
        $confirm = Read-Host
        if ($confirm -ne 'Y' -and $confirm -ne 'y') {
            Write-Host "Operace zrusena." -ForegroundColor Gray
            Start-Sleep -Seconds 1
            return
        }
        Write-Host ""
        Write-Host "Odstranuji plan '$($selectedPlan.Name)'..." -ForegroundColor Yellow
        powercfg -delete $selectedPlan.GUID | Out-Null
        Write-Host "Napajecí plan byl uspesne odstranen!" -ForegroundColor Green
    }
    catch {
        Write-Warning "Chyba pri odstranovani napajeciho planu: $($_.Exception.Message)"
    }
    Write-Host ""
    Write-Host "Stisknete klavesu pro pokracovani..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
function Show-PowerPlanMenu {
    while ($true) {
        Clear-Host
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host "                        PLÁNY   NAPÁJENÍ                                    " -ForegroundColor Yellow
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host "--- Volby Aplikace Tweaků ---" -ForegroundColor Blue
        Write-Host " [1] Aplikovat 'Vysoký výkon' (Hodnoty UltimatePerformance)" -ForegroundColor Red
        Write-Host
        Write-Host " [2] Aplikovat 'Rovnováha' " -ForegroundColor Gray
        Write-Host
        Write-Host " [3] Aplikovat 'Úsporný režim' (Hodnoty PowerSaver)"  -ForegroundColor Green # Clarified name
        Write-Host
        Write-Host "----------------------------------------------------------------------------" -ForegroundColor Green
        Write-Host " [4] Obnovit výchozí schémata Windows" -ForegroundColor Yellow
        Write-Host
        Write-Host " [5] Zobrazit uživatelské napájecí plány" -ForegroundColor Cyan
        Write-Host " [6] Odstranit uživatelský napájecí plán" -ForegroundColor Red
        Write-Host
        Write-Host " [Q] Zpět do hlavního menu" -ForegroundColor Red
        Write-Host "================================================="
        $selection = Read-Host "Zadejte volbu"
        switch ($selection) {
            '1' {
                Set-PlanSettings -SettingsList $script:UltimatePerformanceSettings -TargetGUID "e9a42b02-d5df-448d-aa00-03f14749eb61" -TargetName "Maximální výkon"
            }
            '2' {
                Set-PlanSettings -SettingsList $script:BalancedSettings -TargetGUID $script:BalancedGUID -TargetName "Rovnováha"
            }
            '3' {
                Set-PlanSettings -SettingsList $script:PowerSaverSettings -TargetGUID $script:PowerSaverGUID -TargetName "Úsporný režim"
            }
            '4' {
                Write-Host "---"
                Write-Host "Obnovuji výchozí schémata (Vysoký výkon, Rovnováha, Úsporný režim)..."
                try {
                    powercfg -restoredefaultschemes | Out-Null
                    Write-Host "Výchozí schémata byla obnovena." -ForegroundColor Green
                }
                catch {
                    Write-Error "Obnova selhala. Spusťte PowerShell jako Administrátor. Chyba: $($_.Exception.Message)"
                }
            }
            '5' {
                Show-CustomPowerPlans
            }
            '6' {
                Remove-CustomPowerPlan
            }
            'Q' {
                return # Exit the function/loop
            }
            default {
                Write-Warning "Neplatná volba: $selection"
            }
        } # Konec Switche
        # Only pause if an action was taken (not Q or invalid)
        if ($selection -in '1', '2', '3', '4') {
            Write-Host
            Read-Host "Stiskněte Enter pro návrat do menu..."
        }
        elseif ($selection -ne 'Q') {
            # Pause for invalid input as well
            Start-Sleep -Seconds 2
        }
    }
}
# ===========================================================
# EXPORT MODULE MEMBERS
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
    Show-PowerPlanMenu
}
Export-ModuleMember -Function @(
    'Show-PowerPlanMenu',
    'Set-PlanSettings',
    'Show-CustomPowerPlans',
    'Remove-CustomPowerPlan',
    'Invoke-ModuleEntry'
)