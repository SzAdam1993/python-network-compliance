
# Python Network Compliance

## A projektről

Python-alapú hálózatüzemeltetési és konfigurációellenőrzési rendszer,
amely mérnökinformatikus BSc-szakdolgozat keretében készült.

A rendszer célja Cisco hálózati eszközök konfigurációinak
automatizált lekérdezése, ellenőrzése, mentése és az eltérések
felismerése.

## Megvalósított funkciók

- SSH-kapcsolódás Netmiko használatával
- SSH-szerverkulcsok ellenőrzése
- Több hálózati eszköz kezelése
- Running-config konfigurációmentés
- VLAN-konfigurációk ellenőrzése
- Interfészek adminisztratív és operatív állapotának vizsgálata
- Trunk VLAN-listák ellenőrzése
- ACL-szabályok és hozzárendelések ellenőrzése
- Konfigurációeltérés felismerése (configuration drift)
- Kontrollált VLAN- és trunkkonfiguráció-módosítások
- Syslog-események feldolgozása
- Időablakos interfész flap-gyanú felismerése
- JSON-formátumú riportok készítése

## Tesztkörnyezet

- Cisco Modeling Labs Free
- 1 Cisco IOS XE router (R1)
- 2 Cisco IOL-L2 switch (SW1, SW2)
- 2 tesztkliens
- Ubuntu automatizálási szerver
- Python 3 és Netmiko

Menedzsmentcímek:

- R1: 10.10.99.1
- SW1: 10.10.99.11
- SW2: 10.10.99.12
- Ubuntu: 10.10.99.10

## Telepítés

A projektkönyvtárban:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

A kapcsolat paramétereit az inventory.yaml tartalmazza.

A hitelesítési adatokat külön .env fájlban kell megadni:

    DEVICE_USERNAME=<felhasználónév>
    DEVICE_PASSWORD=<jelszó>

Az SSH-szerverkulcsok hitelesített bejegyzéseit
az ssh_host_keys/known_hosts fájlban kell elhelyezni.

A szerverkulcsok ujjlenyomatát felvétel előtt
megbízható forrásból ellenőrizni kell.

Az .env, a known_hosts, a mentések és a helyi
bizonyítékok nem kerülnek verziókezelésbe.

## Programhasználat

Konfigurációmentés:

    python backup.py

Compliance-ellenőrzés:

    python run_compliance.py

Első referenciaállapot készítése:

    python run_drift.py baseline

Konfigurációeltérés ellenőrzése:

    python run_drift.py check

Jóváhagyott referencia frissítése:

    python run_drift.py baseline --replace

Syslog-elemzés:

    python run_syslog.py

Egyetlen eszköz Syslog-elemzése:

    python run_syslog.py --device SW1

Syslog bizonyíték mentése:

    python capture_syslog.py --device SW1 --label test

## Kontrollált konfigurációmódosítás

Példa az SW1 teszt accessportjának módosítására:

    python run_changes.py set-access-vlan --device SW1 --interface Ethernet0/2 --vlan 40

A program alapértelmezés szerint csak előnézetet készít.

A tényleges módosítás a --apply kapcsolóval,
külön megerősítés után történik:

    python run_changes.py set-access-vlan --device SW1 --interface Ethernet0/2 --vlan 40 --apply

A módosító modul kizárólag az engedélyezett
teszteszközökön és interfészeken használható.

## Automatizált tesztek

A teljes egységteszt-készlet futtatása:

    python -m unittest discover -s tests -v

A projekt 27 automatizált egységtesztet tartalmaz.

Az integrációs tesztek a következőket vizsgálták:

- TC-01: Access VLAN-eltérés és helyreállítás
- TC-02: Trunk VLAN-lista eltérése és helyreállítás
- TC-03: Váratlan ACL-szabály felismerése
- TC-04: SSH-biztonság és hibakezelés

Külön vizsgálat készült a hitelesített NTP-ről
és az időablakos Syslog flap-felismerésről.

## Riportok és referenciaállapotok

A program JSON-riportokat készít a report/
könyvtárban.

A konfigurációs referenciaállapotok a baselines/
könyvtárban találhatók.

Az eltérések részletes különbségállományai a
drift_diffs/ könyvtárba kerülnek.

Ezek helyi állományok, a Git nem követi őket.

## Korlátok

A rendszer a konfigurált követelményeket vizsgálja,
nem helyettesít teljes körű hálózatfelügyeleti rendszert.

A Syslog-modul lekérdezéskor elemzi a helyi
naplópuffert, nem folyamatos valós idejű monitorozás.

A konfigurációmódosító modul csak előre meghatározott,
ellenőrzött tesztműveleteket támogat.

A rendszer nem végez automatikus hibajavítást.
