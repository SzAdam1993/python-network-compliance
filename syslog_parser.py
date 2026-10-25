
import re
from collections import defaultdict

from compliance_result import ComplianceResult


EVENT_RE = re.compile(
    r"%(?P<facility>[A-Z][A-Z0-9_]*)-"
    r"(?P<severity>[0-7])-"
    r"(?P<mnemonic>[A-Z0-9_]+):\s*"
    r"(?P<text>.*)"
)

INTERFACE_RE = re.compile(
    r"(?:line protocol on\s+)?"
    r"interface\s+([\w./-]+),\s*"
    r"changed state to\s+(up|down)\b",
    re.IGNORECASE,
)

BUFFER_RE = re.compile(
    r"(?im)^\s*Log Buffer"
    r"(?:\s*\([^\n)]*\))?\s*:"
)


def analyze_syslog(device_name, raw):
    """
    Cisco show logging kimenet feldolgozása.

    Az eredmény négy ComplianceResult objektum:
    interfész, login, konfigurációmódosítás, flap.
    """

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(
            "Üres vagy érvénytelen show logging kimenet."
        )

    if re.search(
        r"(?im)^\s*(?:Syslog logging|Buffer logging)"
        r":\s*disabled\b",
        raw,
    ):
        raise ValueError(
            "A helyi naplózás nincs engedélyezve."
        )

    buffer_match = BUFFER_RE.search(raw)

    if not buffer_match:
        raise ValueError(
            "Nem található a Log Buffer szakasz. "
            "A napló nem értékelhető megbízhatóan."
        )

    # Kizárólag a helyi naplópuffer üzenetei.
    events = []

    for line in raw[buffer_match.end():].splitlines():

        match = EVENT_RE.search(line)

        if match:
            events.append(match.groupdict())

    # 1. Interfészállapot-változások
    link_events = [
        event for event in events
        if event["facility"] in ("LINK", "LINEPROTO")
        and event["mnemonic"] == "UPDOWN"
    ]

    # 2. Sikertelen bejelentkezések
    login_events = [
        event for event in events
        if event["facility"] in ("SEC_LOGIN", "LOGIN")
        and event["mnemonic"] == "LOGIN_FAILED"
    ]

    # 3. Konfigurációmódosítások
    config_events = [
        event for event in events
        if event["facility"] == "SYS"
        and event["mnemonic"] == "CONFIG_I"
    ]

    # 4. Ismétlődő UP/DOWN állapotváltások
    by_interface = defaultdict(
        lambda: {"LINK": [], "LINEPROTO": []}
    )

    for event in link_events:

        match = INTERFACE_RE.search(event["text"])

        if not match:
            continue

        interface_name, state = match.groups()

        by_interface[interface_name][
            event["facility"]
        ].append(state.lower())

    flap_interfaces = []

    for interface_name, sources in by_interface.items():

        # Ha van fizikai LINK napló, azt részesítjük
        # előnyben, hogy a LINEPROTO ne duplázzon.
        states = (
            sources["LINK"]
            if sources["LINK"]
            else sources["LINEPROTO"]
        )

        transitions = []

        for state in states:
            if not transitions or transitions[-1] != state:
                transitions.append(state)

        # Legalább négy váltakozó állapotüzenet.
        # Időablak nélkül csak flap-gyanút jelzünk.
        if len(transitions) >= 4:
            flap_interfaces.append(interface_name)

    def create_result(target, count, description):

        return ComplianceResult(
            device=device_name,
            category="SYSLOG",
            target=target,
            status="WARNING" if count else "PASS",
            message=(
                f"{description}: {count} üzenet "
                "a helyi naplópufferben."
            ),
            expected=0,
            actual=count,
        )

    results = [
        create_result(
            "Interfész UP/DOWN",
            len(link_events),
            "Állapotváltozások",
        ),
        create_result(
            "Sikertelen login",
            len(login_events),
            "Sikertelen bejelentkezések",
        ),
        create_result(
            "Konfigurációmódosítás",
            len(config_events),
            "Konfigurációmódosítási események",
        ),
    ]

    results.append(
        ComplianceResult(
            device=device_name,
            category="SYSLOG",
            target="Flap gyanú",
            status=(
                "WARNING"
                if flap_interfaces
                else "PASS"
            ),
            message=(
                "Ismétlődő állapotváltás: "
                + ", ".join(sorted(flap_interfaces))
                if flap_interfaces
                else "Nem észleltünk flap-gyanút "
                     "a rendelkezésre álló naplóban."
            ),
            expected=[],
            actual=sorted(flap_interfaces),
        )
    )

    return results
