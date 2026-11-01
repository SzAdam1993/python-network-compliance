"""Cisco IOS helyi naplópufferének kategorizálása és időablakos flap-vizsgálata."""
import re
from collections import defaultdict
from datetime import datetime

from compliance_result import ComplianceResult
from checks.interface import normalize_interface_name

EVENT_RE = re.compile(
    r"%(?P<facility>[A-Z][A-Z0-9_]*)-"
    r"(?P<severity>[0-7])-"
    r"(?P<mnemonic>[A-Z0-9_]+):\s*"
    r"(?P<text>.*)"
)

INTERFACE_RE = re.compile(
    r"(?:line protocol on\s+)?interface\s+([\w./-]+),\s*"
    r"changed state to\s+(up|down)\b", re.IGNORECASE
)

BUFFER_RE = re.compile(
    r"(?im)^\s*Log Buffer(?:\s*\([^\n)]*\))?\s*:"
)

# Cisco IOS datetime: "Oct 28 2026 14:00:00.123 UTC:" vagy
# "Oct 28 14:00:00.123 UTC 2026:". A '*' és '.' nem megbízható óra.
TIMESTAMP_RE = re.compile(r"""
    ^\s*(?:\d{1,10}:\s*)?(?P<uncertain>[*.]?)
    (?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+
    (?P<day>\d{1,2})\s+
    (?:(?P<year_before>\d{4})\s+)?
    (?P<clock>\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)
    (?:\s+[A-Z]{2,6})?
    (?:\s+(?P<year_after>\d{4}))?
    \s*:\s*$
""", re.IGNORECASE | re.VERBOSE)

MONTHS = {
    name: month for month, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}


def parse_event_time(prefix):
    """Teljes évvel megadott, hiteles IOS-dátumot értelmez.

    Év nélküli, uptime-alapú vagy szinkronizálatlan időt nem találgat.
    """
    match = TIMESTAMP_RE.fullmatch(prefix)
    if not match or match.group("uncertain"):
        return None
    year = match.group("year_before") or match.group("year_after")
    if not year:
        return None
    try:
        month = MONTHS[match.group("month").title()]
        time = match.group("clock")
        fmt = "%H:%M:%S.%f" if "." in time else "%H:%M:%S"
        parsed_time = datetime.strptime(time, fmt).time()
        return datetime(int(year), month, int(match.group("day")),
                        parsed_time.hour, parsed_time.minute,
                        parsed_time.second, parsed_time.microsecond)
    except (ValueError, KeyError):
        return None


def find_flaps(events, window_seconds=60, threshold=4):
    """Flap-gyanú: 4 váltakozó UP/DOWN egy 60 másodperces ablakban.

    Azonos idejű, azonos állapotú duplikátumot nem számol kétszer.
    Későn beérkezett, de időbélyeges eseményeket időrendbe rendezi.
    """
    if window_seconds <= 0 or threshold < 2:
        raise ValueError("Érvénytelen flap-időablak vagy küszöb.")

    grouped = defaultdict(lambda: {"LINK": [], "LINEPROTO": []})
    incomplete = 0

    for event in events:
        if not (event["facility"] in ("LINK", "LINEPROTO")
                and event["mnemonic"] == "UPDOWN"):
            continue
        parsed = INTERFACE_RE.search(event["text"])
        timestamp = parse_event_time(event["prefix"])
        if not parsed or timestamp is None:
            incomplete += 1
            continue
        interface, state = parsed.groups()
        interface = normalize_interface_name(interface)
        grouped[interface][event["facility"]].append((timestamp, state.lower()))

    flaps = []
    for interface, sources in grouped.items():
        # A LINK és LINEPROTO ugyanarról a fizikai váltásról is értesíthet.
        
        # A több tényleges állapotváltást tartalmazó
        # eseményforrást választjuk.
        # Azonos eredmény esetén a LINK az elsődleges.

        def transition_count(records):
            states = [
                state
                for _, state in sorted(set(records))
            ]

            return sum(
                i == 0 or states[i] != states[i - 1]
                for i in range(len(states))
            )

        samples = max(
            (sources["LINK"], sources["LINEPROTO"]),
            key=transition_count,
        )

        samples = sorted(set(samples), key=lambda item: item[0])
        # Azonos másodpercben eltérő állapotok sorrendje bizonytalan.
        states_at_time = defaultdict(set)
        for when, state in samples:
            states_at_time[when].add(state)
        if any(len(states) > 1 for states in states_at_time.values()):
            incomplete += 1
            continue
        transitions = []
        for item in samples:
            if not transitions or transitions[-1][1] != item[1]:
                transitions.append(item)
        for pos in range(threshold - 1, len(transitions)):
            elapsed = (transitions[pos][0] - transitions[pos - threshold + 1][0]).total_seconds()
            if 0 <= elapsed <= window_seconds:
                flaps.append(interface)
                break

    return sorted(flaps), incomplete


def analyze_syslog(device_name, raw):
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Üres vagy érvénytelen show logging kimenet.")
    if re.search(r"(?im)^\s*(?:Syslog logging|Buffer logging):\s*disabled\b", raw):
        raise ValueError("A helyi naplózás nincs engedélyezve.")
    buffer_match = BUFFER_RE.search(raw)
    if not buffer_match:
        raise ValueError("Nem található a Log Buffer szakasz. A napló nem értékelhető.")

    events = []
    for line in raw[buffer_match.end():].splitlines():
        match = EVENT_RE.search(line)
        if match:
            events.append({**match.groupdict(), "prefix": line[:match.start()]})

    links = [e for e in events if e["facility"] in ("LINK", "LINEPROTO")
             and e["mnemonic"] == "UPDOWN"]
    logins = [e for e in events if e["facility"] in ("SEC_LOGIN", "LOGIN")
              and e["mnemonic"] == "LOGIN_FAILED"]
    configs = [e for e in events if e["facility"] == "SYS"
               and e["mnemonic"] == "CONFIG_I"]

    def count_result(target, values, description):
        return ComplianceResult(
            device=device_name, category="SYSLOG", target=target,
            status="WARNING" if values else "PASS",
            message=f"{description}: {len(values)} üzenet a helyi naplópufferben.",
            expected=0, actual=len(values),
        )

    results = [
        count_result("Interfész UP/DOWN", links, "Állapotváltozások"),
        count_result("Sikertelen login", logins, "Sikertelen bejelentkezések"),
        count_result("Konfigurációmódosítás", configs, "Konfigurációmódosítási események"),
    ]

    flaps, incomplete = find_flaps(events)
    if flaps:
        status = "WARNING"
        message = "60 mp-en belül legalább 4 váltakozó állapot: " + ", ".join(flaps)
        if incomplete:
            message += f"; {incomplete} további esemény nem értékelhető"
    elif incomplete:
        status = "NOT_EVALUATED"
        message = (f"{incomplete} UP/DOWN esemény hiányos, év nélküli vagy "
                   "bizonytalan időbélyeggel; időablak nem számítható.")
    else:
        status = "PASS"
        message = "Nincs flap-gyanú az értékelhető helyi naplópufferben."

    results.append(ComplianceResult(
        device=device_name, category="SYSLOG", target="Flap időablak (60 mp)",
        status=status, message=message, expected=[], actual=flaps,
    ))
    return results
