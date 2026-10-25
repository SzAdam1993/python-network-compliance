
import re
from datetime import datetime
from pathlib import Path

from compliance_result import ComplianceResult
from drift import private_write
from checks.interface import (
    normalize_interface_name,
    normalize_mode,
)
from checks.trunk import expand_vlan_list

def validate_vlan(vlan_id, vlan_name):
    """
    VLAN paraméterek ellenőrzése.
    A laborban csak a normál VLAN-tartományt használjuk.
    """

    if not 2 <= vlan_id <= 1001:
        raise ValueError(
            "A VLAN-azonosító 2 és 1001 között lehet."
        )

    if vlan_id == 99:
        raise ValueError(
            "A management VLAN módosítása tiltott."
        )

    if not re.fullmatch(
        r"[A-Z][A-Z0-9_-]{0,31}",
        vlan_name,
    ):
        raise ValueError(
            "A VLAN-név nagybetűvel kezdődjön, "
            "és csak A-Z, 0-9, _ vagy - karaktereket "
            "tartalmazzon (maximum 32 karakter)."
        )


def get_vlans(connection):
    """
    A switch aktuális VLAN-táblájának lekérdezése.
    """

    output = connection.send_command(
        "show vlan brief",
        use_textfsm=True,
    )

    if not isinstance(output, list) or not output:
        raise ValueError(
            "Nem sikerült feldolgozni a VLAN-táblát."
        )

    try:
        return {
            int(row["vlan_id"]): row["vlan_name"]
            for row in output
        }

    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(
            "Hibás strukturált VLAN-adatok."
        ) from error


def backup_before_change(device_name, connection):
    """
    Teljes running-config mentése módosítás előtt.
    """

    config = connection.send_command(
        "show running-config",
        read_timeout=30,
    )

    if (
        not isinstance(config, str)
        or not re.search(r"(?m)^end\s*$", config)
    ):
        raise ValueError(
            "Nem sikerült teljes konfigurációmentést készíteni."
        )

    root = Path("backups")
    root.mkdir(exist_ok=True)
    root.chmod(0o700)

    directory = root / device_name
    directory.mkdir(exist_ok=True)
    directory.chmod(0o700)

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    path = (
        directory
        / f"{device_name}_prechange_{timestamp}.cfg"
    )

    private_write(path, config)

    return path


def create_vlan(connection, device_name, vlan_id, vlan_name):
    """
    VLAN létrehozása és visszaellenőrzése.
    A hívó felelős az előzetes jóváhagyásért.
    """

    commands = [
        f"vlan {vlan_id}",
        f"name {vlan_name}",
    ]

    output = connection.send_config_set(
        commands,
        cmd_verify=True,
        read_timeout=30,
    )

    command_error = re.search(
        r"(?im)^\s*%\s*(?:Invalid input|Error|"
        r"Incomplete command|Ambiguous command)",
        output,
    )

    # Minden esetben újra lekérdezzük az eszközt.
    actual_vlans = get_vlans(connection)
    actual_name = actual_vlans.get(vlan_id)

    if command_error:
        status = "FAIL"
        message = "A Cisco konfigurációs hibát jelzett."

    elif actual_name == vlan_name:
        status = "PASS"
        message = (
            "A VLAN létrejött, és a visszaellenőrzés sikeres."
        )

    else:
        status = "FAIL"
        message = (
            "A módosítás után a VLAN nem megfelelő."
        )

    return ComplianceResult(
        device=device_name,
        category="CHANGE",
        target=f"VLAN {vlan_id}",
        status=status,
        message=message,
        expected=vlan_name,
        actual=actual_name,
    )


def get_access_vlan(connection, interface_name):
    """
    Egy access port aktuális VLAN-jának lekérdezése.
    Trunk vagy ismeretlen mód esetén hibát ad.
    """

    output = connection.send_command(
        "show interfaces switchport",
        use_textfsm=True,
    )

    if not isinstance(output, list) or not output:
        raise ValueError(
            "A switchport-adatok nem dolgozhatók fel."
        )

    expected_name = normalize_interface_name(
        interface_name
    )

    for row in output:

        if not isinstance(row, dict):
            raise ValueError("Hibás switchport-adatsor.")

        raw_name = row.get("interface")

        if not isinstance(raw_name, str):
            raise ValueError("Hiányzik az interfész neve.")

        actual_name = normalize_interface_name(
            raw_name
        )

        if actual_name != expected_name:
            continue

        admin_mode = normalize_mode(
            row.get("admin_mode", "")
        )

        if admin_mode != "access":
            raise ValueError(
                f"{interface_name}: "
                "nem konfigurált access port. "
                f"Adminisztratív mód: {admin_mode}"
            )

        try:
            return int(row["access_vlan"])

        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(
                "Nem olvasható az access VLAN."
            ) from error

    raise ValueError(
        f"Az interfész nem található: {interface_name}"
    )


def set_access_vlan(
    connection,
    device_name,
    interface_name,
    vlan_id,
):
    """
    Meglévő access port VLAN-jának módosítása,
    majd utólagos visszaellenőrzése.
    """

    commands = [
        f"interface {interface_name}",
        f"switchport access vlan {vlan_id}",
    ]

    output = connection.send_config_set(
        commands,
        cmd_verify=True,
        read_timeout=30,
    )

    command_error = re.search(
        r"(?im)^\s*%\s*(?:Invalid input|Error|"
        r"Incomplete command|Ambiguous command)",
        output,
    )

    # A tényleges állapotot újra lekérdezzük.
    actual_vlan = get_access_vlan(
        connection,
        interface_name,
    )

    if command_error:
        status = "FAIL"
        message = "A Cisco konfigurációs hibát jelzett."

    elif actual_vlan == vlan_id:
        status = "PASS"
        message = (
            "Az access VLAN módosítása és "
            "visszaellenőrzése sikeres."
        )

    else:
        status = "FAIL"
        message = (
            "Az access VLAN eltér a kívánt értéktől."
        )

    return ComplianceResult(
        device=device_name,
        category="CHANGE",
        target=f"{interface_name} access VLAN",
        status=status,
        message=message,
        expected=vlan_id,
        actual=actual_vlan,
    )


def get_trunk_allowed_vlans(connection, interface_name):
    """
    Lekérdezi egy trunk engedélyezett VLAN-listáját.
    """

    output = connection.send_command(
        "show interfaces switchport",
        use_textfsm=True,
    )

    if not isinstance(output, list) or not output:
        raise ValueError(
            "A switchport-kimenet nem feldolgozható."
        )

    target = normalize_interface_name(interface_name)

    for row in output:

        if not isinstance(row, dict):
            raise ValueError("Hibás switchport-adatsor.")

        raw_name = row.get("interface")

        if not isinstance(raw_name, str):
            raise ValueError("Hiányzik az interfész neve.")

        if normalize_interface_name(raw_name) != target:
            continue

        administrative = normalize_mode(
            row.get("admin_mode", "")
        )

        operational = normalize_mode(
            row.get("mode", "")
        )

        if administrative != "trunk" or operational != "trunk":
            raise ValueError(
                f"{interface_name}: nem működő trunk port "
                f"(admin={administrative}, oper={operational})."
            )

        try:
            allowed = expand_vlan_list(
                row["trunking_vlans"]
            )

        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(
                "Hibás trunk allowed VLAN-lista."
            ) from error

        if not allowed or 99 not in allowed:
            raise ValueError(
                "A management VLAN 99 hiányzik. "
                "Módosítás tiltva."
            )

        return allowed

    raise ValueError(
        f"Nem található a trunk port: {interface_name}"
    )


def change_trunk_allowed_vlan(
    connection,
    device_name,
    interface_name,
    vlan_id,
    operation,
    expected_before,
):
    """
    Egyetlen teszt-VLAN hozzáadása vagy eltávolítása,
    majd a teljes allowed VLAN-lista visszaellenőrzése.
    """

    if (
        device_name != "SW1"
        or interface_name != "Ethernet0/1"
        or vlan_id != 40
        or operation not in ("add", "remove")
    ):
        raise ValueError(
            "Nem engedélyezett trunk-módosítás."
        )

    before = get_trunk_allowed_vlans(
        connection,
        interface_name,
    )

    if before != expected_before:
        raise RuntimeError(
            "A trunk állapota időközben megváltozott."
        )

    desired = (
        before | {vlan_id}
        if operation == "add"
        else before - {vlan_id}
    )

    if desired == before or 99 not in desired:
        raise ValueError(
            "Érvénytelen vagy már végrehajtott művelet."
        )

    output = connection.send_config_set(
        [
            f"interface {interface_name}",
            f"switchport trunk allowed vlan "
            f"{operation} {vlan_id}",
        ],
        cmd_verify=True,
        read_timeout=30,
    )

    command_error = re.search(
        r"(?im)^\s*%\s*(?:Invalid input|Error|"
        r"Incomplete command|Ambiguous command)",
        output,
    )

    # Nem elég, hogy a parancsot elfogadta az eszköz:
    # a teljes VLAN-listát újra lekérdezzük.
    actual = get_trunk_allowed_vlans(
        connection,
        interface_name,
    )

    status = (
        "PASS"
        if not command_error and actual == desired
        else "FAIL"
    )

    return ComplianceResult(
        device=device_name,
        category="CHANGE",
        target=f"{interface_name} trunk allowed",
        status=status,
        message=(
            "A trunk VLAN-lista módosítása "
            "és ellenőrzése sikeres."
            if status == "PASS"
            else
            "A trunk VLAN-lista nem felel meg "
            "a célállapotnak."
        ),
        expected=sorted(desired),
        actual=sorted(actual),
    )
