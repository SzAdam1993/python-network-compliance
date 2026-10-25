from compliance_result import ComplianceResult
from checks.interface import (
    normalize_interface_name,
    normalize_mode,
)


def expand_vlan_list(values):
    """VLAN-listák és tartományok halmazzá alakítása."""

    if isinstance(values, str):
        items = values.split(",")

    elif isinstance(values, (list, tuple, set)):
        items = []
        for value in values:
            items.extend(str(value).split(","))

    else:
        raise TypeError("Nem feldolgozható VLAN-lista.")

    vlans = set()

    for item in items:
        item = item.strip().upper()

        if item in ("", "NONE"):
            continue

        if item == "ALL":
            vlans.update(range(1, 4095))
            continue

        if "-" in item:
            start, end = item.split("-", 1)
            start = int(start)
            end = int(end)

            if not 1 <= start <= end <= 4094:
                raise ValueError("Hibás VLAN-tartomány.")

            vlans.update(range(start, end + 1))

        else:
            vlan_id = int(item)

            if not 1 <= vlan_id <= 4094:
                raise ValueError("Hibás VLAN-azonosító.")

            vlans.add(vlan_id)

    return vlans


def check_trunks(device_name, connection, expected_trunks):

    results = []

    switchport_data = connection.send_command(
        "show interfaces switchport",
        use_textfsm=True,
    )

    if not isinstance(switchport_data, list) or not switchport_data:
        return [
            ComplianceResult(
                device=device_name,
                category="TRUNK",
                target="Lekérdezés",
                status="NOT_EVALUATED",
                message="A switchport-adatok nem dolgozhatók fel.",
            )
        ]

    try:
        switchports = {
            normalize_interface_name(row["interface"]): row
            for row in switchport_data
        }

    except (KeyError, TypeError):
        return [
            ComplianceResult(
                device=device_name,
                category="TRUNK",
                target="Feldolgozás",
                status="NOT_EVALUATED",
                message="Hiányos switchport-adatok.",
            )
        ]

    for interface_name, expected in expected_trunks.items():

        name = normalize_interface_name(interface_name)

        if name not in switchports:
            results.append(
                ComplianceResult(
                    device=device_name,
                    category="TRUNK",
                    target=name,
                    status="FAIL",
                    message="A trunk interfész nem található.",
                    expected=expected,
                    actual=None,
                )
            )
            continue

        actual = switchports[name]

        # 1. Trunk üzemmód ellenőrzése
        expected_mode = expected["mode"]

        operational = normalize_mode(
            actual.get("mode", "")
        )

        administrative = normalize_mode(
            actual.get("admin_mode", "")
        )

        if not operational or not administrative:
            mode_status = "NOT_EVALUATED"

        elif (
            operational == expected_mode
            and administrative == expected_mode
        ):
            mode_status = "PASS"

        else:
            mode_status = "FAIL"

        results.append(
            ComplianceResult(
                device=device_name,
                category="TRUNK",
                target=f"{name} mód",
                status=mode_status,
                message="Trunk üzemmód ellenőrzése.",
                expected=expected_mode,
                actual={
                    "operational": operational,
                    "administrative": administrative,
                },
            )
        )

        # 2. Native VLAN ellenőrzése
        expected_native = int(expected["native_vlan"])

        try:
            actual_native = int(actual["native_vlan"])
        except (KeyError, ValueError, TypeError):
            actual_native = None

        if actual_native is None:
            native_status = "NOT_EVALUATED"
        elif actual_native == expected_native:
            native_status = "PASS"
        else:
            native_status = "FAIL"

        results.append(
            ComplianceResult(
                device=device_name,
                category="TRUNK",
                target=f"{name} native VLAN",
                status=native_status,
                message="Native VLAN ellenőrzése.",
                expected=expected_native,
                actual=actual_native,
            )
        )

        # 3. Allowed VLAN-lista ellenőrzése
        expected_vlans = set(
            int(vlan) for vlan in expected["allowed_vlans"]
        )

        try:
            actual_vlans = expand_vlan_list(
                actual["trunking_vlans"]
            )

        except (KeyError, ValueError, TypeError):
            results.append(
                ComplianceResult(
                    device=device_name,
                    category="TRUNK",
                    target=f"{name} allowed VLAN",
                    status="NOT_EVALUATED",
                    message="A VLAN-lista nem dolgozható fel.",
                    expected=sorted(expected_vlans),
                    actual=None,
                )
            )
            continue

        missing = expected_vlans - actual_vlans
        unexpected = actual_vlans - expected_vlans

        if not missing and not unexpected:
            status = "PASS"
            message = "Az engedélyezett VLAN-lista megfelelő."

        else:
            status = "FAIL"
            message = (
                f"Hiányzó VLAN-ok: {sorted(missing)}; "
                f"nem várt VLAN-ok: {sorted(unexpected)}"
            )

        results.append(
            ComplianceResult(
                device=device_name,
                category="TRUNK",
                target=f"{name} allowed VLAN",
                status=status,
                message=message,
                expected=sorted(expected_vlans),
                actual=sorted(actual_vlans),
            )
        )

    return results
