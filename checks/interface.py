from compliance_result import ComplianceResult

def normalize_interface_name(interface_name):
    replacements = {
        "Ethernet": "Et",
        "FastEthernet": "Fa",
        "GigabitEthernet": "Gi",
        "TenGigabitEthernet": "Te",
    }

    for long_name, short_name in replacements.items():
        if interface_name.startswith(long_name):
            return interface_name.replace(
                long_name, short_name, 1
            )
    return interface_name

def normalize_mode(mode):
    mode = str(mode).strip().lower()

    if "access" in mode:
        return "access"

    if "trunk" in mode:
        return "trunk"

    return mode

def check_interfaces(device_name, connection, expected_interfaces):

    results = []

    switchport_data = connection.send_command(
        "show interfaces switchport",
        use_textfsm=True,
    )

    interface_data = connection.send_command(
        "show ip interface brief",
        use_textfsm=True,
    )

    if (
        not isinstance(switchport_data, list)
        or not isinstance(interface_data, list)
        or not switchport_data
        or not interface_data
    ):
        return [
            ComplianceResult(
                device=device_name,
                category="INTERFACE",
                target="Lekérdezés",
                status="NOT_EVALUATED",
                message="Az interfészadatok feldolgozása sikertelen. ",
            )
        ]

    try:
        switchports = {
            normalize_interface_name(row["interface"]): row
            for row in switchport_data
        }

        interface_states = {
            normalize_interface_name(row["interface"]): row
            for row in interface_data
        }


    except (KeyError, TypeError):
        return [
            ComplianceResult(
                device=device_name,
                category="INTERFACE",
                target="Feldolgozás",
                status="NOT_EVALUATED",
                message="Hiányos strukturált interfészadatok. ",
            )
        ]

    for interface_name, expected in expected_interfaces.items():

        name = normalize_interface_name(interface_name)

        if name not in switchports:
            results.append(
                ComplianceResult(
                    device=device_name,
                    category="INTERFACE",
                    target=name,
                    status="FAIL",
                    message="Az interfész nem található. ",
                    expected=expected,
                    actual=None,
                )
            )
            continue

        actual = switchports[name]

#1.konfigurált switchport üzemmód

        expected_mode = expected["mode"]
        raw_mode = actual.get("admin_mode")

        if not raw_mode:
            results.append(
                ComplianceResult(
                    device=device_name,
                    category="INTERFACE",
                    target=f"{name} mód",
                    status="NOT_EVALUATED",
                    message="Hiányzik az üzemmód adata. ",
                )
            )
        else:
            actual_mode = normalize_mode(raw_mode)

            results.append(
                ComplianceResult(
                    device=device_name,
                    category="INTERFACE",
                    target=f"{name} mód",
                    status=(
                        "PASS" if actual_mode == expected_mode
                        else "FAIL"
                    ),
                    message="Konfigurált switchport üzemmód. ",
                    expected=expected_mode,
                    actual=actual_mode,
                )
            )

#2. Access VLAN ellenőrzése

        expected_vlan = int(expected["access_vlan"])

        try:
            actual_vlan = int(actual["access_vlan"])
        except (ValueError, TypeError, KeyError):
            actual_vlan = None

        results.append(
            ComplianceResult(
                device=device_name,
                category="INTERFACE",
                target=f"{name} access VLAN ",
                status=(
                    "NOT_EVALUATED" if actual_vlan is None
                    else "PASS" if actual_vlan == expected_vlan
                    else "FAIL"
                ),
                message="Access VLAN hozzárendelés. ",
                expected=expected_vlan ,
                actual=actual_vlan,
            )
        )

#3. Interfész működési állapota

        if name not in interface_states:
            results.append(
                ComplianceResult(
                    device=device_name,
                    category="INTERFACE",
                    target=f"{name} állapot",
                    status="NOT_EVALUATED",
                    message="Az interfészállapot nem található. ",
                )
            )
            continue

        actual_state = interface_states[name].get("status")

        expected_state = expected["admin_state"]

        results.append(
            ComplianceResult(
                device=device_name,
                category="INTERFACE",
                target=f"{name} állapot ",
                status=(
                    "NOT_EVALUATED" if not actual_state
                    else "PASS" if actual_state == expected_state
                    else "FAIL"
                ),
                message="Interfész működési állapota. ",
                expected=expected_state,
                actual=actual_state,
            )
        )

    return results
