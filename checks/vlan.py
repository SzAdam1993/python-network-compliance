from compliance_result import ComplianceResult

def check_vlans(device_name, connection, expected_vlans):

    output = connection.send_command(
        "show vlan brief",
        use_textfsm=True,
    )

    if not isinstance(output, list) or not output:
        return [
            ComplianceResult(
                device=device_name,
                category="VLAN",
                target="VLAN lekérdezése",
                status="NOT_EVALUATED",
                message="A VLAN-kimenet nem dolgozható fel struktúráltan. ",
            )
        ]

    try:
        actual_vlans = {
            int(vlan["vlan_id"]): vlan["vlan_name"]
            for vlan in output
        }

    except (KeyError, ValueError, TypeError):
        return [
            ComplianceResult(
                device=device_name,
                category="VLAN",
                target="VLAN feldolgozás",
                status="NOT_EVALUATED",
                message="Hibás vagy hiányos VLAN-adatok. ",
            )
        ]

    result = []

    for vlan_id, expected_name in expected_vlans.items():

        vlan_id = int(vlan_id)
        actual_name = actual_vlans.get(vlan_id)

        if actual_name is None:
            status = "FAIL"
            message = "A VLAN hiányzik. "

        elif actual_name != expected_name:
            status = "FAIL"
            message = "A VLAN neve eltér az elvárttól. "

        else:
            status = "PASS"
            message = "A VLAN megfelelő. "

        result.append(
            ComplianceResult(
                device=device_name,
                category="VLAN",
                target=f"VLAN {vlan_id}",
                status=status,
                message=message,
                expected=expected_name,
                actual=actual_name,
            )
        )

    return result
