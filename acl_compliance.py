import os
import re
import yaml

from dotenv import load_dotenv
from connection import connect_to_device
from netmiko.exceptions import(
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

def normalize_whitespace(text):
    """Felesleges szóközök eltávolítása."""
    return " ".join(text.split())

def parse_acl_section(output, acl_name, acl_type):
    """
    Egy named ACL running-config részét struktúrált szabálylistává alakítja.
    """

    expected_header = (
        f"ip access-list {acl_type} {acl_name}"
    )

    header_found = False
    rules = []

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        normalized_line = normalize_whitespace(line)

        if normalized_line == expected_header:
            header_found = True
            continue

        match = re.match(
            r"^(\d+)\s+(.+)$",
            normalized_line,
        )

        if match:
            sequence = int(match.group(1))
            rule = normalize_whitespace(match.group(2))

            rules.append(
                {
                    "sequence": sequence,
                    "rule": rule,
                }
            )
    return header_found, rules


def get_acl_bindings(interface_output, interface_name):
    bindings = []
    inside_interface = False

    expected_header = f"interface {interface_name}"

    for raw_line in interface_output.splitlines():
        line = raw_line.strip()

        if line == expected_header:
            inside_interface = True
            continue

        if inside_interface:
            if raw_line and not raw_line[0].isspace():
                break

            if line.startswith("ip access-group "):
                bindings.append(line)

    return bindings

def is_dangerously_permissive(rule):
    """
    Egyszerű biztonsági szabály:
    permit ip any any esetén kritikus figyelmeztetés.
    """

    normalized_rule = normalize_whitespace(
        rule
    ).lower()

    return normalized_rule == "permit ip any any"

load_dotenv()

username = os.getenv("DEVICE_USERNAME")
password = os.getenv("DEVICE_PASSWORD")

if not username or not password:
    raise RuntimeError(
        "A DEVICE_USERNAME vagy DEVICE_PASSWORD"
        "környezeti változó hiányzik. "
    )
with open(
    "inventory.yaml",
    "r",
    encoding="utf-8",
) as file: 
    inventory = yaml.safe_load(file)

with open(
    "expected_state.yaml",
    "r",
    encoding="utf-8",
) as file:
    expected_state = yaml.safe_load(file)

for device in inventory["devices"]:
    name = device["name"]

    if name not in expected_state:
        continue

    if "acls" not in expected_state[name]:
        continue

    print(
        f"\n===== {name} ACL ELLENŐRZÉS ====="
    )

    connection_parameters = {
        "device_type": device["device_type"],
        "host": device["host"],
        "username": username,
        "password": password,
    }

    try:
        with connect_to_device(device) as connection:

            for acl_name, expected_acl in (
                expected_state[name]["acls"].items()
            ):
                print(
                    f"\n  ----- ACL: {acl_name} -----"
                )

                acl_type = expected_acl["type"]

                interface_name = (
                    expected_acl["interface"]
                )

                expected_direction = (
                    expected_acl["direction"]
                )

                acl_command = "show running-config | section ^ip access-list"

                acl_output = (
                    connection.send_command(
                        acl_command,
                        read_timeout=30,
                    )
                )

 
                interface_output = connection.send_command(
                        "show running-config",
                        read_timeout=30,
                )

                acl_found, actual_rules = (
                    parse_acl_section(
                        acl_output,
                        acl_name,
                        acl_type,
                    )
                )

                acl_failed = False

                if not acl_found:
                    print(
                        f"[FAIL] {acl_name}: "
                        "az ACL nem található. "
                    )
                    acl_failed = True
                    continue

                print(
                    f"[PASS] {acl_name}: "
                    "az ACL létezik. "
                )
#elvárt szabályok előkészítése
                expected_rules = []
                for rule in expected_acl["rules"]:
                    expected_rules.append(
                        {
                            "sequence": int(
                                rule["sequence"]
                            ),
                            "rule": (
                                normalize_whitespace(
                                    rule["rule"]
                                )
                            ),
                        }
                    )
                expected_by_sequence = {
                    rule["sequence"]: rule["rule"]
                    for rule in actual_rules
                }


                actual_by_sequence = {
                    rule["sequence"]: rule["rule"]
                    for rule in actual_rules
                }

#elvárt szabályok ellenőrzése
                for expected_rule in expected_rules:

                    sequence = (
                        expected_rule["sequence"]
                    )

                    expected_text = (
                        expected_rule["rule"]
                    )

                    if sequence not in ( 
                        actual_by_sequence
                    ):
                        print(
                            f"[FAIL] szabály {sequence}:"
                            "hiányzik."
                        )
                        acl_failed = True
                        continue

                    actual_text = (
                        actual_by_sequence[sequence]
                    )

                    if (
                        actual_text == expected_text
                    ):
                        print(
                            f"[PASS] szabály"
                            f"{sequence}: "
                            f"{actual_text}"
                        )
                    else:
                        print(
                            f"[FAIL] szabály: "
                            f"{sequence}: "
                        )

                        print(
                            f" elvárt: "
                            f"{expected_text}"
                        )

                        print(
                            f" tényleges: "
                            f"{actual_text}"
                        )

                        acl_failed = True

#nem várt szabályok keresése

                for actual_rule in actual_rules:
                    sequence = (
                        actual_rule["sequence"]
                    )

                    if sequence not in (
                        expected_by_sequence
                    ):
                        print(
                            f"[FAIL] nem várt"
                            f"szabály {sequence}: "
                            f"{actual_rule['rule']}"
                        )

                        acl_failed = True

#sorrend ellenőrzése

                expected_order = [
                    rule["sequence"]
                    for rule in expected_rules
                ]

                actual_order = [
                    rule["sequence"]
                    for rule in actual_rules
                ]

                if actual_order == expected_order:
                    print(
                        "[PASS] szabálysorrend: "
                        f"{actual_order}"
                    )
                else:
                    print(
                        "[FAIL] szabálysorred:"
                    )

                    print(
                        f" elvárt: "
                        f"{expected_order}"
                    )

                    print(
                        f" tényleges: "
                        f"{actual_order}"
                    )

                    acl_failed = True

#veszélyesen permissív szabály felismerése

                for actual_rule in actual_rules:

                    if is_dangerously_permissive(
                        actual_rule["rule"]
                    ):
                        print(
                            "[KRITIKUS]"
                            f"szabály "
                            f"{actual_rule['sequence']}: "
                            "permit ip any any"
                        )

                        acl_failed = True

#acl interfészhez rendelése

                bindings = get_acl_bindings(
                    interface_output,
                    interface_name,
                )

                expected_binding = (
                    f"ip access-group "
                    f"{acl_name} "
                    f"{expected_direction}"
                )

                if expected_binding in bindings:
                    print(
                        f"[PASS] kötés: "
                        f"{interface_name} "
                        f"{expected_direction}"
                    )

                else:
                    print(
                        f"[FAIL] ACL-kötés: "
                    )

                    print(
                        f"  elvárt: "
                        f"{expected_binding}"
                    )

                    if bindings:
                        print(
                            f" tényleges: "
                            f"{bindings}"
                        )

                    else:
                        print(
                            " tényleges: "
                            "nincs ACL-kötés"
                        )
                    acl_failed = True
                if acl_failed:
                    print(
                        f"[ÖSSZESÍTÉS] "
                        f"{acl_name}: FAIL"
                    )
                else:
                    print(
                        f"[ÖSSZESÍTÉS] "
                        f"{acl_name}: PASS"
                    )

    except NetmikoAuthenticationException:
        print(
            f"[HITELESÍTÉSI HIBA] {name}"
        )

    except NetmikoTimeoutException:
        print(
            f"[NEM ELÉRHETŐ] {name}"
        )

    except Exception as error:
        print(
            f"[EGYÉB HIBA]"
            f"{name}: {error}"
        )
