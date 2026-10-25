
import traceback

import yaml

from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from compliance_result import ComplianceResult
from connection import connect_to_device

from checks.vlan import check_vlans
from checks.interface import check_interfaces
from checks.trunk import check_trunks
from checks.acl import check_acls

from reporter import print_report, save_json_report


# Az elérhető ellenőrző modulok
CHECKS = (
    ("vlans", "VLAN", check_vlans),
    ("interfaces", "INTERFACE", check_interfaces),
    ("trunks", "TRUNK", check_trunks),
    ("acls", "ACL", check_acls),
)


def read_yaml(path):
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def run_check(device_name, category, checker, connection, expected):
    """
    Egy ellenőrző modul elkülönített futtatása.
    Hiba esetén NOT_EVALUATED eredményt ad vissza.
    """

    try:
        checked = checker(
            device_name,
            connection,
            expected,
        )

        # A modulnak nem szabad üres eredményt adnia.
        if not isinstance(checked, list) or not checked:
            raise ValueError(
                "A modul üres vagy nem lista típusú eredményt adott."
            )

        # Csak megfelelő ComplianceResult objektumokat fogadunk el.
        if any(
            not isinstance(item, ComplianceResult)
            or item.device != device_name
            or item.category != category
            or item.status not in (
                "PASS",
                "FAIL",
                "WARNING",
                "NOT_EVALUATED",
            )
            for item in checked
        ):
            raise ValueError(
                "A modul hibás ComplianceResult adatot adott vissza."
            )

        return checked

    except Exception as error:

        print(
            f"[ERROR] {device_name} / {category}: "
            f"{type(error).__name__}: {error}"
        )

        traceback.print_exc()

        return [
            ComplianceResult(
                device=device_name,
                category=category,
                target="Modul futtatása",
                status="NOT_EVALUATED",
                message=(
                    f"Modulhiba: "
                    f"{type(error).__name__}: {error}"
                ),
            )
        ]


def main():

    inventory = read_yaml("inventory.yaml")
    expected_state = read_yaml("expected_state.yaml")

    if (
        not isinstance(inventory, dict)
        or not isinstance(inventory.get("devices"), list)
    ):
        raise ValueError(
            "Hibás inventory.yaml: hiányzó devices lista."
        )

    if not isinstance(expected_state, dict):
        raise ValueError(
            "Hibás expected_state.yaml: nem YAML szótár."
        )

    results = []

    print(
        "[INFO] VLAN, interface, trunk és ACL "
        "ellenőrzések indítása."
    )

    for device in inventory["devices"]:

        name = device["name"]
        expected = expected_state.get(name, {})

        if not isinstance(expected, dict):
            raise ValueError(
                f"Hibás elvárt állapot: {name}."
            )

        # Csak akkor kapcsolódunk, ha van ellenőrizendő kategória.
        if not any(
            key in expected
            for key, _, _ in CHECKS
        ):
            continue

        try:

            with connect_to_device(device) as connection:

                for key, category, checker in CHECKS:

                    if key in expected:

                        module_results = run_check(
                            device_name=name,
                            category=category,
                            checker=checker,
                            connection=connection,
                            expected=expected[key],
                        )

                        results.extend(module_results)

        except NetmikoAuthenticationException:

            results.append(
                ComplianceResult(
                    device=name,
                    category="DEVICE",
                    target="SSH",
                    status="NOT_EVALUATED",
                    message="SSH hitelesítési hiba.",
                )
            )

        except NetmikoTimeoutException:

            results.append(
                ComplianceResult(
                    device=name,
                    category="DEVICE",
                    target="SSH",
                    status="NOT_EVALUATED",
                    message=(
                        "SSH időtúllépés vagy nem elérhető eszköz."
                    ),
                )
            )

        except Exception as error:

            traceback.print_exc()

            results.append(
                ComplianceResult(
                    device=name,
                    category="DEVICE",
                    target="Feldolgozás",
                    status="NOT_EVALUATED",
                    message=(
                        f"Váratlan eszközhiba: "
                        f"{type(error).__name__}: {error}"
                    ),
                )
            )

    if not results:
        raise RuntimeError(
            "Egyetlen ellenőrzés sem futott le."
        )

    print_report(results)
    save_json_report(results)


if __name__ == "__main__":
    main()
