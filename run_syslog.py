
import argparse

import yaml

from compliance_result import ComplianceResult
from connection import connect_to_device
from reporter import print_report, save_json_report
from syslog_parser import analyze_syslog


def main():

    parser = argparse.ArgumentParser(
        description="Cisco Syslog események feldolgozása."
    )

    parser.add_argument(
        "--device",
        help="Csak a megadott eszköz vizsgálata.",
    )

    args = parser.parse_args()

    with open(
        "inventory.yaml",
        "r",
        encoding="utf-8",
    ) as file:
        inventory = yaml.safe_load(file)

    if (
        not isinstance(inventory, dict)
        or not isinstance(inventory.get("devices"), list)
    ):
        raise ValueError(
            "Hibás inventory.yaml."
        )

    devices = inventory["devices"]

    if args.device:

        devices = [
            device
            for device in devices
            if device["name"] == args.device
        ]

        if not devices:
            parser.error(
                f"Nem található eszköz: {args.device}"
            )

    results = []

    for device in devices:

        name = device["name"]

        try:

            with connect_to_device(device) as connection:

                output = connection.send_command(
                    "show logging",
                    read_timeout=30,
                )

                module_results = analyze_syslog(
                    name,
                    output,
                )

                results.extend(module_results)

        except Exception as error:

            print(
                f"[HIBA] {name}: "
                f"{type(error).__name__}: {error}"
            )

            results.append(
                ComplianceResult(
                    device=name,
                    category="SYSLOG",
                    target="Lekérdezés",
                    status="NOT_EVALUATED",
                    message=(
                        f"A napló nem értékelhető: "
                        f"{type(error).__name__}"
                    ),
                )
            )

    if not results:
        raise RuntimeError(
            "Nem keletkezett Syslog-eredmény."
        )

    print_report(
        results,
        title="NETWORK SYSLOG ANALYSIS REPORT",
    )

    save_json_report(
        results,
        prefix="syslog",
    )


if __name__ == "__main__":
    main()
