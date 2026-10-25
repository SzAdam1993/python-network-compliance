
import argparse

import yaml

from compliance_result import ComplianceResult
from connection import connect_to_device
from drift import capture_baseline, check_device_drift
from reporter import print_report, save_json_report


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Cisco konfigurációk referencia- "
            "és drift-vizsgálata."
        )
    )

    parser.add_argument(
        "action",
        choices=("baseline", "check"),
    )

    parser.add_argument(
        "--device",
        help="Csak egy eszköz, például SW1",
    )

    parser.add_argument(
        "--replace",
        action="store_true",
        help="Meglévő referencia szándékos felülírása.",
    )

    args = parser.parse_args()

    if args.action != "baseline" and args.replace:
        parser.error(
            "A --replace csak baseline módban használható."
        )

    with open(
        "inventory.yaml", "r", encoding="utf-8"
    ) as file:
        inventory = yaml.safe_load(file)

    if (
        not isinstance(inventory, dict)
        or not isinstance(inventory.get("devices"), list)
    ):
        raise ValueError(
            "Hibás inventory.yaml: devices lista szükséges."
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
    captured = 0

    for device in devices:

        name = device["name"]

        try:
            role = device.get("role")

            if role not in ("router", "switch"):
                raise ValueError(
                    f"Hiányzó vagy érvénytelen eszközszerep: {name}"
                )

            track_vlans = role == "switch"

            with connect_to_device(device) as connection:

                if args.action == "baseline":

                    path = capture_baseline(
                        name,
                        connection,
                        replace=args.replace,
                        include_vlans=track_vlans,
                    )

                    captured += 1

                    print(
                        f"[BASELINE OK] {name}: {path}"
                    )

                else:
                    results.append(
                        check_device_drift(
                            name,
                            connection,
                            include_vlans=track_vlans,
                        )
                    )

        except Exception as error:

            print(
                f"[HIBA] {name}: "
                f"{type(error).__name__}: {error}"
            )

            results.append(
                ComplianceResult(
                    device=name,
                    category="DRIFT",
                    target="SSH / feldolgozás",
                    status="NOT_EVALUATED",
                    message=(
                        f"{type(error).__name__}: {error}"
                    ),
                )
            )

    if args.action == "baseline":

        print(
            f"Referenciafelvételek: "
            f"{captured}/{len(devices)}"
        )

    else:

        if not results:
            raise RuntimeError(
                "Nem keletkezett drift-eredmény."
            )

        print_report(
            results,
            title="CONFIGURATION DRIFT REPORT",
        )

        save_json_report(
            results,
            prefix="drift",
        )


if __name__ == "__main__":
    main()
