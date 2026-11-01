
import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from connection import connect_to_device
from drift import private_write, safe_device_name


def main():
    parser = argparse.ArgumentParser(
        description="Cisco Syslog naplók biztonságos mentése."
    )

    parser.add_argument(
        "--device",
        help="Csak a megadott eszköz mentése.",
    )

    parser.add_argument(
        "--label",
        default="snapshot",
        help="A mentés megnevezése.",
    )

    args = parser.parse_args()

    if not re.fullmatch(
        r"[A-Za-z0-9_-]{1,24}",
        args.label,
    ):
        parser.error("Érvénytelen mentési címke.")

    with open(
        "inventory.yaml",
        "r",
        encoding="utf-8",
    ) as file:
        inventory = yaml.safe_load(file)

    devices = inventory["devices"]

    if args.device:
        devices = [
            device
            for device in devices
            if device["name"] == args.device
        ]

        if not devices:
            parser.error("Ismeretlen eszköz.")

    output_dir = Path("evidence/syslog")
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )
    output_dir.chmod(0o700)

    failures = 0

    for device in devices:
        name = safe_device_name(device["name"])

        try:
            with connect_to_device(device) as connection:
                raw = connection.send_command(
                    "show logging",
                    read_timeout=30,
                )

            if (
                not isinstance(raw, str)
                or "Log Buffer" not in raw
            ):
                raise ValueError(
                    "Hiányos Syslog-kimenet."
                )

            timestamp = datetime.now(
                timezone.utc
            ).strftime("%Y%m%dT%H%M%S_%fZ")

            path = output_dir / (
                f"{name}_{args.label}_{timestamp}.log"
            )

            private_write(path, raw)

            print(f"[MENTÉS OK] {name}: {path}")

        except Exception as error:
            failures += 1
            print(
                f"[MENTÉSI HIBA] {name}: "
                f"{type(error).__name__}: {error}"
            )

    if failures:
        raise SystemExit(1)

    print("\nMinden Syslog-mentés sikeres.")


if __name__ == "__main__":
    main()
