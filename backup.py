
import re
from datetime import datetime
from pathlib import Path

import yaml

from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from connection import connect_to_device
from drift import private_write, safe_device_name


def backup_device(device, backup_root):
    name = safe_device_name(device["name"])
    host = device["host"]

    print(f"\nKapcsolódás: {name} ({host})")

    with connect_to_device(device) as connection:
        running_config = connection.send_command(
            "show running-config",
            read_timeout=30,
        )

        if (
            not isinstance(running_config, str)
            or not re.search(
                r"(?m)^end\s*$",
                running_config,
            )
        ):
            raise ValueError(
                "Hiányos vagy érvénytelen konfigurációkimenet."
            )

        device_directory = backup_root / name
        device_directory.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )
        device_directory.chmod(0o700)

        timestamp = datetime.now().strftime(
            "%Y-%m-%d_%H-%M-%S_%f"
        )

        backup_file = (
            device_directory
            / f"{name}_{timestamp}.cfg"
        )

        private_write(
            backup_file,
            running_config,
        )

        print(f"[MENTÉS OK] {backup_file}")
        return backup_file


def main():
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
        raise ValueError("Hibás inventory.yaml.")

    backup_root = Path("backups")
    backup_root.mkdir(
        exist_ok=True,
        mode=0o700,
    )
    backup_root.chmod(0o700)

    failures = 0

    for device in inventory["devices"]:
        name = device.get("name", "ISMERETLEN")

        try:
            backup_device(device, backup_root)

        except NetmikoAuthenticationException:
            failures += 1
            print(f"[HITELESÍTÉSI HIBA] {name}")

        except NetmikoTimeoutException:
            failures += 1
            print(f"[NEM ELÉRHETŐ] {name}")

        except Exception as error:
            failures += 1
            print(
                f"[MENTÉSI HIBA] {name}: "
                f"{type(error).__name__}: {error}"
            )

    if failures:
        print(
            f"\nSikertelen mentések száma: {failures}"
        )
        raise SystemExit(1)

    print("\nMinden konfigurációmentés sikeres.")


if __name__ == "__main__":
    main()
