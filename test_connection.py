
import yaml

from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from connection import connect_to_device


def main():
    with open(
        "inventory.yaml",
        "r",
        encoding="utf-8",
    ) as file:
        inventory = yaml.safe_load(file)

    failures = 0

    for device in inventory["devices"]:
        name = device["name"]
        host = device["host"]

        print(f"\nKapcsolódás: {name} ({host})")

        try:
            with connect_to_device(device) as connection:
                output = connection.send_command(
                    "show ip interface brief"
                )

            if not output.strip():
                raise ValueError("Üres parancskimenet.")

            print(f"[PASS] {name}: SSH-kapcsolat")
            print(output)

        except NetmikoAuthenticationException:
            failures += 1
            print(f"[HIBA] {name}: hitelesítési hiba")

        except NetmikoTimeoutException:
            failures += 1
            print(f"[HIBA] {name}: időtúllépés")

        except Exception as error:
            failures += 1
            print(
                f"[HIBA] {name}: "
                f"{type(error).__name__}"
            )

    if failures:
        raise SystemExit(1)

    print("\nMindhárom SSH-kapcsolat sikeres.")


if __name__ == "__main__":
    main()
