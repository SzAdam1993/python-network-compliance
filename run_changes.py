
import argparse
import sys
import yaml

from connection import connect_to_device

from changes import (
    validate_vlan,
    get_vlans,
    get_access_vlan,
    get_trunk_allowed_vlans,
    backup_before_change,
    create_vlan,
    set_access_vlan,
    change_trunk_allowed_vlan,
)

from reporter import print_report, save_json_report


ALLOWED_DEVICES = {"SW1", "SW2"}

TEST_ACCESS_DEVICE = "SW1"
TEST_ACCESS_PORT = "Ethernet0/2"
TEST_ACCESS_VLANS = {10, 40}

TEST_TRUNK_DEVICE = "SW1"
TEST_TRUNK_PORT = "Ethernet0/1"
TEST_TRUNK_VLAN = 40

BASE_TRUNK_VLANS = {10, 20, 30, 99}


def main():

    parser = argparse.ArgumentParser(
        description="Kontrollált Cisco konfigurációmódosítás."
    )

    parser.add_argument(
        "action",
        choices=[
            "create-vlan",
            "set-access-vlan",
            "add-trunk-vlan",
            "remove-trunk-vlan",
        ],
    )

    parser.add_argument("--device", required=True)
    parser.add_argument("--vlan", required=True, type=int)
    parser.add_argument("--name")
    parser.add_argument("--interface")

    parser.add_argument(
        "--apply",
        action="store_true",
    )

    args = parser.parse_args()

    if args.device not in ALLOWED_DEVICES:
        parser.error(
            "Csak SW1 vagy SW2 módosítható."
        )

    # Paraméterek ellenőrzése
    if args.action == "create-vlan":

        if not args.name or args.interface:
            parser.error(
                "A create-vlan művelethez --name kell, "
                "--interface nem adható meg."
            )

        validate_vlan(args.vlan, args.name)

    elif args.action == "set-access-vlan":

        if args.name:
            parser.error(
                "A set-access-vlan művelethez nem kell --name."
            )

        if (
            args.device != TEST_ACCESS_DEVICE
            or args.interface != TEST_ACCESS_PORT
            or args.vlan not in TEST_ACCESS_VLANS
        ):
            parser.error(
                "Csak SW1 Ethernet0/2, "
                "VLAN 10 vagy VLAN 40 engedélyezett."
            )

    else:

        if args.name:
            parser.error(
                "A trunk-műveleteknél --name nem használható."
            )

        if (
            args.device != TEST_TRUNK_DEVICE
            or args.interface != TEST_TRUNK_PORT
            or args.vlan != TEST_TRUNK_VLAN
        ):
            parser.error(
                "Csak SW1 Ethernet0/1, "
                "VLAN 40 engedélyezett."
            )

    with open(
        "inventory.yaml",
        "r",
        encoding="utf-8",
    ) as file:
        inventory = yaml.safe_load(file)

    devices = [
        device
        for device in inventory["devices"]
        if device["name"] == args.device
    ]

    if len(devices) != 1:
        parser.error(
            "Az eszköz hiányzik vagy többször szerepel."
        )

    try:

        with connect_to_device(devices[0]) as connection:

            vlans = get_vlans(connection)
            before = None

            # 1. VLAN létrehozása
            if args.action == "create-vlan":

                if args.vlan in vlans:

                    if vlans[args.vlan] == args.name:
                        print(
                            "[NO CHANGE] A VLAN már megfelelő."
                        )
                        return

                    raise ValueError(
                        f"VLAN {args.vlan} már létezik "
                        f"más névvel: {vlans[args.vlan]}"
                    )

                commands = [
                    f"vlan {args.vlan}",
                    f"name {args.name}",
                ]

                confirmation = (
                    f"APPLY {args.device} VLAN {args.vlan}"
                )

                detail = (
                    f"VLAN: {args.vlan}\n"
                    f"Név: {args.name}"
                )

            # 2. Access VLAN módosítása
            elif args.action == "set-access-vlan":

                if args.vlan not in vlans:
                    raise ValueError(
                        f"A cél VLAN {args.vlan} nem létezik."
                    )

                before = get_access_vlan(
                    connection,
                    TEST_ACCESS_PORT,
                )

                if before == args.vlan:
                    print(
                        "[NO CHANGE] A port már "
                        "a kívánt VLAN-ban van."
                    )
                    return

                commands = [
                    f"interface {TEST_ACCESS_PORT}",
                    f"switchport access vlan {args.vlan}",
                ]

                confirmation = (
                    f"APPLY {args.device} "
                    f"{TEST_ACCESS_PORT} VLAN {args.vlan}"
                )

                detail = (
                    f"Interfész: {TEST_ACCESS_PORT}\n"
                    f"Jelenlegi VLAN: {before}\n"
                    f"Cél VLAN: {args.vlan}"
                )

            # 3. Trunk allowed VLAN módosítása
            else:

                if args.vlan not in vlans:
                    raise ValueError(
                        f"A VLAN {args.vlan} "
                        "nem létezik a switchen."
                    )

                before = get_trunk_allowed_vlans(
                    connection,
                    TEST_TRUNK_PORT,
                )

                action_word = (
                    "add"
                    if args.action == "add-trunk-vlan"
                    else "remove"
                )

                required_before = (
                    BASE_TRUNK_VLANS
                    if action_word == "add"
                    else BASE_TRUNK_VLANS | {TEST_TRUNK_VLAN}
                )

                intended_after = (
                    BASE_TRUNK_VLANS | {TEST_TRUNK_VLAN}
                    if action_word == "add"
                    else BASE_TRUNK_VLANS
                )

                if before == intended_after:
                    print(
                        "[NO CHANGE] A trunk allowed "
                        "VLAN-listája már megfelelő."
                    )
                    return

                if before != required_before:
                    raise ValueError(
                        "Váratlan trunk-kiinduló állapot: "
                        f"{sorted(before)}. "
                        f"Elvárt: {sorted(required_before)}. "
                        "Módosítás leállítva."
                    )

                commands = [
                    f"interface {TEST_TRUNK_PORT}",
                    f"switchport trunk allowed vlan "
                    f"{action_word} {TEST_TRUNK_VLAN}",
                ]

                confirmation = (
                    f"APPLY {args.device} {TEST_TRUNK_PORT} "
                    f"{action_word.upper()} "
                    f"VLAN {TEST_TRUNK_VLAN}"
                )

                detail = (
                    f"Interfész: {TEST_TRUNK_PORT}\n"
                    f"Jelenlegi allowed: {sorted(before)}\n"
                    f"Tervezett allowed: {sorted(intended_after)}"
                )

            # A módosítási terv megjelenítése
            print()
            print("TERVEZETT KONFIGURÁCIÓMÓDOSÍTÁS")
            print("=" * 50)
            print(f"Eszköz: {args.device}")
            print(detail)

            print()
            print("Cisco parancsok:")

            for command in commands:
                print(f"  {command}")

            print("=" * 50)

            # Alapértelmezés: csak előnézet
            if not args.apply:

                print()
                print(
                    "[DRY RUN] Nem történt módosítás. "
                    "--apply szükséges."
                )
                return

            print()
            print("A végrehajtáshoz írd be pontosan:")
            print(confirmation)

            if input("> ").strip() != confirmation:
                print(
                    "[CANCELLED] A művelet megszakítva."
                )
                return

            # Minden módosítás előtt mentés
            backup_path = backup_before_change(
                args.device,
                connection,
            )

            print(f"[BACKUP OK] {backup_path}")

            if args.action == "create-vlan":

                if args.vlan in get_vlans(connection):
                    raise RuntimeError(
                        "A VLAN időközben megjelent. "
                        "Művelet leállítva."
                    )

                result = create_vlan(
                    connection,
                    args.device,
                    args.vlan,
                    args.name,
                )

            elif args.action == "set-access-vlan":

                if get_access_vlan(
                    connection,
                    TEST_ACCESS_PORT,
                ) != before:
                    raise RuntimeError(
                        "A port időközben megváltozott. "
                        "Művelet leállítva."
                    )

                result = set_access_vlan(
                    connection,
                    args.device,
                    TEST_ACCESS_PORT,
                    args.vlan,
                )

            else:

                # A change_trunk_allowed_vlan újraellenőrzi
                # a kiinduló állapotot a parancsküldés előtt.
                result = change_trunk_allowed_vlan(
                    connection=connection,
                    device_name=args.device,
                    interface_name=TEST_TRUNK_PORT,
                    vlan_id=TEST_TRUNK_VLAN,
                    operation=(
                        "add"
                        if args.action == "add-trunk-vlan"
                        else "remove"
                    ),
                    expected_before=before,
                )

            print_report(
                [result],
                title=(
                    "CONTROLLED CONFIGURATION CHANGE REPORT"
                ),
            )

            save_json_report(
                [result],
                prefix="change",
            )

            if result.status != "PASS":
                sys.exit(1)

    except Exception as error:

        print(
            f"[ERROR] {type(error).__name__}: {error}"
        )

        print(
            "Ha a módosítás megkezdődött, "
            "ellenőrizd az eszköz aktuális állapotát. "
            "Ne ismételd meg automatikusan!"
        )

        sys.exit(1)


if __name__ == "__main__":
    main()
