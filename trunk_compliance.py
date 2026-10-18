import os
import yaml
from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import(
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

def normalize_interface_name(interface_name):
    replacements = {
        "Ethernet": "Et",
        "FastEthernet": "Fa",
        "GiganbitEthernet": "Gi",
        "TenGigabitEthernet": "Te",
    }

    for long_name, short_name in replacements.items():
        if interface_name.startswith(long_name):
            return interface_name.replace(
                long_name,
                short_name,
                1,
            )
    return interface_name

def normalize_mode(mode):
    mode = mode.lower().strip()

    if "trunk" in mode:
        return "trunk"
    if "access" in mode:
        return "access"
    return mode

def expand_vlan_list(vlan_values):
    vlans = set()

    for value in vlan_values:
        value = str(value).strip().upper()

        if value == "NONE":
            continue
        if value == "ALL":
            vlans.update(range(1,4095))
            continue

        if "-" in value:
            start, end = value.split("-",1)

            vlans.update(
                range(
                    int(start),
                    int(end) +1,
                )
            )
        else:
            vlans.add(int(value))
    return vlans

load_dotenv()

username = os.getenv("DEVICE_USERNAME")
password = os.getenv("DEVICE_PASSWORD")

if not username or not password:
    raise RuntimeError(
        "A DEIVECE_USERNAME vagy DEVICE_PASSWORD környezeti változó hiányzik."
    )
with open("inventory.yaml","r",encoding="utf-8") as file:
    inventory = yaml.safe_load(file)

with open("expected_state.yaml","r",encoding="utf-8") as file:
    expected_state = yaml.safe_load(file)

for device in inventory["devices"]:
    name = device["name"]

    if name not in expected_state:
        continue

    if "trunks" not in expected_state[name]:
        continue

    print(f"\n===== {name} TRUNK ELLENŐRZÉS =====")

    connection_parameters = {
        "device_type": device["device_type"],
        "host": device["host"],
        "username": username,
        "password": password,
    }

    try:
        with ConnectHandler(**connection_parameters) as connection:

            switchport_data = connection.send_command(
                "show interfaces switchport",
                use_textfsm=True,
            )


            if not isinstance(switchport_data, list):
                print(
                    f"[NEM ÉRTÉKELHETŐ] {name}: "
                    "a switchport adatok feldolgozása sikertelen. "
                )

                continue
        switchports = {}

        for interface in switchport_data:
            interface_name = normalize_interface_name(
                interface["interface"]
            )

            switchports[interface_name] = interface
        device_failed=False

        for interface_name, expected in expected_state[name]["trunks"].items():
            normalized_name = normalize_interface_name(
                interface_name
            )
            if normalized_name not in switchports:
                print(
                    f"[FAIL] {normalized_name}: "
                    "az interfész nem található."
                )
                device_failed=True
                continue
            actual = switchports[normalized_name]

            expected_mode = expected["mode"]

            actual_mode = normalize_mode(
                actual["mode"]
            )

            admin_mode = normalize_mode(
                actual["admin_mode"]
            )

            if(
                actual_mode == expected_mode
                and admin_mode == expected_mode
            ):
                print(
                    f"[PASS] {normalized_name} mód: trunk"
                )
            else:
                print(
                    f"[FAIL] {normalized_name}: mód: "
                    f"evlvárt='{expected_mode}', "
                    f"operatív='{actual_mode}', "
                    f"adminisztratív='{admin_mode}'"
                )
                device_failed = True

            expected_native = int(
                expected["native_vlan"]
            )

            actual_native = int(
                actual["native_vlan"]
            )

            if actual_native == expected_native:
                print(
                    f"[PASS] {normalized_name} native VLAN: "
                    f"{actual_native}"
                )
            else:
                print(
                    f"[FAIL] {normalized_name} native VLAN: "
                    f"elvárt='{expected_native}', "
                    f"tényleges='{actual_name}' "
                )
                device_failed = True

            expected_vlans = set(
                int(vlan)
                for vlan in expected["allowed_vlans"]
            )

            actual_vlans = expand_vlan_list(
                actual["trunking_vlans"]
            )

            missing_vlans = (
                expected_vlans - actual_vlans
            )

            unexpected_vlans = (
                actual_vlans - expected_vlans
            )

            if not missing_vlans and not unexpected_vlans:
                print(
                    f"[PASS] {normalized_name} "
                    f"engedélyezett VLAN-ok: "
                    f"{sorted(actual_vlans)}"
                )
            else:
                print(
                    f"[FAIL] {normalized_name} "
                    "engedélyezett VLAN-lista eltér. "
                )
                if missing_vlans:
                    print(
                        " Hiányzó VLAN-ok: "
                        f"{sorted(missing_vlans)}"
                    )
                if unexpected_vlans:
                    print(
                        " Nem várt VLAN-ok: "
                        f"{sorted(unexoected_vlans)}"
                    )
                device_failed = True
        if device_failed:
            print(f"[ÖSSZESÍTÉS] {name}: FAIL ")
        else:
            print(f"[ÖSSZESÍTÉS] {name}: PASS")

    except NetmikoAuthenticationException:
        print(f"[HITELESÍTÉSI HIBA] {name}")
    except NetmikoTimeoutException:
        print(f"[NEM ELÉRHETŐ] {name}")
    except Exception as error:
        print(f"[EGYÉB HIBA] {name} : {error}")
