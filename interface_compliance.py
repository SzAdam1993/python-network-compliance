import os
import yaml
from dotenv import load_dotenv
from connection import connect_to_device
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    )

def normalize_interface_name(interface_name):
    replacements = {
        "Ethernet": "Et",
        "FastEthernet": "Fe",
        "GigabitEthernet": "Gi",
        "TenGigabitEthernet":"Te",
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
    mode = str(mode).strip().lower()

    if "access" in mode:
        return "access"
    if "trunk" in mode:
        return "trunk"
    return mode

load_dotenv()

username = os.getenv("DEVICE_USERNAME")
password = os.getenv("DEVICE_PASSWORD")

if not username or not password:
    raise RuntimeError(
        "A DEVICE_USERNAME vagy DEVICE_PASSWORD környezeti változó hiányzik."
    )

with open("inventory.yaml","r",encoding="utf-8") as file:
    inventory = yaml.safe_load(file)

with open("expected_state.yaml","r",encoding="utf-8") as file:
    expected_state = yaml.safe_load(file)

for device in inventory["devices"]:
    name = device["name"]
    if name not in expected_state:
        continue
    if "interfaces" not in expected_state[name]:
        continue
    print(f"\n===== {name} INTERFÉSZ ELLENŐRZÉS =====")

    connection_parameters = {
        "device_type": device["device_type"],
        "host": device["host"],
        "username": username,
        "password": password,
    }

    try:
        with connect_to_device(device) as connection:

            switchport_data = connection.send_command(
                "show interfaces switchport",
                use_textfsm=True,
            )

            interface_data = connection.send_command(
                "show ip interface brief",
                use_textfsm=True,
            )

            if not isinstance(switchport_data, list):
                print(
                    f"[NEM ÉRTÉKELHETŐ] {name}: "
                    "a switchportállapotok feldolgozása sikertelen."
                )
                continue

            if not isinstance(interface_data, list):
                print(
                    f"[NEM ÉRTÉKELHETŐ] {name}: "
                    "az intefészállapotok feldolgozása sikertelen."
                )
                continue

            switchports = {}

            for interface in switchport_data:
                interface_name = normalize_interface_name(
                    interface["interface"]
                )
                switchports[interface_name] = interface
            interface_states = {}

            for interface in interface_data:
                interface_name=normalize_interface_name(
                    interface["interface"]
                )
                interface_states[interface_name] = interface
            device_failed = False

            for interface_name, expected in expected_state[name][
               "interfaces"
            ].items():
                normalized_name = normalize_interface_name(
                    interface_name
                )

                if normalized_name not in switchports:
                    print(
                        f"[FAIL] {normalized_name}: "
                        "az interfész nem található."
                    )
                    device_failed = True
                    continue

                actual = switchports[normalized_name]
                expected_mode = expected["mode"]
                actual_mode = normalize_mode(actual["admin_mode"])

                if actual_mode == expected_mode:
                    print(
                        f"[PASS] {normalized_name} mód: "
                        f"{actual_mode}"
                    )
                else:
                    print(
                        f"[FAIL] {normalized_name} mód: "
                        f"elvárt='{expected_mode}',"
                        f"tényleges='{actual_mode}'"
                    )
                    device_failed = True
                expected_vlan = int(expected["access_vlan"])

                try:
                    actual_vlan = int(actual["access_vlan"])
                except(ValueError, TypeError):
                    actual_vlan = actual["access_vlan"]

                if actual_vlan == expected_vlan:
                    print(
                        f"[PASS] {normalized_name} access VLAN: "
                        f"{actual_vlan}"
                    )
                else:
                    print(
                        f"[FAIL] {normalized_name} access VLAN: "
                        f"elvárt='{expected_vlan}'"
                        f"tényleges='{actual_vlan}'"
                    )
                    device_failed = True
                    print(f"[DEBUG] Sor elérve: {normalized_name}")
                if normalized_name not in interface_states:
                    print(
                        f"[NEM ÉRTÉKELHETŐ] {normalized_name}: "
                        "az interfészállapot nem található."
                    )
                    device_failed = True
                    continue

                actual_state = interface_states[
                    normalized_name
                ]["status"]

                expected_state_value = expected["admin_state"]

                if actual_state == expected_state_value:
                    print(
                        f"[PASS] {normalized_name} állapot: "
                        f"{actual_state}"
                    )
                else:
                    print(
                        f"[FAIL] {normalized_name} állapot: "
                        f"elvárt= '{expected_state_value} állapot:' , "
                        f"tényleges= '{actual_state}'"
                    )
                    device_failed = True

            if device_failed:
                    print(f"[ÖSSZESÍTÉS] {name}: FAIL")
            else:
                    print(f"[ÖSSZESÍTÉS] {name}: PASS")
    except NetmikoAuthenticationException:
        print(f"[HITELESÍTÉSI HIBA] {name}")
    except NetmikoTimeoutException:
        print(f"[NEM ELÉRHETŐ] {name}")
    except Exception as error:
        print(f"[EGYÉB HIBA]  {name}: {error}")
