import os
import yaml
from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

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

    if name  not in expected_state:
        continue
    print(f"\n====={name} VLAN ELLENŐRZÉS =====")
    connection_parameters = {
        "device_type": device["device_type"],
        "host": device["host"],
        "username": username,
        "password": password,
    }

    try:
        with ConnectHandler(**connection_parameters) as connection:
            vlan_data = connection.send_command(
                "show vlan brief",
                use_textfsm=True,
            )
            if not isinstance(vlan_data, list):
                print(f"[NEM ELÉRHETŐ] {name}: a VLAN-adatok feldolgozás sikertelen.")
                continue
            actual_vlans = {}

            for vlan in vlan_data:
                vlan_id = int(vlan["vlan_id"])
                vlan_name = vlan["vlan_name"]

                actual_vlans[vlan_id] = vlan_name

            expected_vlans = expected_state[name]["vlans"]

            failed = False

            for vlan_id, expected_name in expected_vlans.items():
                if vlan_id not in actual_vlans:
                    print(
                        f"[FAIL] VLAN {vlan_id}: "
                        f"hiányzik, elvárt név: {expected_name}"
                    )
                    failed=True
                    continue
                actual_name = actual_vlans[vlan_id]
                if actual_name != expected_name:
                    print(
                        f"[FAIL] VLAN {vlan_id}: "
                        f"elvárt='{expected_name}', "
                        f"tényleges='{actual_name}'"
                    )
                    failed = True
                else:
                    print(
                        f"PASS] VLAN {vlan_id}: {actual_name}"
                    )
            if failed:
                print(f"[ÖSSZESÍTÉS] {name}: FAIL")
            else:
                print(f"[ÖSSZESÍTÉS] {name}: PASS")

    except NetmikoAuthenticationException:
        print(f"[NEM ELÉRHETŐ] {name}")
    except NetmikoTimeoutException:
        print(f"[NEM ELÉRHETŐ] {name}")
    except Exception as error:
        print(f"[EGYÉB HIBA] {name} : {error}")
