import os
from datetime import datetime
from pathlib import Path
import yaml
from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import(
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

load_dotenv()
username = os.getenv ("DEVICE_USERNAME")
password = os.getenv ("DEVICE_PASSWORD")
if not username or not password:
    raise RuntimeError(
        "A DEVICE_USERNAME vagy DEVICE_PASSWORD környezeti változó hiányzik."
    )
with open("inventory.yaml","r",encoding = "utf-8") as file:
    inventory = yaml.safe_load(file)
backup_root = Path("backups")
backup_root.mkdir(exist_ok=True)

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

for device in inventory["devices"]:
    name = device["name"]
    host = device["host"]
    print(f"\n Kapcsolódás: {name} ( {host})")
    connection_parameters = {
        "device_type": device["device_type"],
        "host": host,
        "username": username ,
        "password": password,
    }
    try:
        with ConnectHandler(**connection_parameters) as connection:
            print(f"[SSH OK] {name}")
            running_config = connection.send_command(
                "show running-config",
                read_timeout=30,
            )
            if "%Invalid inout" in running_config:
                print("f[PARANCSHIBA] {name}: show running-config")
                continue
            device_backup_dir = backup_root /name
            device_backup_dir.mkdir(exist_ok=True)

            backup_file = (
                device_backup_dir
                / f"{name}_{timestamp}.cfg"
            )
            backup_file.write_text(
                running_config,
                encoding = "utf-8",
            )
            print(f"[MENTÉS OK] {backup_file}")
    except NetmikoAutheticationException:
        print(f"[HITELESITŐ HIBA] {name}")
    except NetmikoTimeoutException:
        print(f"[NEM ELÉRHETŐ] {name}")
    except Exception as error:
        print(f"[EGYÉB HIBA] {name} : {error}")
