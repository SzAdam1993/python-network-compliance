import os
import yaml
from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import (NetmikoAuthenticationException, NetmikoTimeoutException, )

load_dotenv()
username = os.getenv ("DEVICE_USERNAME")
password = os.getenv ("DEVICE_PASSWORD")

with open ("inventory.yaml","r", encoding="utf-8") as File:
	inventory = yaml.safe_load(File)

for device in inventory["devices"]:
    print(f"\n Kapcsolódás: {device['name']} ({device['host']})")

    connection_parameters={
	"device_type": device["device_type"],
	"host": device["host"],
	"username": username,
	"password": password,
	 }

    try:
         with ConnectHandler(**connection_parameters) as Connection:
             output = Connection.send_command("show ip interface brief")
         print (f"[SIKERES] {device ['name']}")
         print (output)

    except NetmikoAuthenticationException:
        print(f"[HITELESÍTÉSI HIBA] {device ['name']}")

    except NetmikoTimeoutException:
        print(f"[NEM ELÉRHETŐ] {device['name']}")

    except Exceptions as error:
        print("f[EGYÉB HIBA]{device['name']}:{error}")
