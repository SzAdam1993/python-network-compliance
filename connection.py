import os

from dotenv import load_dotenv
from netmiko import ConnectHandler

load_dotenv()

def connect_to_device(device):
    username = os.getenv("DEVICE_USERNAME")
    password = os.getenv("DEVICE_PASSWORD")

    if not username or not password:
        raise RuntimeError(
            "A DEVICE_USERNAME vagy a DEVICE_PASSWORD"
            "hiányzik a .env fájlból."
        )

    return ConnectHandler(
        device_type=device["device_type"],
        host=device["host"],
        username=username,
        password=password,
        conn_timeout=10,
        auth_timeout=10,
    )

