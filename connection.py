
import os
from pathlib import Path

from dotenv import load_dotenv
from netmiko import ConnectHandler

load_dotenv()

HOST_KEYS_FILE = (
    Path(__file__).resolve().parent
    / "ssh_host_keys"
    / "known_hosts"
)


def connect_to_device(device):
    username = os.getenv("DEVICE_USERNAME")
    password = os.getenv("DEVICE_PASSWORD")

    if not username or not password:
        raise RuntimeError(
            "A DEVICE_USERNAME vagy DEVICE_PASSWORD "
            "hiányzik a környezeti változókból."
        )

    if (
        not HOST_KEYS_FILE.is_file()
        or HOST_KEYS_FILE.stat().st_size == 0
    ):
        raise RuntimeError(
            "Hiányzik vagy üres a hitelesített "
            "SSH known_hosts állomány."
        )

    return ConnectHandler(
        device_type=device["device_type"],
        host=device["host"],
        username=username,
        password=password,

# SSH-szerverazonosság ellenőrzése
        ssh_strict=True,
        system_host_keys=False,
        alt_host_keys=True,
        alt_key_file=str(HOST_KEYS_FILE),

# Kapcsolati korlátok
        conn_timeout=10,
        auth_timeout=10,
        banner_timeout=15,
    )

