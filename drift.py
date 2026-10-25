
import difflib
import hashlib
import json
import os
import re
import tempfile

from datetime import datetime
from pathlib import Path

from compliance_result import ComplianceResult


BASELINE_DIR = Path("baselines")
DIFF_DIR = Path("drift_diffs")


def safe_device_name(name):
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]+", name)
    ):
        raise ValueError("Érvénytelen eszköznév.")

    return name


def checksum(text):
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def vlan_checksum(vlans):
    data = json.dumps(
        vlans,
        sort_keys=True,
        ensure_ascii=False,
    )

    return checksum(data)


def private_write(path, content, replace=False):

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    path.parent.chmod(0o700)

    if path.exists() and not replace:
        raise FileExistsError(
            f"A fájl már létezik: {path}"
        )

    fd, temp_name = tempfile.mkstemp(
        prefix=".tmp_",
        dir=path.parent,
    )

    try:
        with os.fdopen(
            fd, "w", encoding="utf-8"
        ) as stream:
            stream.write(content)

        os.replace(temp_name, path)

    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def current_config(connection):

    raw = connection.send_command(
        "show running-config",
        read_timeout=30,
    )

    if (
        not isinstance(raw, str)
        or not re.search(r"(?m)^end\s*$", raw)
    ):
        raise ValueError(
            "Hiányos running-config kimenet."
        )

    lines = []

    for line in raw.replace("\r", "").splitlines():

        stripped = line.strip()

        if (
            not stripped
            or stripped.startswith("!")
            or stripped.startswith("Building configuration")
            or stripped.startswith("Current configuration :")
            or stripped == "end"
        ):
            continue

        lines.append(line.rstrip())

    if len(lines) < 5:
        raise ValueError(
            "Túl rövid konfiguráció."
        )

    return "\n".join(lines) + "\n"


def current_vlans(connection):
    """
    VLAN-adatbázis lekérdezése strukturált formában.
    """

    output = connection.send_command(
        "show vlan brief",
        use_textfsm=True,
    )

    if not isinstance(output, list) or not output:
        raise ValueError(
            "A show vlan brief TextFSM-feldolgozása sikertelen."
        )

    result = {}

    for row in output:

        if not isinstance(row, dict):
            raise ValueError(
                "Hibás VLAN-adatsor."
            )

        try:
            vlan_id = int(row["vlan_id"])
            name = row["vlan_name"]

        except (KeyError, ValueError, TypeError) as error:
            raise ValueError(
                "Hiányzó VLAN-azonosító vagy név."
            ) from error

        if (
            not 1 <= vlan_id <= 4094
            or not isinstance(name, str)
            or not name.strip()
        ):
            raise ValueError(
                "Érvénytelen VLAN-azonosító vagy név."
            )

        key = str(vlan_id)

        if key in result:
            raise ValueError(
                f"Ismétlődő VLAN: {key}"
            )

        result[key] = name.strip()

    return dict(
        sorted(
            result.items(),
            key=lambda item: int(item[0]),
        )
    )


def vlan_lines(vlans):
    """
    VLAN-adatok rendezett szöveges reprezentációja.
    """

    return [
        f"vlan {key} name {vlans[key]}"
        for key in sorted(vlans, key=int)
    ]


def capture_baseline(
    device_name,
    connection,
    replace=False,
    include_vlans=False,
):
    """
    Referencia rögzítése.
    Router: running-config.
    Switch: running-config és VLAN-adatbázis.
    """

    device_name = safe_device_name(device_name)

    path = (
        BASELINE_DIR
        / f"{device_name}.json"
    )

    if path.exists() and not replace:
        raise FileExistsError(
            f"Már van referencia: {path}. "
            "Használd a --replace kapcsolót."
        )

    config = current_config(connection)

    vlans = (
        current_vlans(connection)
        if include_vlans
        else None
    )

    data = {
        "schema_version": 2,
        "device": device_name,
        "captured_at": (
            datetime.now()
            .astimezone()
            .isoformat()
        ),
        "vlan_tracking": include_vlans,
        "sha256": checksum(config),
        "config": config,
        "vlans_sha256": (
            vlan_checksum(vlans)
            if include_vlans
            else None
        ),
        "vlans": vlans,
    }

    private_write(
        path,
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        replace=replace,
    )

    return path


def check_device_drift(
    device_name,
    connection,
    include_vlans=False,
):
    """
    Aktuális és referenciaállapot összehasonlítása.
    """

    device_name = safe_device_name(device_name)

    path = (
        BASELINE_DIR
        / f"{device_name}.json"
    )

    if not path.exists():
        return ComplianceResult(
            device=device_name,
            category="DRIFT",
            target="running-config / VLAN",
            status="NOT_EVALUATED",
            message="Nincs referenciaállapot.",
        )

    baseline = json.loads(
        path.read_text(encoding="utf-8")
    )

    # Régi, VLAN-pillanatkép nélküli baseline
    if baseline.get("schema_version") != 2:
        return ComplianceResult(
            device=device_name,
            category="DRIFT",
            target="running-config / VLAN",
            status="NOT_EVALUATED",
            message=(
                "Régi referenciaformátum: "
                "új baseline szükséges."
            ),
        )

    if (
        baseline.get("device") != device_name
        or baseline.get("vlan_tracking") is not include_vlans
    ):
        raise ValueError(
            "A baseline eszköze vagy követett "
            "adatforrásai nem egyeznek."
        )

    before = baseline.get("config")

    if (
        not isinstance(before, str)
        or baseline.get("sha256") != checksum(before)
    ):
        raise ValueError(
            "Hibás running-config referencia vagy lenyomat."
        )

    old_vlans = baseline.get("vlans")

    if include_vlans:
        if (
            not isinstance(old_vlans, dict)
            or baseline.get("vlans_sha256")
            != vlan_checksum(old_vlans)
        ):
            raise ValueError(
                "Hibás VLAN-referencia vagy lenyomat."
            )

    elif old_vlans is not None:
        raise ValueError(
            "Váratlan VLAN-adatok a router referenciájában."
        )

    # Aktuális állapot lekérdezése
    after = current_config(connection)

    new_vlans = (
        current_vlans(connection)
        if include_vlans
        else None
    )

    config_changed = before != after

    vlans_changed = (
        include_vlans
        and old_vlans != new_vlans
    )

    expected_hashes = {
        "running_config": baseline["sha256"][:12],
        "vlans": (
            baseline["vlans_sha256"][:12]
            if include_vlans
            else None
        ),
    }

    actual_hashes = {
        "running_config": checksum(after)[:12],
        "vlans": (
            vlan_checksum(new_vlans)[:12]
            if include_vlans
            else None
        ),
    }

    # Nincs változás
    if not config_changed and not vlans_changed:

        return ComplianceResult(
            device=device_name,
            category="DRIFT",
            target="running-config / VLAN",
            status="PASS",
            message=(
                "Nincs eltérés a referenciaállapothoz képest."
            ),
            expected=expected_hashes,
            actual=actual_hashes,
        )

    # Eltérések előállítása
    diffs = []

    if config_changed:
        diffs.extend(
            difflib.unified_diff(
                before.splitlines(),
                after.splitlines(),
                fromfile=(
                    f"{device_name} running-config referencia"
                ),
                tofile=(
                    f"{device_name} running-config aktuális"
                ),
                lineterm="",
            )
        )

    if vlans_changed:
        diffs.extend(
            difflib.unified_diff(
                vlan_lines(old_vlans),
                vlan_lines(new_vlans),
                fromfile=f"{device_name} VLAN referencia",
                tofile=f"{device_name} VLAN aktuális",
                lineterm="",
            )
        )

    added = sum(
        line.startswith("+")
        and not line.startswith("+++")
        for line in diffs
    )

    removed = sum(
        line.startswith("-")
        and not line.startswith("---")
        for line in diffs
    )

    filename = (
        f"{device_name}_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        ".diff"
    )

    diff_path = DIFF_DIR / filename

    private_write(
        diff_path,
        "\n".join(diffs) + "\n",
    )

    return ComplianceResult(
        device=device_name,
        category="DRIFT",
        target="running-config / VLAN",
        status="WARNING",
        message=(
            f"Eltérés: running-config={config_changed}, "
            f"VLAN={vlans_changed}; "
            f"+{added}/-{removed} sor. "
            f"Diff: {diff_path}"
        ),
        expected=expected_hashes,
        actual=actual_hashes,
    )
