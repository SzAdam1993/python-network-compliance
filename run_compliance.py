import yaml

from netmiko.exceptions import(
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from compliance_result import ComplianceResult
from connection import connect_to_device
from checks.vlan import check_vlans
from checks.interface import check_interfaces
from checks.trunk import check_trunks
from checks.acl import check_acls

from reporter import(
    print_report,
    save_json_report,
)

def read_yaml(path):
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)

def main():

    inventory = read_yaml("inventory.yaml")
    expected_state = read_yaml("expected_state.yaml")

    results = []

    print(
        "[INFO] Vlan,interface és trunk és ACL "
        "megfelelőségvizsgálat indítása. "
    )

    for device in inventory["devices"]:

        name = device["name"]
        expected = expected_state.get(name, {})

        if not any(
            key in expected
            for key in ("vlans", "interfaces", "trunks" ,"acls")
        ):
            continue
##
        try:
            with connect_to_device(device) as connection:

                if "vlans" in expected:
                    results.extend(
                        check_vlans(
                            name,
                            connection,
                            expected["vlans"],
                        )
                    )
                if "interfaces" in expected:
                    results.extend(
                        check_interfaces(
                            name,
                            connection,
                            expected["interfaces"],
                        )
                    )
                if "trunks" in expected:
                    results.extend(
                    check_trunks(
                        name,
                        connection,
                        expected["trunks"],
                    )
                )

                if "acls" in expected:
                    results.extend(
                        check_acls(
                            name,
                            connection,
                            expected["acls"],
                        )
                    )

##
        except NetmikoAuthenticationException:
            results.append(
                ComplianceResult(
                    device=name,
                    category="DEVICE",
                    target="SSH",
                    status="NOT_EVALUATED",
                    message="SSH hitelesítési hiba. ",
                )
            )
        except NetmikoTimeoutException:
            results.append(
                ComplianceResult(
                    device=name,
                    category="DEVICE",
                    target="SSH",
                    status="NOT_EVALUATED",
                    message="SSH időtúllépés vagy nem elérhető eszköz. ",
                )
            )

        except Exception as error:

            import traceback
            traceback.print_exc()

            results.append(
                ComplianceResult(
                    device=name,
                    category="DEVICE",
                    target="Feldolgozás",
                    status="NOT_EVALUATED",
                    message=(
                        f"Váratlan hiba: "
                        f"{type(error).__name__}: {error} "
                    ),
                )
            )
    if not results:
        raise RuntimeError(
            "Egyetlen ellenőrzés sem futott le. "
            "Ellenőrizd az expected_state.yaml fájlt! "
        )

    print_report(results)
    save_json_report(results)

if  __name__ == "__main__":
    main()
