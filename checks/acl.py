import re

from compliance_result import ComplianceResult


def parse_acl_rules(config, acl_name):
    lines = config.splitlines()
    header = f"ip access-list extended {acl_name}"

    if header not in lines:
        return None

    rules = {}

    for line in lines[lines.index(header) + 1:]:
        if line == "!" or (
            line and not line[0].isspace()
        ):
            break

        if not line.strip():
            continue

        match = re.fullmatch(
            r"\s*(\d+)\s+(.+?)\s*",
            line,
        )

        if not match:
            raise ValueError(
                f"Nem feldolgozható ACL-sor: {line!r}"
            )

        sequence = int(match.group(1))

        if sequence in rules:
            raise ValueError(
                f"Ismétlődő ACL-sorszám: {sequence}"
            )

        rules[sequence] = " ".join(
            match.group(2).split()
        )

    return rules


def parse_acl_bindings(config, interface):
    lines = config.splitlines()
    header = f"interface {interface}"

    if header not in lines:
        return None

    bindings = []

    for line in lines[lines.index(header) + 1:]:
        if line == "!" or (
            line and not line[0].isspace()
        ):
            break

        if line.strip().startswith("ip access-group"):
            match = re.fullmatch(
                r"\s*ip access-group\s+(\S+)\s+(in|out)\s*",
                line,
            )

            if not match:
                raise ValueError(
                    f"Nem feldolgozható ACL-kötés: {line!r}"
                )

            bindings.append(
                (match.group(1), match.group(2))
            )

    return bindings


def check_acls(device_name, connection, expected_acls):

    def make_result(
        target, status, message,
        expected=None, actual=None,
    ):
        return ComplianceResult(
            device=device_name,
            category="ACL",
            target=target,
            status=status,
            message=message,
            expected=expected,
            actual=actual,
        )

    config = connection.send_command(
        "show running-config"
    )

    if (
        not isinstance(config, str)
        or not re.search(r"(?m)^end\s*$", config)
    ):
        return [
            make_result(
                "running-config",
                "NOT_EVALUATED",
                "Hiányzó vagy nem teljes konfigurációkimenet.",
            )
        ]

    results = []

    for acl_name, settings in expected_acls.items():

        try:
            expected_rules = {
                int(seq): " ".join(str(rule).split())
                for seq, rule in settings["rules"].items()
            }

            binding = settings["binding"]
            interface = binding["interface"]
            direction = binding["direction"]

            if direction not in ("in", "out"):
                raise ValueError(
                    "A kötés iránya csak in vagy out lehet."
                )

            actual_rules = parse_acl_rules(
                config, acl_name
            )

            actual_bindings = parse_acl_bindings(
                config, interface
            )

        except (
            KeyError, TypeError, ValueError, AttributeError
        ) as error:
            results.append(
                make_result(
                    acl_name,
                    "NOT_EVALUATED",
                    f"ACL-feldolgozási hiba: {error}",
                )
            )
            continue

        # 1. Az ACL létezése
        if actual_rules is None:
            results.append(
                make_result(
                    acl_name,
                    "FAIL",
                    "Az ACL nem létezik.",
                    expected="létezik",
                    actual="hiányzik",
                )
            )
            continue

        results.append(
            make_result(
                acl_name,
                "PASS",
                "Az ACL létezik.",
            )
        )

        # 2. Szabályok ellenőrzése
        for sequence, expected_rule in expected_rules.items():

            actual_rule = actual_rules.get(sequence)

            status = (
                "PASS"
                if actual_rule == expected_rule
                else "FAIL"
            )

            results.append(
                make_result(
                    f"{acl_name} szabály {sequence}",
                    status,
                    "ACL-szabály ellenőrzése.",
                    expected=expected_rule,
                    actual=actual_rule,
                )
            )

        # 3. Szabálysorrend ellenőrzése
        expected_order = list(expected_rules)
        actual_order = list(actual_rules)

        results.append(
            make_result(
                f"{acl_name} sorrend",
                (
                    "PASS"
                    if actual_order == expected_order
                    else "FAIL"
                ),
                "Szabálysorrend és váratlan szabályok ellenőrzése.",
                expected=expected_order,
                actual=actual_order,
            )
        )

        # 4. Interfészhez rendelés ellenőrzése
        correct_binding = (
            actual_bindings is not None
            and (acl_name, direction) in actual_bindings
        )

        actual_binding_data = (
            None
            if actual_bindings is None
            else [
                {"acl": name, "direction": acl_direction}
                for name, acl_direction in actual_bindings
            ]
        )

        results.append(
            make_result(
                f"{acl_name} kötés",
                (
                    "PASS"
                    if correct_binding
                    else "FAIL"
                ),
                "ACL interfészhez és irányhoz rendelése.",
                expected={
                    "interface": interface,
                    "direction": direction,
                },
                actual=actual_binding_data,
            )
        )

    return results
