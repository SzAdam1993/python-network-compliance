
import unittest

from checks.interface import check_interfaces


class FakeConnection:
    def __init__(self, status):
        self.status = status

    def send_command(self, command, **kwargs):
        if command == "show interfaces switchport":
            return [{
                "interface": "Ethernet0/2",
                "admin_mode": "static access",
                "access_vlan": "10",
            }]

        if command == "show ip interface brief":
            return [{
                "interface": "Ethernet0/2",
                "status": self.status,
                "proto": "down",
            }]

        raise ValueError(command)


class InterfaceStateTests(unittest.TestCase):

    def check_state(
        self, status,
        expected_admin="up",
        expected_oper="up",
    ):
        expected = {
            "mode": "access",
            "access_vlan": 10,
            "admin_state": expected_admin,
            "oper_state": expected_oper,
        }

        results = check_interfaces(
            "SW1",
            FakeConnection(status),
            {"Ethernet0/2": expected},
        )

        return {
            result.target: result
            for result in results
        }

    def test_up_up(self):
        results = self.check_state("up")

        self.assertEqual(
            results["Et0/2 admin állapot"].status,
            "PASS",
        )
        self.assertEqual(
            results["Et0/2 operatív állapot"].status,
            "PASS",
        )

    def test_link_down_but_admin_up(self):
        results = self.check_state("down")

        self.assertEqual(
            results["Et0/2 admin állapot"].status,
            "PASS",
        )
        self.assertEqual(
            results["Et0/2 operatív állapot"].status,
            "FAIL",
        )

    def test_administratively_down(self):
        results = self.check_state(
            "administratively down",
            expected_admin="down",
            expected_oper="down",
        )

        self.assertEqual(
            results["Et0/2 admin állapot"].status,
            "PASS",
        )
        self.assertEqual(
            results["Et0/2 operatív állapot"].status,
            "PASS",
        )

    def test_unknown_status(self):
        results = self.check_state("unknown")

        self.assertEqual(
            results["Et0/2 admin állapot"].status,
            "NOT_EVALUATED",
        )
        self.assertEqual(
            results["Et0/2 operatív állapot"].status,
            "NOT_EVALUATED",
        )


if __name__ == "__main__":
    unittest.main()
