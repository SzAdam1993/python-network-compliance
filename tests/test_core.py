"""Offline unit tests for python-network-compliance.

Usage from the project root (after copying this file to tests/test_core.py):
    python -m unittest discover -s tests -v

No real SSH sessions or Cisco configuration changes occur in these tests.
Some tests intentionally reveal known issues in GitHub commit 346118d08.
"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from compliance_result import ComplianceResult
from checks.interface import normalize_interface_name, check_interfaces
from checks.trunk import expand_vlan_list
from checks.vlan import check_vlans
from checks.acl import parse_acl_rules
from run_compliance import run_check
from reporter import print_report
from syslog_parser import analyze_syslog
import drift


class FakeConnection:
    def __init__(self, responses):
        self.responses = responses

    def send_command(self, command, **kwargs):
        response = self.responses[command]
        return response() if callable(response) else response


class InterfaceTests(unittest.TestCase):
    def test_normalize_multiple_cisco_interface_types(self):
        self.assertEqual(normalize_interface_name('Ethernet0/2'), 'Et0/2')
        self.assertEqual(normalize_interface_name('FastEthernet0/1'), 'Fa0/1')
        self.assertEqual(normalize_interface_name('GigabitEthernet0/1'), 'Gi0/1')
        self.assertEqual(normalize_interface_name('TenGigabitEthernet1/1'), 'Te1/1')

    def test_malformed_switchport_output_is_not_evaluated(self):
        connection = FakeConnection({
            'show interfaces switchport': [{'wrong_key': 'Ethernet0/2'}],
            'show ip interface brief': [{'interface': 'Ethernet0/2', 'status': 'up'}],
        })
        results = check_interfaces('SW1', connection, {
            'Ethernet0/2': {'mode': 'access', 'access_vlan': 10, 'admin_state': 'up'}
        })
        self.assertTrue(results)
        self.assertEqual(results[0].status, 'NOT_EVALUATED')
        self.assertEqual(results[0].device, 'SW1')


class VlanTests(unittest.TestCase):
    def test_missing_vlan_returns_fail(self):
        connection = FakeConnection({
            'show vlan brief': [{'vlan_id': '10', 'vlan_name': 'USERS'}]
        })
        result = check_vlans('SW1', connection, {10: 'USERS', 99: 'MANAGEMENT'})
        self.assertEqual([item.status for item in result], ['PASS', 'FAIL'])

    def test_broken_vlan_row_is_not_evaluated(self):
        connection = FakeConnection({'show vlan brief': [{'wrong': 'field'}]})
        result = check_vlans('SW1', connection, {10: 'USERS'})
        self.assertEqual(result[0].status, 'NOT_EVALUATED')


class TrunkTests(unittest.TestCase):
    def test_expand_ranges(self):
        self.assertEqual(expand_vlan_list('10,20,30-31,99'), {10, 20, 30, 31, 99})

    def test_reject_bad_range(self):
        with self.assertRaises(ValueError):
            expand_vlan_list('30-10')


class AclTests(unittest.TestCase):
    def test_acl_rules_and_order(self):
        config = '\n'.join([
            'version 15',
            'ip access-list extended TO_SERVERS',
            ' 10 deny ip any any',
            ' 20 permit ip any any',
            '!',
            'end',
        ])
        rules = parse_acl_rules(config, 'TO_SERVERS')
        self.assertEqual(list(rules), [10, 20])
        self.assertEqual(rules[10], 'deny ip any any')


class IsolationTests(unittest.TestCase):
    def test_failed_module_does_not_stop_the_next_one(self):
        def broken(device, connection, expected):
            raise RuntimeError('deliberate parser failure')

        def working(device, connection, expected):
            return [ComplianceResult(device, 'TRUNK', 'Et0/1', 'PASS', 'ok')]

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            a = run_check('SW1', 'INTERFACE', broken, None, {})
        b = run_check('SW1', 'TRUNK', working, None, {})
        self.assertEqual(a[0].status, 'NOT_EVALUATED')
        self.assertEqual(b[0].status, 'PASS')


class ReporterTests(unittest.TestCase):
    def test_custom_title_is_displayed(self):
        results = [ComplianceResult('SW1', 'VLAN', 'VLAN 10', 'PASS', 'ok')]
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            print_report(results, title='NETWORK TEST REPORT')
        self.assertIn('NETWORK TEST REPORT', capture.getvalue())


class SyslogTests(unittest.TestCase):
    def test_malformed_log_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_syslog('SW1', 'not a Cisco show logging output')

    def test_all_event_categories(self):
        sample = '''Syslog logging: enabled
Buffer logging: level informational
Log Buffer (16384 bytes):
%LINK-3-UPDOWN: Interface Ethernet0/2, changed state to down
%LINK-3-UPDOWN: Interface Ethernet0/2, changed state to up
%LINK-3-UPDOWN: Interface Ethernet0/2, changed state to down
%LINK-3-UPDOWN: Interface Ethernet0/2, changed state to up
%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin]
%SYS-5-CONFIG_I: Configured from console by vty0
'''
        out = analyze_syslog('SW1', sample)
        self.assertEqual(len(out), 4)
        self.assertEqual([r.status for r in out], ['WARNING', 'WARNING', 'WARNING', 'NOT_EVALUATED'])


class DriftTests(unittest.TestCase):
    def test_detect_vlan_change_when_running_config_is_unchanged(self):
        config = '\n'.join([
            'Building configuration...',
            'version 15',
            'hostname SW1',
            'service timestamps log datetime',
            'ip routing',
            'line vty 0 4',
            'logging on',
            'end',
        ])
        base_vlans = [
            {'vlan_id': '10', 'vlan_name': 'USERS'},
            {'vlan_id': '99', 'vlan_name': 'MANAGEMENT'},
        ]
        changed_vlans = base_vlans + [{'vlan_id': '40', 'vlan_name': 'LAB_AUTOMATION'}]
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(drift, 'BASELINE_DIR', Path(tmp) / 'baselines'), \
                 patch.object(drift, 'DIFF_DIR', Path(tmp) / 'diffs'):
                before = FakeConnection({'show running-config': config, 'show vlan brief': base_vlans})
                drift.capture_baseline('SW1', before, include_vlans=True)
                after = FakeConnection({'show running-config': config, 'show vlan brief': changed_vlans})
                result = drift.check_device_drift('SW1', after, include_vlans=True)
                self.assertEqual(result.status, 'WARNING')
                self.assertIn('running-config=False, VLAN=True', result.message)
                self.assertTrue(list((Path(tmp) / 'diffs').glob('*.diff')))


if __name__ == '__main__':
    unittest.main()
