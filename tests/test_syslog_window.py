"""Offline tesztek a Cisco IOS Syslog-időablakos flap-észleléshez."""
import unittest
from syslog_parser import analyze_syslog, parse_event_time

PREFIX = "Syslog logging: enabled\nBuffer logging: level informational\nLog Buffer (16384 bytes):\n"

def sample(times, states=None, kind="LINK", suffix=" UTC"):
    states = states or ["down", "up", "down", "up"]
    return PREFIX + "\n".join(
        f"Oct 28 2026 14:00:{seconds:02d}{suffix}: " +
        f"%{kind}-{'3' if kind == 'LINK' else '5'}-UPDOWN: " +
        f"{'Line protocol on ' if kind == 'LINEPROTO' else ''}"
        f"Interface Ethernet0/2, changed state to {state}"
        for seconds, state in zip(times, states)
    ) + "\n"

class SyslogWindowTests(unittest.TestCase):
    def flap(self, raw):
        return analyze_syslog("SW1", raw)[3]

    def test_four_transitions_within_60_seconds(self):
        r = self.flap(sample([0, 12, 24, 37]))
        self.assertEqual((r.status, r.actual), ("WARNING", ["Et0/2"]))

    def test_outside_window_is_pass(self):
        # 00:00, 01:00, 02:00 és 03:00
        raw = PREFIX + "\n".join(
            f"Oct 28 2026 14:{minute:02d}:00 UTC: "
            f"%LINK-3-UPDOWN: Interface Ethernet0/2, changed state to {state}"
            for minute, state in enumerate(["down", "up", "down", "up"])
        )
        self.assertEqual(self.flap(raw).status, "PASS")

    def test_only_three_transitions_is_pass(self):
        self.assertEqual(self.flap(sample([0, 12, 24], ["down", "up", "down"])).status, "PASS")

    def test_missing_timestamps_not_evaluated(self):
        raw = PREFIX + "\n".join(
            f"%LINK-3-UPDOWN: Interface Ethernet0/2, changed state to {state}"
            for state in ("down", "up", "down", "up")
        )
        self.assertEqual(self.flap(raw).status, "NOT_EVALUATED")

    def test_duplicates_and_out_of_order(self):
        raw = sample([37, 24, 12, 0], ["up", "down", "up", "down"])
        raw += "Oct 28 2026 14:00:00 UTC: %LINK-3-UPDOWN: Interface Ethernet0/2, changed state to down\n"
        self.assertEqual(self.flap(raw).status, "WARNING")

    def test_untrusted_time_not_evaluated(self):
        raw = sample([0, 12, 24, 37]).replace("Oct 28", "*Oct 28")
        self.assertEqual(self.flap(raw).status, "NOT_EVALUATED")

    def test_timestamp_variants(self):
        self.assertIsNotNone(parse_event_time("Oct 28 2026 14:00:00.123 UTC: "))
        self.assertIsNotNone(parse_event_time("Oct 28 14:00:00 UTC 2026: "))
        self.assertIsNone(parse_event_time("Oct 28 14:00:00 UTC: "))

if __name__ == "__main__":
    unittest.main()
