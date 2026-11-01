
import unittest

from syslog_parser import analyze_syslog


class IOLSyslogTests(unittest.TestCase):

    def test_administrative_link_cycles(self):
        prefix = (
            "Syslog logging: enabled\n"
            "Buffer logging: level informational\n"
            "Log Buffer (16384 bytes):\n"
        )

        events = [
            ("17:31:26", "LINK-5-CHANGED",
             "administratively down"),
            ("17:31:27", "LINEPROTO-5-UPDOWN", "down"),
            ("17:31:33", "LINK-3-UPDOWN", "up"),
            ("17:31:34", "LINEPROTO-5-UPDOWN", "up"),
            ("17:31:39", "LINK-5-CHANGED",
             "administratively down"),
            ("17:31:40", "LINEPROTO-5-UPDOWN", "down"),
            ("17:31:46", "LINK-3-UPDOWN", "up"),
            ("17:31:47", "LINEPROTO-5-UPDOWN", "up"),
        ]

        lines = []

        for timestamp, event_type, state in events:
            facility = event_type.split("-")[0]

            subject = (
                "Line protocol on Interface Ethernet0/2"
                if facility == "LINEPROTO"
                else "Interface Ethernet0/2"
            )

            lines.append(
                f"Nov 1 2026 {timestamp}.000: "
                f"%{event_type}: "
                f"{subject}, changed state to {state}"
            )

        raw = prefix + "\n".join(lines)

        results = analyze_syslog("SW1", raw)
        flap = results[3]

        self.assertEqual(flap.status, "WARNING")
        self.assertEqual(flap.actual, ["Et0/2"])


if __name__ == "__main__":
    unittest.main()
