
import os
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

import connection


class SSHSecurityTests(unittest.TestCase):

    def test_strict_ssh_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            host_keys = Path(directory) / "known_hosts"
            host_keys.write_text(
                "test-host ssh-rsa test-public-key\n",
                encoding="utf-8",
            )

            device = {
                "name": "R1",
                "host": "10.10.99.1",
                "device_type": "cisco_ios",
            }

            with (
                patch.object(
                    connection,
                    "HOST_KEYS_FILE",
                    host_keys,
                ),
                patch.dict(
                    os.environ,
                    {
                        "DEVICE_USERNAME": "test",
                        "DEVICE_PASSWORD": "test",
                    },
                ),
                patch.object(
                    connection,
                    "ConnectHandler",
                ) as mock_connect,
            ):
                connection.connect_to_device(device)

                kwargs = mock_connect.call_args.kwargs

                self.assertTrue(kwargs["ssh_strict"])
                self.assertTrue(kwargs["alt_host_keys"])
                self.assertFalse(kwargs["system_host_keys"])
                self.assertEqual(
                    kwargs["alt_key_file"],
                    str(host_keys),
                )

    def test_missing_host_keys_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"

            with (
                patch.object(
                    connection,
                    "HOST_KEYS_FILE",
                    missing,
                ),
                patch.dict(
                    os.environ,
                    {
                        "DEVICE_USERNAME": "test",
                        "DEVICE_PASSWORD": "test",
                    },
                ),
                patch.object(
                    connection,
                    "ConnectHandler",
                ) as mock_connect,
            ):
                with self.assertRaises(RuntimeError):
                    connection.connect_to_device(
                        {
                            "name": "R1",
                            "host": "10.10.99.1",
                            "device_type": "cisco_ios",
                        }
                    )

                mock_connect.assert_not_called()

    def test_empty_host_keys_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "known_hosts"
            empty.touch()

            with (
                patch.object(
                    connection,
                    "HOST_KEYS_FILE",
                    empty,
                ),
                patch.dict(
                    os.environ,
                    {
                        "DEVICE_USERNAME": "test",
                        "DEVICE_PASSWORD": "test",
                    },
                ),
                patch.object(
                    connection,
                    "ConnectHandler",
                ) as mock_connect,
            ):
                with self.assertRaises(RuntimeError):
                    connection.connect_to_device(
                        {
                            "name": "R1",
                            "host": "10.10.99.1",
                            "device_type": "cisco_ios",
                        }
                    )

                mock_connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
