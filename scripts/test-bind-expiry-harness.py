#!/usr/bin/env python3
"""Local, process-free regression tests for the BIND expiry harness."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'expiry_harness', Path(__file__).with_name('test-bind-expiry-recovery.py'))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class SocketDirectoryTests(unittest.TestCase):
    def test_shared_long_evidence_path_does_not_affect_socket_security(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / ('evidence-' + 'x' * 120)
            output.mkdir()
            output.chmod(0o775)
            sockets = []

            def check(*args):
                socket = args[-1]
                sockets.append(socket)
                self.assertEqual(socket.parent.parent, Path('/tmp'))
                self.assertEqual(stat.S_IMODE(socket.parent.stat().st_mode), 0o700)
                self.assertEqual(socket.parent.stat().st_uid, os.getuid())
                self.assertLess(len(os.fsencode(socket)), 104)
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o775)

            previous = os.umask(0o002)
            try:
                with patch.object(harness, '_scenario', side_effect=check):
                    harness.scenario(output, 'unused', 'unused', 'test', (1, 1, 1), 60)
                self.assertFalse(sockets[-1].parent.exists())

                def fail(*args):
                    check(*args)
                    raise RuntimeError('injected failure')

                with patch.object(harness, '_scenario', side_effect=fail):
                    with self.assertRaisesRegex(RuntimeError, 'injected failure'):
                        harness.scenario(output, 'unused', 'unused', 'test', (1, 1, 1), 60)
                self.assertFalse(sockets[-1].parent.exists())
            finally:
                os.umask(previous)


if __name__ == '__main__':
    unittest.main()
