"""COM command parsing must preserve the binary path without probing it."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adint_scan.modules import host


class TestServerPath(unittest.TestCase):
    def test_command_boundaries(self):
        cases = (
            (r'C:\tool.exe\payload.bat -Embedding', r'C:\tool.exe\payload.bat'),
            (r'C:\folder.com\payload.exe -Embedding', r'C:\folder.com\payload.exe'),
            (r'C:\folder.exe.backup\payload.cmd /quiet', r'C:\folder.exe.backup\payload.cmd'),
            (r'C:/folder.exe/payload.COM -Embedding', r'C:/folder.exe/payload.COM'),
            (r'C:\folder.cmd\payload.exe', r'C:\folder.cmd\payload.exe'),
            (r'C:\Program Files\server.exe -Embedding', r'C:\Program Files\server.exe'),
            (r'C:\server.com --helper C:\later.exe', r'C:\server.com'),
            (r'C:\server.bat --helper C:\later.exe', r'C:\server.bat'),
            (r'C:\server.cmd --helper C:\later.com', r'C:\server.cmd'),
            ('C:\\server.EXE\t-Embedding', r'C:\server.EXE'),
            (r'"C:\Program Files\tool.exe\payload.bat" -Embedding',
             r'C:\Program Files\tool.exe\payload.bat'),
            (r'\\remote.invalid\share.exe\payload.bat -Embedding',
             r'\\remote.invalid\share.exe\payload.bat'),
        )
        with patch.object(host.os.path, 'exists', side_effect=AssertionError('filesystem probe')), \
             patch.object(host.os, 'stat', side_effect=AssertionError('filesystem probe')), \
             patch.object(host.subprocess, 'run', side_effect=AssertionError('command execution')):
            for raw, expected in cases:
                with self.subTest(raw=raw):
                    self.assertEqual(host._server_path(raw, 'LocalServer32'), expected)

    def test_bare_dll_values_keep_spaces_and_extension_like_directories(self):
        for kind in ('InprocServer32', 'InprocHandler32'):
            for raw in (r'C:\folder.exe\my server.dll', r'"C:\my folder\server.dll"'):
                with self.subTest(kind=kind, raw=raw):
                    self.assertEqual(host._server_path(raw, kind), raw.strip('"'))

    def test_environment_expansion_precedes_command_parsing(self):
        with patch.dict(os.environ, {'ZB_SERVER_TEST': r'C:\folder.exe'}):
            self.assertEqual(host._server_path('${ZB_SERVER_TEST}\\payload.cmd -Embedding',
                                              'LocalServer32'), r'C:\folder.exe\payload.cmd')


if __name__ == '__main__':
    unittest.main()
