import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import reconflow_v2


class TestCustomHeaders(unittest.TestCase):
    def _run(self, headers):
        proc = MagicMock(stdout="")
        with patch("reconflow_v2.shutil.which", return_value="/usr/bin/httpx"), \
             patch("reconflow_v2.subprocess.run", return_value=proc) as run, \
             tempfile.TemporaryDirectory() as d:
            reconflow_v2.run_httpx(["a.example.com"], Path(d), headers=headers)
        return run.call_args[0][0]

    def test_headers_forwarded(self):
        cmd = self._run(["X-Bug-Bounty: user", "X-Security-Research: true"])
        pairs = [(cmd[i], cmd[i + 1]) for i in range(len(cmd) - 1) if cmd[i] == "-H"]
        self.assertEqual(pairs, [("-H", "X-Bug-Bounty: user"),
                                 ("-H", "X-Security-Research: true")])

    def test_no_headers(self):
        self.assertNotIn("-H", self._run(None))


if __name__ == "__main__":
    unittest.main()
