import json, os, subprocess, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from pwn_env.installer import validate_prefix, build_plan, execute_plan, _probe

class InstallationPlanTests(unittest.TestCase):
    def test_rejects_unowned_nonempty_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "prefix"; p.mkdir(); (p/"stranger").touch()
            with self.assertRaises(ValueError): validate_prefix(p)
    def test_package_failure_never_records_python_success(self):
        with tempfile.TemporaryDirectory() as d:
            prefix = Path(d)/"prefix"
            actions = build_plan(["pwntools"], "ubuntu24.04", prefix)
            with patch("pwn_env.installer._install_system", return_value=1), patch("os.geteuid", return_value=1000):
                self.assertEqual(execute_plan(actions, True, "ubuntu24.04", prefix), 1)
            self.assertFalse((prefix/"installed.json").exists())
    def test_private_python_entry_is_found_outside_host_path(self):
        with tempfile.TemporaryDirectory() as d:
            prefix = Path(d)
            binpath = prefix/"python/.venv/bin"
            binpath.mkdir(parents=True)
            command = binpath/"sample-tool"
            command.write_text("#!/bin/sh\nexit 0\n")
            command.chmod(0o755)
            tool = {"id":"sample-tool", "python_extra":"sample-tool", "probe":{"command":["sample-tool"]}}
            self.assertTrue(_probe(tool, prefix))
    def test_symlink_to_system_prefix_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"prefix"
            path.symlink_to("/usr")
            with self.assertRaises(ValueError): validate_prefix(path)
if __name__ == "__main__": unittest.main()
