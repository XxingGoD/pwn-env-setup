import os, subprocess, sys, tempfile, unittest
from pathlib import Path
from pwn_env.installer import validate_prefix
from pwn_env.__main__ import main

class SafetyTests(unittest.TestCase):
    def test_root_and_home_prefix_are_rejected(self):
        with self.assertRaises(ValueError): validate_prefix("/")
        with self.assertRaises(ValueError): validate_prefix(Path.home())
    def test_exec_requires_separator(self):
        self.assertEqual(main(["exec", "echo"]), 2)
    def test_exec_preserves_cwd_and_quoted_arguments(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="pwn env ") as d:
            argument = "space ' quote ; $(touch SHOULD_NOT_EXIST)"
            env = {**os.environ,"PYTHONPATH":str(root),"PYTHONDONTWRITEBYTECODE":"1","PWN_ENV_PREFIX":d}
            result = subprocess.run([sys.executable,"-B","-m","pwn_env","exec","--",sys.executable,"-c","import os,sys; print(os.getcwd()); print(sys.argv[1]); sys.exit(7)",argument], cwd=d, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stdout.splitlines(), [d, argument])
            self.assertFalse((Path(d)/"SHOULD_NOT_EXIST").exists())
    def test_unknown_command_exits_127(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable,"-B","-m","pwn_env","exec","--","pwn-env-nonexistent-command"],cwd=root, env={**os.environ,"PYTHONPATH":str(root)},capture_output=True)
        self.assertEqual(result.returncode,127)
    def test_dry_run_never_creates_installation_files(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            for platform in ("ubuntu22.04", "ubuntu24.04", "arch"):
                result = subprocess.run([sys.executable,"-B","-m","pwn_env","--all","--dry-run","--platform",platform,"--prefix",str(home/"prefix")], cwd="/tmp", env={**os.environ,"HOME":d,"PYTHONPATH":str(root),"PYTHONDONTWRITEBYTECODE":"1"}, capture_output=True, text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(list(home.iterdir()),[])
    def test_noninteractive_yes_does_not_select_everything(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable,"-B","-m","pwn_env","--yes"], input="", cwd=root, env={**os.environ,"PYTHONPATH":str(root)}, capture_output=True,text=True)
        self.assertEqual(result.returncode,2)
if __name__ == "__main__": unittest.main()
