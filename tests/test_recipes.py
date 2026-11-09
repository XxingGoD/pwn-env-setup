import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from pwn_env.recipes import RecipeError, _safe_extract, _write_bin

class RecipeSafetyTests(unittest.TestCase):
    def test_archive_traversal_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as d:
            archive = Path(d)/"bad.tar"
            with tarfile.open(archive, "w") as tf:
                member = tarfile.TarInfo("../escaped")
                member.size = 1
                tf.addfile(member, io.BytesIO(b"x"))
            with self.assertRaises(RecipeError): _safe_extract(archive, Path(d)/"out")
            self.assertFalse((Path(d)/"escaped").exists())
    def test_internal_relative_symlink_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            archive = Path(d)/"safe.tar"
            with tarfile.open(archive, "w") as tf:
                base = tarfile.TarInfo("package")
                base.type = tarfile.DIRTYPE
                tf.addfile(base)
                file = tarfile.TarInfo("package/data")
                file.size = 1
                tf.addfile(file, io.BytesIO(b"x"))
                link = tarfile.TarInfo("package/alias")
                link.type = tarfile.SYMTYPE
                link.linkname = "data"
                tf.addfile(link)
            extracted = _safe_extract(archive, Path(d)/"out")
            self.assertEqual((extracted/"alias").read_text(), "x")
    def test_locked_pwndbg_archive_extracts_safely(self):
        archive_name = os.environ.get("PWN_ENV_TEST_PWNDBG_ARCHIVE")
        if not archive_name: self.skipTest("requires verified pinned Pwndbg release archive")
        with tempfile.TemporaryDirectory() as d:
            extracted = _safe_extract(Path(archive_name), Path(d)/"out")
            self.assertTrue((extracted/"bin"/"pwndbg").is_file())
    def test_unmanaged_binary_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            prefix = Path(d)
            (prefix/"bin").mkdir()
            original = prefix/"bin"/"pwndbg"
            original.write_text("user-owned program\n")
            with self.assertRaises(RecipeError): _write_bin(prefix,"bin/pwndbg","new program\n","pwndbg")
            self.assertEqual(original.read_text(),"user-owned program\n")

if __name__ == "__main__": unittest.main()
