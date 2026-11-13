"""Windows-only behaviour: reserved device names, long paths, locked files."""
import os
import sys
import tempfile
import unittest

from sumproofy.hashing import sha256_file, HashError

pytestmark = unittest.skipUnless(sys.platform == "win32", "Windows-only")


@unittest.skipUnless(sys.platform == "win32", "Windows-only")
class TestWindows(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def test_device_names_refused_fast(self):
        # CON/NUL are devices, not files. They must be refused, never read
        # (reading CON would hang waiting for console input).
        for name in ("NUL", "CON"):
            with self.assertRaises((HashError, OSError, ValueError), msg=name):
                sha256_file(name)

    def test_long_path_over_260(self):
        base = os.path.abspath(self.dir.name)
        deep = base
        # build nested folders until the full path is well past 260 chars
        while len(deep) < 280:
            deep = os.path.join(deep, "d" * 40)
        ext = "\\\\?\\" + deep
        os.makedirs(ext)
        target = ext + "\\f.bin"
        with open(target, "wb") as fh:
            fh.write(b"abc")
        self.assertGreater(len(deep + "\\f.bin"), 260)
        self.assertEqual(sha256_file(target),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_exclusively_locked_file(self):
        import ctypes
        p = os.path.join(self.dir.name, "locked.exe")
        with open(p, "wb") as fh:
            fh.write(b"abc")
        GENERIC_READ_WRITE = 0xC0000000
        CREATE_NEW_OK = 3  # OPEN_EXISTING
        handle = ctypes.windll.kernel32.CreateFileW(
            str(p), GENERIC_READ_WRITE, 0, None, CREATE_NEW_OK, 0, None)
        self.assertNotEqual(handle, -1)
        try:
            with self.assertRaises(HashError):
                sha256_file(p)
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)

    def test_unc_style_input_path(self):
        p = os.path.join(self.dir.name, "u.bin")
        with open(p, "wb") as fh:
            fh.write(b"abc")
        ext = "\\\\?\\" + os.path.abspath(p)
        self.assertEqual(sha256_file(ext),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


if __name__ == "__main__":
    unittest.main()
