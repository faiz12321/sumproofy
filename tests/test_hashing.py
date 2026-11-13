import hashlib
import os
import sys
import tempfile
import unittest
from unittest import mock

from sumproofy.hashing import sha256_file, HashError


class TestHashing(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, data):
        p = os.path.join(self.dir.name, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    def test_known_vector(self):
        p = self.write("a.bin", b"abc")
        self.assertEqual(sha256_file(p),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_empty_file(self):
        p = self.write("empty.bin", b"")
        self.assertEqual(sha256_file(p), hashlib.sha256(b"").hexdigest())

    def test_multichunk(self):
        data = os.urandom(3 * 1024 * 1024 + 7)
        p = self.write("big.bin", data)
        self.assertEqual(sha256_file(p), hashlib.sha256(data).hexdigest())

    def test_progress_called(self):
        p = self.write("b.bin", b"x" * (2 * 1024 * 1024 + 1))
        calls = []
        sha256_file(p, progress=lambda done, total: calls.append((done, total)))
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(calls[-1][0], calls[-1][1])

    def test_missing_file(self):
        with self.assertRaises(HashError):
            sha256_file(os.path.join(self.dir.name, "nope.bin"))

    def test_directory_refused(self):
        with self.assertRaises(HashError):
            sha256_file(self.dir.name)

    def test_blank_path_refused(self):
        for bad in ("", "   ", None):
            with self.assertRaises(HashError):
                sha256_file(bad)

    def test_quoted_path_unwrapped(self):
        p = self.write("q.bin", b"abc")
        self.assertEqual(sha256_file(f'"{p}"'), hashlib.sha256(b"abc").hexdigest())

    def test_file_changes_mid_read(self):
        p = self.write("c.bin", b"abc")
        real_getsize = os.path.getsize
        with mock.patch("sumproofy.hashing.os.path.getsize",
                        side_effect=lambda q: real_getsize(q) + 5):
            with self.assertRaises(HashError) as ctx:
                sha256_file(p)
            self.assertIn("changed", str(ctx.exception))

    @unittest.skipIf(sys.platform == "win32", "chmod has no effect on Windows")
    def test_unreadable_file(self):
        p = self.write("d.bin", b"abc")
        os.chmod(p, 0)
        try:
            with self.assertRaises(HashError):
                sha256_file(p)
        finally:
            os.chmod(p, 0o644)

    def test_unicode_filename(self):
        p = self.write("café ü.msi", b"abc")
        self.assertEqual(sha256_file(p), hashlib.sha256(b"abc").hexdigest())


if __name__ == "__main__":
    unittest.main()


class TestCancellation(unittest.TestCase):
    def test_progress_callback_can_stop_the_read(self):
        import tempfile, os
        from sumproofy.hashing import sha256_file, HashError
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"x" * (3 * 1024 * 1024))
            path = fh.name
        self.addCleanup(os.unlink, path)
        calls = []
        def stop_early(done, total):
            calls.append(done)
            if done >= 2 * 1024 * 1024:
                raise HashError("The check was taking too long, so it was stopped.")
        with self.assertRaises(HashError) as ctx:
            sha256_file(path, progress=stop_early)
        self.assertIn("stopped", str(ctx.exception))
        self.assertLess(len(calls), 4)  # did not read the whole file
