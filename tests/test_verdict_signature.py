import json
import unittest
from unittest import mock

from sumproofy.lookup import LookupResult
from sumproofy.verdict import compare, MATCH, MISMATCH, NO_OFFICIAL
from sumproofy import signature

H = "a" * 64


class TestVerdict(unittest.TestCase):
    def test_match(self):
        v, _ = compare(H, LookupResult("found", official_hash=H))
        self.assertEqual(v, MATCH)

    def test_match_case_insensitive(self):
        v, _ = compare(H, LookupResult("found", official_hash=H.upper()))
        self.assertEqual(v, MATCH)

    def test_mismatch(self):
        v, ex = compare(H, LookupResult("found", official_hash="b" * 64))
        self.assertEqual(v, MISMATCH)
        self.assertIn("NOT", ex)

    def test_ambiguous_is_no_official(self):
        v, _ = compare(H, LookupResult("ambiguous", detail="two answers"))
        self.assertEqual(v, NO_OFFICIAL)

    def test_error_is_no_official(self):
        v, ex = compare(H, LookupResult("error", detail="boom"))
        self.assertEqual(v, NO_OFFICIAL)
        self.assertIn("boom", ex)

    def test_not_found_is_no_official(self):
        v, _ = compare(H, LookupResult("not_found", detail="none here"))
        self.assertEqual(v, NO_OFFICIAL)


class TestSignature(unittest.TestCase):
    def test_non_windows(self):
        with mock.patch.object(signature.sys, "platform", "linux"):
            r = signature.check_signature("C:/x/app.exe")
        self.assertEqual(r["status"], "not_windows")

    def test_not_signable_extension(self):
        with mock.patch.object(signature.sys, "platform", "win32"):
            r = signature.check_signature("C:/x/photo.zip")
        self.assertEqual(r["status"], "not_signable")

    def _run_on_windows(self, stdout, rc=0):
        class Out:
            returncode = rc
            stderr = ""
        Out.stdout = stdout
        with mock.patch.object(signature.sys, "platform", "win32"):
            return signature.check_signature("C:/x/app.exe", _runner=lambda *a, **k: Out())

    def test_valid_signature(self):
        r = self._run_on_windows(json.dumps({"Status": "Valid", "Signer": "CN=OpenJS"}))
        self.assertEqual((r["status"], r["signer"]), ("Valid", "CN=OpenJS"))

    def test_unsigned(self):
        r = self._run_on_windows(json.dumps({"Status": "NotSigned", "Signer": None}))
        self.assertEqual(r["status"], "NotSigned")

    def test_hash_mismatch_wording(self):
        r = self._run_on_windows(json.dumps({"Status": "HashMismatch", "Signer": "CN=X"}))
        self.assertIn("changed after signing", r["detail"])

    def test_garbage_output(self):
        r = self._run_on_windows("<not json>")
        self.assertEqual(r["status"], "unknown")

    def test_nonzero_exit(self):
        r = self._run_on_windows("", rc=1)
        self.assertEqual(r["status"], "unknown")

    def test_runner_raises(self):
        def boom(*a, **k):
            raise OSError("no powershell")
        with mock.patch.object(signature.sys, "platform", "win32"):
            r = signature.check_signature("C:/x/app.exe", _runner=boom)
        self.assertEqual(r["status"], "unknown")



class ReviewVerdictCase(unittest.TestCase):
    def _lookup(self, kind):
        from sumproofy.lookup import LookupResult
        return LookupResult("found", official_hash="a" * 64, source_kind=kind)

    def test_strong_match_wording_unchanged(self):
        v, why = compare("a" * 64, self._lookup("strong"))
        self.assertEqual(v, "match")
        self.assertEqual(why, "This file is exactly what the maker published.")

    def test_weak_match_wording_is_careful(self):
        v, why = compare("a" * 64, self._lookup("weak"))
        self.assertEqual(v, "match")
        self.assertIn("does not prove the page", why)
        self.assertNotEqual(why, "This file is exactly what the maker published.")

    def test_weak_mismatch_wording_is_careful(self):
        v, why = compare("b" * 64, self._lookup("weak"))
        self.assertEqual(v, "mismatch")
        self.assertIn("printed on that page", why)

    def test_strong_mismatch_wording_unchanged(self):
        v, why = compare("b" * 64, self._lookup("strong"))
        self.assertEqual(why, "The file is NOT what the maker published. Do not run or open it.")


if __name__ == "__main__":
    unittest.main()
