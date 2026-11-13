import unittest

from sumproofy.checksums import (parse_checksum_text, extract_hashes_near_name,
                                        find_sidecar_links, MAX_LINES)

H = "a" * 64
H2 = "b" * 64


class TestParse(unittest.TestCase):
    def test_gnu_two_spaces(self):
        self.assertEqual(parse_checksum_text(f"{H}  node.msi", "node.msi"),
                         (H, "found", "official fingerprint found"))

    def test_gnu_binary_marker(self):
        self.assertEqual(parse_checksum_text(f"{H} *node.msi", "node.msi")[1], "found")

    def test_bsd_format(self):
        self.assertEqual(parse_checksum_text(f"SHA256 (node.msi) = {H}", "node.msi")[1], "found")

    def test_bare_single(self):
        self.assertEqual(parse_checksum_text(H, "node.msi")[1], "found")

    def test_uppercase_hex(self):
        self.assertEqual(parse_checksum_text(H.upper() + "  node.msi", "node.msi")[0], H)

    def test_wrong_name_not_found(self):
        self.assertEqual(parse_checksum_text(f"{H}  other.msi", "node.msi")[1], "not_found")

    def test_ambiguous_same_name(self):
        self.assertEqual(parse_checksum_text(f"{H}  node.msi\n{H2}  node.msi", "node.msi")[1],
                         "ambiguous")

    def test_ambiguous_bare_hashes(self):
        self.assertEqual(parse_checksum_text(f"{H}\n{H2}", "node.msi")[1], "ambiguous")

    def test_bare_ignored_when_named_lines_exist(self):
        self.assertEqual(parse_checksum_text(f"{H}  other.msi\n{H2}", "node.msi")[1], "not_found")

    def test_directory_part_stripped(self):
        self.assertEqual(parse_checksum_text(f"{H}  dist/node.msi", "node.msi")[1], "found")
        self.assertEqual(parse_checksum_text(f"{H}  dist\\node.msi", "node.msi")[1], "found")

    def test_crlf_and_bom(self):
        self.assertEqual(parse_checksum_text("\ufeff" + H + "  node.msi\r\n", "node.msi")[1], "found")

    def test_comments_skipped(self):
        self.assertEqual(parse_checksum_text(f"# comment\n{H}  node.msi", "node.msi")[1], "found")

    def test_partial_name_no_match(self):
        self.assertEqual(parse_checksum_text(f"{H}  node.msi.sig", "node.msi")[1], "not_found")

    def test_63_and_65_hex_not_hashes(self):
        self.assertEqual(parse_checksum_text("a" * 63, "node.msi")[1], "not_found")
        self.assertEqual(parse_checksum_text("a" * 65, "node.msi")[1], "not_found")

    def test_huge_file_capped(self):
        text = (H + "\n") * (MAX_LINES + 1)
        self.assertEqual(parse_checksum_text(text, "node.msi")[1], "not_found")

    def test_empty_text(self):
        self.assertEqual(parse_checksum_text("", "node.msi")[1], "not_found")


class TestNearName(unittest.TestCase):
    def test_hash_near_name(self):
        self.assertEqual(extract_hashes_near_name(f"get node.msi sha256 {H} ok", "node.msi"), {H})

    def test_hash_belongs_to_other_file(self):
        text = f"other.msi {H} " + "x" * 200 + "node.msi"
        self.assertEqual(extract_hashes_near_name(text, "node.msi"), set())

    def test_two_hashes_ambiguous_set(self):
        self.assertEqual(extract_hashes_near_name(f"node.msi SHA256: {H} or checksum {H2}", "node.msi"), {H, H2})

    def test_far_away_ignored(self):
        self.assertEqual(extract_hashes_near_name(H + "x" * 400 + "node.msi", "node.msi"), set())

    def test_no_name(self):
        self.assertEqual(extract_hashes_near_name(H, "node.msi"), set())


class TestSidecarLinks(unittest.TestCase):
    def test_relative_resolved(self):
        self.assertEqual(find_sidecar_links('<a href="sums.sha256">x</a>', "https://a.org/d/"),
                         ["https://a.org/d/sums.sha256"])

    def test_javascript_refused(self):
        self.assertEqual(find_sidecar_links('<a href="javascript:x.sha256">x</a>', "https://a.org/"), [])

    def test_no_links(self):
        self.assertEqual(find_sidecar_links("<p>none</p>", "https://a.org/"), [])



from sumproofy.checksums import extract_hashes_near_name, decode_text



class ReviewChecksumCase(unittest.TestCase):
    def test_unlabelled_hex_near_name_ignored(self):
        page = "download app.exe here " + H + " thanks"
        self.assertEqual(extract_hashes_near_name(page, "app.exe"), set())

    def test_labelled_hex_near_name_found(self):
        for label in ("SHA256:", "sha-256", "Checksum", "SHA-256 fingerprint"):
            page = "app.exe " + label + " " + H
            self.assertEqual(extract_hashes_near_name(page, "app.exe"), {H}, label)

    def test_case_insensitive_name_match_gnu(self):
        h, status, _ = parse_checksum_text(H + "  APP.EXE", "app.exe")
        self.assertEqual((h, status), (H, "found"))

    def test_case_insensitive_name_match_bsd(self):
        h, status, _ = parse_checksum_text("SHA256 (App.Exe) = " + H, "APP.EXE")
        self.assertEqual((h, status), (H, "found"))

    def test_case_variant_hashes_are_ambiguous_not_guessed(self):
        text = H + "  app.exe\n" + H2 + "  APP.EXE\n"
        h, status, _ = parse_checksum_text(text, "app.exe")
        self.assertEqual(status, "ambiguous")

    def test_utf16_checksum_files(self):
        line = H + "  app.exe\n"
        for enc in ("utf-16", "utf-16-le", "utf-16-be"):
            body = line.encode(enc)
            h, status, _ = parse_checksum_text(decode_text(body), "app.exe")
            self.assertEqual((h, status), (H, "found"), enc)

    def test_utf8_bom_checksum_file(self):
        body = ("\ufeff" + H + "  app.exe\n").encode("utf-8")
        h, status, _ = parse_checksum_text(decode_text(body), "app.exe")
        self.assertEqual((h, status), (H, "found"))


if __name__ == "__main__":
    unittest.main()

class TestSidecarNames(unittest.TestCase):
    def test_common_checksum_file_names(self):
        page = ('<a href="SHASUMS256.txt">a</a><a href="SHA256SUMS">b</a>'
                '<a href="SHA256SUMS.txt">c</a><a href="f.sha256">d</a>'
                '<a href="f.sha256sums">e</a><a href="f.sha256.txt">f</a>')
        links = find_sidecar_links(page, "https://x.test/dist/")
        self.assertEqual(len(links), 6)
        self.assertTrue(links[0].endswith("SHASUMS256.txt"))

    def test_non_checksum_links_ignored(self):
        page = '<a href="node.msi">a</a><a href="notes.txt">b</a><a href="shasum.md">c</a>'
        self.assertEqual(find_sidecar_links(page, "https://x.test/"), [])
