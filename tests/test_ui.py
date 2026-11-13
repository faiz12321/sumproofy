"""The start page tells the user which link to paste."""
import unittest
from pathlib import Path


class TestUiNote(unittest.TestCase):
    def test_link_guidance_note_present(self):
        html = (Path(__file__).resolve().parent.parent /
                "sumproofy" / "ui.html").read_text(encoding="utf-8")
        self.assertIn("exact page where you clicked the download button", html)
        self.assertIn("home page usually does not show", html)


if __name__ == "__main__":
    unittest.main()
