import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
import os

from privacy_scanner import Finding, scan


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "privacy_scanner.py"


def _can_symlink() -> bool:
    with tempfile.TemporaryDirectory() as temp_dir:
        target = Path(temp_dir) / "target"
        link = Path(temp_dir) / "link"
        target.touch()
        try:
            link.symlink_to(target)
            return True
        except OSError:
            return False

SUPPORTS_SYMLINKS = _can_symlink()



class ScannerTests(unittest.TestCase):
    def assert_detected(self, value: str, kind: str) -> None:
        self.assertEqual(
            scan(value), (f"[{kind}]", [Finding(kind, 1, 1, len(value))])
        )

    def test_valid_emails(self):
        for value in (
            "a@b.co",
            "1@2.ab",
            "ali@example.com",
            "ALI@EXAMPLE.COM",
            "a-b_c.d2@sub-domain.example.technology",
            "a__b@1.2.ab",
            "0.1@0-1.ir",
        ):
            with self.subTest(value=value):
                self.assert_detected(value, "EMAIL")

    def test_invalid_emails(self):
        for value in (
            "@example.com",
            "ali@",
            "ali.example.com",
            "ali@@example.com",
            ".ali@example.com",
            "ali.@example.com",
            "ali..reza@example.com",
            "-ali@example.com",
            "_ali@example.com",
            "ali-@example.com",
            "ali_@example.com",
            "a.-b@example.com",
            "a.b-@example.com",
            "a._b@example.com",
            "a.b_@example.com",
            "ali@example",
            "ali@.example.com",
            "ali@example..com",
            "ali@-example.com",
            "ali@example-.com",
            "ali@exam_ple.com",
            "ali@example.c",
            "ali@example.c0m",
            "ali@example.12",
            "ali@example.c-m",
            "ali@example.com-",
            "ali@example.com_",
            "ali@example.com@",
        ):
            with self.subTest(value=value):
                self.assertEqual(scan(value), (value, []))

    def test_valid_phones(self):
        for value in ("09123456789", "09000000000", "09999999999"):
            with self.subTest(value=value):
                self.assert_detected(value, "PHONE")

    def test_invalid_phones(self):
        for value in (
            "0912345678",
            "091234567890",
            "08123456789",
            "109123456789",
            "989123456789",
            "+989123456789",
            "00989123456789",
            "abc09123456789",
            "09123456789abc",
            "_09123456789",
            "09123456789-",
            "09123-456789",
            "0912 3456789",
            "09(123)456789",
            "۰۹۱۲۳۴۵۶۷۸۹",
            "٠٩١٢٣٤٥٦٧٨٩",
            "09۱۲۳۴۵۶۷۸۹",
        ):
            with self.subTest(value=value):
                self.assertEqual(scan(value), (value, []))

    def test_valid_ipv4_addresses(self):
        for value in (
            "0.0.0.0",
            "255.255.255.255",
            "192.168.1.15",
            "1.10.100.0",
            "127.0.0.1",
        ):
            with self.subTest(value=value):
                self.assert_detected(value, "IP")

    def test_invalid_ipv4_addresses(self):
        for value in (
            "256.1.1.1",
            "1.256.1.1",
            "1.1.256.1",
            "1.1.1.256",
            "999.168.1.15",
            "01.2.3.4",
            "1.02.3.4",
            "1.2.03.4",
            "1.2.3.04",
            "000.0.0.0",
            "1234.1.1.1",
            "1.1.1.1234",
            "1.2.3",
            "192.168.1.15.30",
            ".192.168.1.15",
            "192..168.1.15",
            "192.168.1..15",
            "-1.2.3.4",
            "x192.168.1.15",
            "192.168.1.15x",
            "192.168.1.15_",
            "192.168.1.15@",
            "۱۹۲.۱۶۸.۱.۱۵",
            "١٩٢.١٦٨.١.١٥",
        ):
            with self.subTest(value=value):
                self.assertEqual(scan(value), (value, []))

    def test_trailing_periods(self):
        for value, kind in (
            ("ali@example.com", "EMAIL"),
            ("09123456789", "PHONE"),
            ("192.168.1.15", "IP"),
        ):
            for suffix in (".", "..", "..."):
                with self.subTest(value=value, suffix=suffix):
                    self.assertEqual(
                        scan(value + suffix),
                        (f"[{kind}]" + suffix, [Finding(kind, 1, 1, len(value))]),
                    )

    def test_invalid_candidates_keep_trailing_periods(self):
        for value in (
            ".",
            "...",
            ".ali@example.com...",
            "ali..reza@example.com.",
            "999.168.1.15...",
            "192.168.1.15.30..",
            "abc09123456789.",
        ):
            with self.subTest(value=value):
                self.assertEqual(scan(value), (value, []))

    def test_candidate_alphabet(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_@"
        for character in alphabet:
            with self.subTest(character=character):
                value = "09123456789" + character
                if character == ".":
                    self.assertEqual(
                        scan(value), ("[PHONE].", [Finding("PHONE", 1, 1, 11)])
                    )
                else:
                    self.assertEqual(scan(value), (value, []))

    def test_separators_and_unicode_boundaries(self):
        separators = (" ", ",", "!", ":", ";", "/", "+", "(", ")", "[", "🙂", "م")
        for separator in separators:
            with self.subTest(separator=separator):
                text = separator + "ali@example.com" + separator
                self.assertEqual(
                    scan(text),
                    (separator + "[EMAIL]" + separator, [Finding("EMAIL", 1, 2, 15)]),
                )

    def test_positions_in_original_text(self):
        text = (
            "سلام\tali@example.com.\r\n"
            "09123456789\t192.168.1.15\rali@example.com\n"
            "x 09123456789"
        )
        self.assertEqual(
            scan(text),
            (
                "سلام\t[EMAIL].\r\n[PHONE]\t[IP]\r[EMAIL]\nx [PHONE]",
                [
                    Finding("EMAIL", 1, 6, 15),
                    Finding("PHONE", 2, 1, 11),
                    Finding("IP", 2, 13, 12),
                    Finding("EMAIL", 2, 26, 15),
                    Finding("PHONE", 3, 3, 11),
                ],
            ),
        )

    def test_unicode_columns_count_code_points(self):
        self.assertEqual(
            scan("🙂e\u0301\tali@example.com"),
            ("🙂e\u0301\t[EMAIL]", [Finding("EMAIL", 1, 5, 15)]),
        )

    def test_line_endings(self):
        for ending in ("\n", "\r\n", "\r"):
            with self.subTest(ending=repr(ending)):
                line, column = (1, 5) if ending == "\r" else (3, 1)
                self.assertEqual(
                    scan("a" + ending + "b" + ending + "09123456789"),
                    (
                        "a" + ending + "b" + ending + "[PHONE]",
                        [Finding("PHONE", line, column, 11)],
                    ),
                )

    def test_repeated_detections_and_existing_tags(self):
        self.assertEqual(
            scan("[EMAIL] a@b.co a@b.co"),
            (
                "[EMAIL] [EMAIL] [EMAIL]",
                [Finding("EMAIL", 1, 9, 6), Finding("EMAIL", 1, 16, 6)],
            ),
        )

    def test_text_without_detections_is_unchanged(self):
        for text in ("", "plain text", "متن فارسی\t🙂\r\n\r\n\r", "\ufeff", "\x00"):
            with self.subTest(text=text):
                self.assertEqual(scan(text), (text, []))

    def test_long_invalid_candidates(self):
        candidates = ("9" * 10_000, "9" * 10_000 + ".1.2.3", "a." * 5_000 + "@x.co")
        for text in candidates:
            with self.subTest(length=len(text)):
                self.assertEqual(scan(text), (text, []))

    def test_example(self):
        text = (ROOT / "examples/input.txt").read_text(encoding="utf-8")
        sanitized, findings = scan(text)
        expected = ROOT / "examples/expected"
        self.assertEqual(sanitized, (expected / "sanitized.txt").read_text())
        self.assertEqual(
            {
                "total_detected": len(findings),
                "findings": [asdict(f) for f in findings],
            },
            json.loads((expected / "report.json").read_text()),
        )


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.input = self.directory / "source.data"
        self.output = self.directory / "output"

    def run_scanner(self, *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, arguments)],
            cwd=self.directory,
            capture_output=True,
            text=True,
        )

    def test_writes_exactly_two_files_and_preserves_bytes(self):
        original = "سلام\tali@example.com.\r\n09123456789\r192.168.1.15\n".encode()
        self.input.write_bytes(original)
        result = self.run_scanner(self.input, "--output-dir", self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.input.read_bytes(), original)
        self.assertEqual(
            sorted(path.name for path in self.output.iterdir()),
            ["report.json", "sanitized.txt"],
        )
        self.assertEqual(
            (self.output / "sanitized.txt").read_bytes(),
            "سلام\t[EMAIL].\r\n[PHONE]\r[IP]\n".encode(),
        )
        self.assertEqual(
            json.loads((self.output / "report.json").read_text()),
            {
                "total_detected": 3,
                "findings": [
                    {"type": "EMAIL", "line": 1, "column": 6, "length": 15},
                    {"type": "PHONE", "line": 2, "column": 1, "length": 11},
                    {"type": "IP", "line": 2, "column": 13, "length": 12},
                ],
            },
        )

    def test_default_output_directory_and_no_detections(self):
        original = "متن\t\r\nplain\rtext\n".encode()
        self.input.write_bytes(original)
        result = self.run_scanner(self.input)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.directory / "sanitized.txt").read_bytes(), original)
        self.assertEqual(
            json.loads((self.directory / "report.json").read_text()),
            {"total_detected": 0, "findings": []},
        )

    def test_empty_input(self):
        self.input.write_bytes(b"")
        result = self.run_scanner(self.input)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.directory / "sanitized.txt").read_bytes(), b"")
        self.assertEqual(
            json.loads((self.directory / "report.json").read_text()),
            {"total_detected": 0, "findings": []},
        )

    def test_missing_input_and_invalid_utf8(self):
        for content in (None, b"\xff"):
            with self.subTest(content=content):
                if content is not None:
                    self.input.write_bytes(content)
                result = self.run_scanner(self.input, "--output-dir", self.output)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("error:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(self.output.exists())

    def test_input_cannot_be_an_output_file(self):
        for name in ("sanitized.txt", "report.json"):
            with self.subTest(name=name):
                source = self.directory / name
                source.write_bytes(b"ali@example.com")
                result = self.run_scanner(source)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must be distinct", result.stderr)
                self.assertEqual(source.read_bytes(), b"ali@example.com")

    @unittest.skipUnless(SUPPORTS_SYMLINKS, "Symbolic links not supported or lack required privileges")
    def test_output_symlink_cannot_overwrite_input(self):
        self.input.write_bytes(b"ali@example.com")
        (self.directory / "sanitized.txt").symlink_to(self.input)
        result = self.run_scanner(self.input)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.input.read_bytes(), b"ali@example.com")

    def test_output_hardlink_cannot_overwrite_input(self):
        self.input.write_bytes(b"ali@example.com")
        (self.directory / "report.json").hardlink_to(self.input)
        result = self.run_scanner(self.input)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.input.read_bytes(), b"ali@example.com")

    @unittest.skipUnless(SUPPORTS_SYMLINKS, "Symbolic links not supported or lack required privileges")
    def test_output_files_cannot_alias_each_other(self):
        self.input.write_bytes(b"ali@example.com")
        sanitized = self.directory / "sanitized.txt"
        sanitized.write_bytes(b"previous output")
        (self.directory / "report.json").symlink_to(sanitized)
        result = self.run_scanner(self.input)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sanitized.read_bytes(), b"previous output")

    def test_output_directory_cannot_be_a_file(self):
        self.input.write_bytes(b"ali@example.com")
        self.output.write_bytes(b"keep this")
        result = self.run_scanner(self.input, "--output-dir", self.output)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.output.read_bytes(), b"keep this")

    def test_outputs_are_replaced_on_rerun(self):
        self.input.write_bytes(b"ali@example.com")
        first = self.run_scanner(self.input, "--output-dir", self.output)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.input.write_bytes(b"plain")
        second = self.run_scanner(self.input, "--output-dir", self.output)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual((self.output / "sanitized.txt").read_bytes(), b"plain")
        self.assertEqual(
            json.loads((self.output / "report.json").read_text()),
            {"total_detected": 0, "findings": []},
        )


if __name__ == "__main__":
    unittest.main()
