# Privacy Scanner

Compiler course, homework 1 bonus. A character-based scanner for email addresses,
Iranian mobile numbers, and IPv4 addresses. Uses Python 3.10+ and the standard
library. No installation is needed.

## Run

```sh
python3 privacy_scanner.py examples/input.txt --output-dir output
```

The output directory is created if needed. Each run writes `sanitized.txt` and
`report.json`, replacing existing outputs. Without `--output-dir`, both files go
in the current directory. The input must be UTF-8 and can have any extension.
Input and output paths must refer to distinct files.

The JSON report lists detections in source order with their type, original line,
column, and length. Lines and columns start at 1. Tabs count as one character;
lengths and columns count Unicode characters, not bytes.

## Scanning rules

The scanner reads maximal candidates containing `A-Z`, `a-z`, `0-9`, `.`, `-`,
`_`, or `@`. It sets aside trailing periods, then validates the entire remaining
candidate. Invalid candidates stay unchanged; valid substrings inside them are
never extracted. Trailing periods and all separators are preserved.

- **Email:** dot-separated local parts with ASCII letters, digits, `-`, and `_`;
  each part starts and ends with a letter or digit. The domain has at least two
  labels, permits internal hyphens, and ends with at least two ASCII letters.
- **Phone:** exactly 11 ASCII digits starting with `09`.
- **IPv4:** four decimal octets from 0 to 255, with no leading zeros.

LF and CRLF line endings are preserved. A standalone CR counts as an ordinary
character. Following the detailed specification, the introductory example's
newlines are preserved, and each report entry's `type` is a string.

Scanning takes O(n) time and O(n) memory for n input characters. The input,
sanitized text, and findings are held in memory.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests cover validation, candidate boundaries, punctuation, Unicode, source
positions, line endings, and file execution. Expected outputs for the example
are in `examples/expected/`.
