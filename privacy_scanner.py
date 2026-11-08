import argparse
import json
from dataclasses import asdict, dataclass
from itertools import combinations
from pathlib import Path
from string import ascii_letters, digits

CANDIDATE_CHARACTERS = frozenset(ascii_letters + digits + ".-_@")


@dataclass(frozen=True)
class Finding:
    type: str
    line: int
    column: int
    length: int


def _is_ascii_alphanumeric(character: str) -> bool:
    return character.isascii() and character.isalnum()


def _is_email(candidate: str) -> bool:
    if candidate.count("@") != 1:
        return False

    local, domain = candidate.split("@")
    for part in local.split("."):
        if not part or not (
            _is_ascii_alphanumeric(part[0]) and _is_ascii_alphanumeric(part[-1])
        ):
            return False
        if any(not (_is_ascii_alphanumeric(c) or c in "-_") for c in part):
            return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or not (
            _is_ascii_alphanumeric(label[0]) and _is_ascii_alphanumeric(label[-1])
        ):
            return False
        if any(not (_is_ascii_alphanumeric(c) or c == "-") for c in label):
            return False

    tld = labels[-1]
    return len(tld) >= 2 and tld.isascii() and tld.isalpha()


def _is_phone(candidate: str) -> bool:
    return (
        len(candidate) == 11
        and candidate.startswith("09")
        and candidate.isascii()
        and candidate.isdigit()
    )


def _is_ipv4(candidate: str) -> bool:
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not (1 <= len(part) <= 3 and part.isascii() and part.isdigit()):
            return False
        if len(part) > 1 and part.startswith("0"):
            return False
        if int(part) > 255:
            return False
    return True


def _classify(candidate: str) -> str | None:
    if _is_email(candidate):
        return "EMAIL"
    if _is_phone(candidate):
        return "PHONE"
    if _is_ipv4(candidate):
        return "IP"
    return None


def scan(text: str) -> tuple[str, list[Finding]]:
    output: list[str] = []
    findings: list[Finding] = []
    index = 0
    line = 1
    column = 1

    while index < len(text):
        character = text[index]
        if character not in CANDIDATE_CHARACTERS:
            output.append(character)
            if character == "\n":
                line += 1
                column = 1
            else:
                column += 1
            index += 1
            continue

        start = index
        while index < len(text) and text[index] in CANDIDATE_CHARACTERS:
            index += 1

        candidate = text[start:index]
        value = candidate.rstrip(".")
        kind = _classify(value)
        if kind is None:
            output.append(candidate)
        else:
            output.append(f"[{kind}]")
            output.append(candidate[len(value) :])
            findings.append(Finding(kind, line, column, len(value)))
        column += len(candidate)

    return "".join(output), findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replace emails, Iranian mobile numbers, and IPv4 addresses."
    )
    parser.add_argument("input", type=Path, help="UTF-8 input file")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="output directory (default: .)",
    )
    args = parser.parse_args()
    sanitized_path = args.output_dir / "sanitized.txt"
    report_path = args.output_dir / "report.json"

    try:
        for left, right in combinations((args.input, sanitized_path, report_path), 2):
            if left.resolve() == right.resolve() or (
                left.exists() and right.exists() and left.samefile(right)
            ):
                parser.error("input and output files must be distinct")

        with args.input.open(encoding="utf-8", newline="") as source:
            sanitized, findings = scan(source.read())

        args.output_dir.mkdir(parents=True, exist_ok=True)
        with sanitized_path.open("w", encoding="utf-8", newline="") as destination:
            destination.write(sanitized)
        with report_path.open("w", encoding="utf-8", newline="") as destination:
            json.dump(
                {
                    "total_detected": len(findings),
                    "findings": [asdict(finding) for finding in findings],
                },
                destination,
                indent=2,
            )
            destination.write("\n")
    except (OSError, UnicodeError) as error:
        parser.exit(1, f"{parser.prog}: error: {error}\n")


if __name__ == "__main__":
    main()
