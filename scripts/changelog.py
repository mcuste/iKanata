#!/usr/bin/env python3
"""Read release notes and move unreleased entries into a dated release."""

import argparse
from datetime import date
from pathlib import Path
import re


def section(text, version):
    headings = list(re.finditer(r"^## \[([^\]\n]+)\][^\n]*$", text, re.MULTILINE))
    matches = [index for index, heading in enumerate(headings) if heading[1] == version]
    if len(matches) != 1:
        raise ValueError(f"Expected one [{version}] section in CHANGELOG.md")
    index = matches[0]
    heading = headings[index]
    following = re.search(r"^## ", text[heading.end():], re.MULTILINE)
    end = heading.end() + following.start() if following else len(text)
    return heading.start(), heading.end(), end


def notes(text, version):
    _, start, end = section(text, version)
    body = text[start:end].strip()
    if not re.search(r"^\s*[-*] \S", body, re.MULTILINE):
        raise ValueError(f"[{version}] has no changelog entries")
    return body + "\n"


def rollover(text, version):
    if re.search(rf"^## \[{re.escape(version)}\]", text, re.MULTILINE):
        raise ValueError(f"CHANGELOG.md already contains [{version}]")
    start, _, end = section(text, "Unreleased")
    body = notes(text, "Unreleased")
    return (text[:start] + "## [Unreleased]\n\n"
            + f"## [{version}] - {date.today().isoformat()}\n\n"
            + body + ("\n" + text[end:] if text[end:] else ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    args = parser.parse_args()
    try:
        text = (Path(__file__).resolve().parent.parent / "CHANGELOG.md").read_text()
        print(notes(text, args.version), end="")
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
