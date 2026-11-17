#!/usr/bin/env python3
"""Prepare, verify, tag, and optionally push a workspace release."""

import argparse
from pathlib import Path
import re
import subprocess
import tomllib

from changelog import rollover

ROOT = Path(__file__).resolve().parent.parent


def run(*args, capture=False):
    result = subprocess.run(args, cwd=ROOT, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def version_parts(value):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError("Use a three-part numeric version without leading zeros")
    return tuple(map(int, value.split(".")))


def prepare(version, push):
    requested = version_parts(version)
    manifest = ROOT / "Cargo.toml"
    original = manifest.read_bytes()
    data = tomllib.loads(original.decode())
    current = data["workspace"]["package"]["version"]
    if requested < version_parts(current):
        raise ValueError("The release version cannot be below the workspace version")
    if run("git", "status", "--porcelain", capture=True):
        raise ValueError("Commit or stash working tree changes before releasing")
    if run("git", "branch", "--show-current", capture=True) != "main":
        raise ValueError("Release from main")
    tag = "v" + version
    if run("git", "tag", "--list", tag, capture=True):
        raise ValueError(tag + " already exists")
    lockfile = ROOT / "Cargo.lock"
    original_lock = lockfile.read_bytes()
    changelog = ROOT / "CHANGELOG.md"
    original_changelog = changelog.read_bytes()
    released_changelog = rollover(original_changelog.decode(), version)
    text = original.decode()
    section = None
    lines = []
    for line in text.splitlines(keepends=True):
        if line.startswith("["):
            section = line.strip()
        if section == "[workspace.package]":
            line = re.sub(r'^version = "[^"]+"', 'version = "' + version + '"', line)
        elif section == "[workspace.dependencies]":
            name = line.split("=", 1)[0].strip()
            dependency = data["workspace"]["dependencies"].get(name)
            if isinstance(dependency, dict) and "path" in dependency:
                line = re.sub(r'version = "=[^"]+"', 'version = "=' + version + '"', line)
        lines.append(line)
    try:
        manifest.write_text("".join(lines))
        changelog.write_text(released_changelog)
        run("cargo", "check", "--workspace")
        run("just", "verify")
    except (OSError, subprocess.CalledProcessError):
        manifest.write_bytes(original)
        lockfile.write_bytes(original_lock)
        changelog.write_bytes(original_changelog)
        raise
    if run("git", "diff", "--name-only", capture=True):
        run("git", "add", "Cargo.toml", "Cargo.lock", "CHANGELOG.md")
        run("git", "commit", "-m", "chore: release " + version)
    run("git", "tag", tag)
    if push:
        run("git", "push", "--atomic", "origin", "main", tag)
    else:
        print("Publish with: git push --atomic origin main " + tag)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    try:
        prepare(args.version, args.push)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, "Release failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
