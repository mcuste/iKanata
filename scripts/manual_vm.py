#!/usr/bin/env python3
"""Run fresh-install or reinstall acceptance with human keyboard checks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
CLI = "/Applications/iKanata.app/Contents/MacOS/ikanata"
FIXTURE = ROOT / "release/manual-test.kbd"


def checksum(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.name = args.name or "ikanata-manual-" + args.scenario + "-" + uuid.uuid4().hex[:8]
        self.directory = ROOT / "target/manual-vm" / self.name
        self.created_report = False
        self.report = {"scenario": args.scenario, "vm": self.name, "image": args.image,
                       "scope": "VM functional acceptance, not protected-Mac acceptance",
                       "status": "in-progress", "checks": []}

    def record(self, name, source="automatic"):
        self.report["checks"].append({"name": name, "source": source})
        self.save()

    def save(self):
        (self.directory / "result.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def command(self, *args, capture=False, timeout=180):
        return subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True,
                              text=True, stdout=subprocess.PIPE if capture else None,
                              timeout=timeout)

    def guest(self, *args, capture=False, timeout=180):
        return self.command("tart", "exec", self.name, *args,
                            capture=capture, timeout=timeout)

    def shell(self, script, *args, capture=False):
        return self.guest("/bin/sh", "-ec", script, "--", *args, capture=capture)

    def human(self, message, token="PASS"):
        print("\n" + message, flush=True)
        if input(f"Type {token} to continue, or anything else to stop: ").strip() != token:
            raise ValueError("Manual check stopped; no pass recorded")

    def stage(self, package):
        digest = checksum(package)
        target = self.args.artifacts / digest / package.name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if checksum(target) != digest:
                raise ValueError("An immutable shared artifact has changed")
        else:
            shutil.copyfile(package, target)
        return "/Volumes/My Shared Files/ikanata/" + digest + "/" + package.name, digest

    def create(self):
        inventory = self.command("tart", "list", "--quiet", capture=True).stdout.splitlines()
        if self.name in inventory or self.directory.exists():
            raise ValueError("Use a new --name; existing VMs and reports are never replaced")
        self.directory.mkdir(parents=True)
        self.created_report = True
        self.save()
        environment = os.environ.copy()
        environment["TART_NO_AUTO_PRUNE"] = "1"
        subprocess.run(["tart", "clone", self.args.image, self.name], cwd=ROOT,
                       env=environment, check=True)
        self.command("tart", "set", self.name, "--cpu", self.args.cpu,
                     "--memory", self.args.memory)
        with (self.directory / "tart.log").open("w") as log:
            runner = subprocess.Popen(
                ["tart", "run", self.name, "--no-clipboard", "--dir",
                 "ikanata:" + str(self.args.artifacts) + ":ro"], cwd=ROOT,
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 180
        while True:
            if runner.poll() is not None:
                raise ValueError("Tart stopped; inspect " + str(self.directory / "tart.log"))
            try:
                self.guest("/usr/bin/true", timeout=10)
                break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                if time.monotonic() >= deadline:
                    raise ValueError("Guest Agent did not become ready") from None
                time.sleep(2)
        self.shell('test ! -e /Applications/iKanata.app; '
                   'test ! -e "$HOME/.config/kanata/config.kbd"; '
                   '/usr/bin/sudo -n /usr/bin/true')
        self.record("Fresh VM without iKanata or configuration; password-free guest execution")
        self.guest("/usr/bin/csrutil", "status")
        policy = subprocess.run(
            ["tart", "exec", self.name, "/usr/sbin/spctl", "--status"],
            cwd=ROOT, check=False, timeout=30, text=True, capture_output=True)
        state = policy.stdout.strip()
        if (policy.returncode, state) not in {
            (0, "assessments enabled"), (1, "assessments disabled"),
        }:
            raise ValueError("Cannot inspect guest Gatekeeper policy: " + policy.stderr.strip())
        print(state, flush=True)
        self.report["gatekeeper"] = state
        print("This CI image is not protected-Mac security acceptance.", flush=True)

    def install(self, package, label):
        path, digest = self.stage(package)
        self.shell('test "$(/usr/bin/shasum -a 256 "$1" | /usr/bin/cut -d " " -f 1)" = "$2"; '
                   '/usr/bin/sudo -n /usr/sbin/installer -pkg "$1" -target /', path, digest)
        self.record(label + " package installed: " + digest)
        while True:
            self.human("In the VM, approve iKanata background access so its root service can install the bundled driver.\n"
                       "Approve the macOS extension, Accessibility and Input Monitoring prompts. No driver wizard is needed.\n"
                       "Do not install full Karabiner-Elements or change host settings. Return when VM approvals are complete.", "CHECK")
            try:
                self.guest(CLI, "status")
                self.guest("/usr/bin/sudo", "-n", "/bin/sh", "-ec",
                           'test -S "/Library/Application Support/iKanata/control.sock"')
                break
            except subprocess.CalledProcessError:
                print("Runtime is not ready. Resolve the displayed issue before checking again.")
        self.shell('/usr/bin/pgrep -x Installer >/dev/null && status=0 || status=$?; '
                   'test "$status" = 1 || { echo "Unexpected Installer UI or process-check failure" >&2; exit 1; }')
        self.record(label + " has no active Installer wizard")
        self.guest("/usr/bin/codesign", "--verify", "--deep", "--strict", "/Applications/iKanata.app")
        self.record(label + " runtime ready and app signature valid")

    def configure(self):
        path, digest = self.stage(FIXTURE)
        self.shell('config="$HOME/.config/kanata/config.kbd"; '
                   'test -f "$config" && test ! -L "$config"; '
                   'backup="$HOME/ikanata-manual-config-before-test.kbd"; test ! -e "$backup"; '
                   '/bin/cp -p "$config" "$backup"; '
                   '/Applications/iKanata.app/Contents/Resources/kanata --check --cfg "$1"; '
                   '/bin/cp "$1" "$config"; /bin/chmod 600 "$config"', path)
        self.guest(CLI, "reload")
        self.assert_config(digest)
        self.record("Caps Lock to Escape fixture validated and loaded")
        return digest

    def assert_config(self, digest):
        self.shell('test "$(/usr/bin/shasum -a 256 "$HOME/.config/kanata/config.kbd" '
                   '| /usr/bin/cut -d " " -f 1)" = "$1"', digest)

    def keyboard(self, label, removed=False):
        self.guest("/usr/bin/open", "-a", "TextEdit")
        expected = ("Press Command-F, then Caps Lock: Find must stay open. "
                    "Type a: it must print A. Turn Caps Lock off afterward."
                    if removed else
                    "Press Command-F, then Caps Lock: Find must close as with Escape. "
                    "Caps Lock must not toggle capitalization.")
        self.human("In the VM's TextEdit, create a blank plain-text document.\n"
                   "With Caps Lock off, typing a must print a.\n" + expected + "\n"
                   "Use the physical keyboard, not paste or simulated key events.\n"
                   "Do not continue if any result differs.")
        self.record(label + " physical keyboard check", "human")

    def uninstall(self, digest):
        self.human("The next check deletes iKanata and the VirtualHID driver only inside " +
                   self.name + ". Approve driver removal in macOS if requested. "
                   "Your test config must remain.", "DELETE")
        self.guest(CLI, "uninstall", "--keep-app", "--remove-driver")
        self.guest("/usr/bin/sudo", "-n", "/bin/sh", "-ec",
                   'test ! -e "/Library/Application Support/iKanata"; '
                   'test ! -e /Library/PrivilegedHelperTools/iKanata; '
                   'if /bin/launchctl print system/io.github.mcuste.ikanata.service >/dev/null 2>&1; then exit 1; fi; '
                   '/bin/rm -rf /Applications/iKanata.app; '
                   '/usr/sbin/pkgutil --forget io.github.mcuste.ikanata.installer')
        self.shell('test ! -e /Applications/iKanata.app; '
                   'test ! -e "/Library/Application Support/org.pqrs/Karabiner-DriverKit-VirtualHIDDevice"; '
                   'test ! -e /Applications/.Karabiner-VirtualHIDDevice-Manager.app; '
                   'if /usr/bin/pgrep -x kanata >/dev/null; then exit 1; fi; '
                   'if /usr/sbin/pkgutil --pkg-info org.pqrs.Karabiner-DriverKit-VirtualHIDDevice >/dev/null 2>&1; then exit 1; fi')
        self.assert_config(digest)
        self.record("Uninstall removed app, service, runtime and driver; config preserved")
        self.keyboard("After uninstall", removed=True)

    def run(self):
        self.create()
        self.install(self.args.baseline or self.args.package, "First installation")
        digest = self.configure()
        self.keyboard("First installation")
        if self.args.scenario == "existing":
            self.install(self.args.package, "Second installation")
            self.assert_config(digest)
            self.record("Second installation preserved the existing test configuration")
            self.keyboard("Second installation")
        self.uninstall(digest)
        self.report["status"] = "passed"
        self.save()
        print("\nAcceptance passed: " + str(self.directory / "result.json"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["fresh", "existing"])
    parser.add_argument("package", type=Path)
    parser.add_argument("--baseline", type=Path, help="Existing-system baseline package; defaults to candidate")
    parser.add_argument("--name", help="New VM name; existing names are never overwritten")
    parser.add_argument("--image", required=True)
    parser.add_argument("--cpu", default="4")
    parser.add_argument("--memory", default="8192")
    parser.add_argument("--artifacts", type=Path, default=ROOT / "target/vm-artifacts")
    args = parser.parse_args()
    if args.name and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.name):
        parser.error("Use a simple VM name with letters, digits, underscores or hyphens")
    if args.scenario == "fresh" and args.baseline:
        parser.error("--baseline applies only to the existing-system scenario")
    args.artifacts = args.artifacts.resolve()
    if not args.artifacts.is_relative_to(ROOT):
        parser.error("Artifacts must remain inside the project")
    for package in [args.package, args.baseline] if args.baseline else [args.package]:
        if not package.is_file() or package.suffix != ".pkg":
            parser.error("Provide an existing .pkg installer")
    args.artifacts.mkdir(parents=True, exist_ok=True)
    acceptance = Acceptance(args)
    try:
        acceptance.run()
    except (EOFError, KeyboardInterrupt, ValueError, OSError, subprocess.SubprocessError) as error:
        if acceptance.created_report:
            acceptance.report["status"] = "incomplete"
            acceptance.save()
        print("\nAcceptance incomplete: " + (str(error) or "human input required"), file=sys.stderr)
        print("Run name: " + acceptance.name + "; inspect " + str(acceptance.directory), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
