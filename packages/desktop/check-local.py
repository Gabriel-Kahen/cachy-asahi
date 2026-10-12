#!/usr/bin/env python3
"""Exercise the reviewed data-only recipe; never install packages or launch a session.

Existing-host packaging is not a clean ARM build. Outputs remain development
evidence even when this runs on an ARM host. Requires the existing makepkg,
fakeroot, Lua, Python, bsdtar, and Hyprland 0.56.2 tools; installs none of them.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
RECIPE = ROOT / "cachy-asahi-hyprland-settings"
EVIDENCE = ROOT / "evidence"
EPOCH = "1791748800"


def run(command, cwd):
    result = subprocess.run(command, cwd=cwd, env={**os.environ, "LC_ALL": "C",
                            "SOURCE_DATE_EPOCH": EPOCH}, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    return result.returncode, result.stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    EVIDENCE.mkdir(exist_ok=True)
    # A failed rerun must not leave a prior PASS summary beside newer outputs.
    (EVIDENCE / "host-packaging.json").unlink(missing_ok=True)
    source_names = [line.split(" = ", 1)[1] for line in
                    (RECIPE / ".SRCINFO").read_text().splitlines()
                    if line.strip().startswith("source = ")]
    if any(Path(name).name != name or not (RECIPE / name).is_file() for name in source_names):
        raise ValueError("expected reviewed local source filenames only")
    commands = [["bash", "-n", "PKGBUILD"], ["luac", "-p", "hyprland.lua"],
                ["python", "-m", "json.tool", "waybar.json"],
                ["makepkg", "--verifysource"],
                ["Hyprland", "--verify-config", "--config", str(RECIPE / "hyprland.lua")]]
    checks = []
    for index, command in enumerate(commands):
        status, output = run(command, RECIPE)
        (EVIDENCE / f"source-check-{index + 1}.txt").write_bytes(output)
        checks.append({"command": command, "exit_code": status})
    if any(check["exit_code"] for check in checks):
        raise RuntimeError(f"source checks failed: {checks}")

    expected = {
        "usr/share/cachy-asahi/hyprland/" + name: sha((RECIPE / name).read_bytes())
        for name in ("hyprland.lua", "waybar.json", "waybar.css", "mako.conf")
    }
    expected.update({
        "usr/share/doc/cachy-asahi-hyprland-settings/README.md": sha((RECIPE / "README.md").read_bytes()),
        **{"usr/share/licenses/cachy-asahi-hyprland-settings/" + name:
           sha((RECIPE / name).read_bytes()) for name in ("NOTICE", "LICENSE")},
    })
    records = []
    for number in (1, 2):
        with tempfile.TemporaryDirectory(prefix=f"cachy-asahi-desktop-package-{number}-") as temporary:
            work = Path(temporary)
            for name in ["PKGBUILD", ".SRCINFO", *source_names]:
                shutil.copyfile(RECIPE / name, work / name)
            command = ["makepkg", "--nodeps", "--noconfirm"]
            status, output = run(command, work)
            (EVIDENCE / f"host-package-{number}.txt").write_bytes(output)
            if status:
                raise RuntimeError(f"packaging run {number} failed; see evidence")
            artifacts = list(work.glob("*.pkg.tar.*"))
            if len(artifacts) != 1:
                raise RuntimeError("expected one package archive")
            # Preserve makepkg's real suffix; don't mislabel compression formats.
            suffix = artifacts[0].name[artifacts[0].name.index(".pkg.tar."):]
            artifact = EVIDENCE / f"host-package-{number}{suffix}"
            shutil.copyfile(artifacts[0], artifact)
            files = subprocess.check_output(["bsdtar", "-tf", str(artifact)], text=True).splitlines()
            payload = {name: sha(subprocess.check_output(["bsdtar", "-xOf", str(artifact), name]))
                       for name in files if not name.endswith("/") and not name.startswith(".")}
            if payload != expected or any(name in files for name in (".INSTALL",)):
                raise RuntimeError("package payload differs from the seven reviewed text inputs")
            for name in (".PKGINFO", ".BUILDINFO"):
                content = subprocess.check_output(["bsdtar", "-xOf", str(artifact), name])
                (EVIDENCE / f"host-package-{number}-{name[1:]}.txt").write_bytes(content)
            records.append({"command": command, "source_date_epoch": EPOCH, "exit_code": status,
                            "environment": "existing development host; separate temporary directory, not clean builder",
                            "artifact": artifact.name, "artifact_sha256": sha(artifact.read_bytes()),
                            "files": files, "payload_sha256": payload})
    report = {"host_arch": platform.machine(),
              "hyprland_version": subprocess.check_output(["Hyprland", "--version"], text=True),
              "checks": checks, "runs": records,
              "payload_matches": records[0]["payload_sha256"] == records[1]["payload_sha256"],
              "artifact_bytes_match": records[0]["artifact_sha256"] == records[1]["artifact_sha256"],
              "clean_arm_build": "NOT RUN", "installed": "NOT RUN", "hardware_tested": "NOT RUN"}
    (EVIDENCE / "host-packaging.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key not in ("checks", "runs")}, indent=2))


if __name__ == "__main__":
    main()
